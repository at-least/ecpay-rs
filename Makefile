# Local mirror of .github/workflows/ci.yml — everything GitHub checks on a
# push, runnable before you push it.
#
# DELIBERATELY ABSENT: the stage-smoke / stage-sandbox / stage-manual jobs.
# They hit ECPay's SHARED PUBLIC test accounts (2000132 and 3002607) and
# leave records that no endpoint can remove — ECPay has no B2C logistics
# cancel at all, and Express/CancelC2COrder needs the store-confirmation
# codes an unconfirmed OTP order never obtains. Running them locally costs
# exactly what running them in CI costs, with nobody reading the log.
# Trigger them on GitHub instead (see `make stage-run`).

# Recipes use bash features (read -d '', [[ =~ ]]) and all run with pipefail
# (no -e: the ci loop reads each step's exit status). .SHELLFLAGS is set
# explicitly because make would otherwise take it from the environment. It
# governs $(shell ...) too, which changes nothing: make does not act on a
# $(shell) exit status.
SHELL := bash
.SHELLFLAGS := -o pipefail -c
# .SHELLFLAGS exists since GNU make 3.82. Older make (macOS ships 3.81 as
# /usr/bin/make) takes it for an ordinary variable and runs every recipe as
# `bash -c`, without pipefail, which would mask a failing `git ls-files` or
# `cargo metadata` at the head of a pipe. Every recipe that pipes (ci, msrv,
# print-msrv and audit) therefore OPENS with need_pipefail (below) and refuses
# a shell without the option, before any other check; a new recipe that pipes
# must open the same way. The rest, gates and so the pre-push hook among them,
# pipe nothing and run on 3.81 as well.

# This file's own path, so the sub-makes of `ci` read it under `make -f` too.
# (MAKEFILE_LIST ends with this file only before any include. A -f path with
# a space in it is not supported: make splits the list on whitespace.)
# Recipes read it from the environment, as "$$SELF" (a recipe that pasted
# the path in would have the shell expand any $ in it).
SELF := $(abspath $(lastword $(MAKEFILE_LIST)))
export SELF

.DEFAULT_GOAL := gates
.PHONY: ci gates fmt lint nt test doctest doc msrv print-msrv audit hooks stage-run
# The steps are meant to run one after another in the listed order; `make -j`
# would otherwise start every cargo step at once.
.NOTPARALLEL:

## gates — the fast pre-push loop: fmt, clippy, nextest, in place, on your
## Cargo.lock. The pre-push hook runs this target on a clean checkout of the
## tip of each pushed ref. Not a full CI mirror: nextest runs each test in its
## own process, while CI's `cargo test` runs a test binary's tests in one shared
## process (see the shared HTTP client note in src/client.rs) — `make test` /
## `make ci` cover that.
gates: fmt lint nt

## ci — the full mirror of ci.yml's non-stage jobs, in ci.yml's order, on a
## fresh dependency resolution in a copy of the working tree (see "fresh
## resolution" below; needs network, jq for msrv and cargo-audit for audit).
## fmt → doc are the steps of ONE CI job, where a red step skips the rest;
## msrv and audit are separate jobs. Here, once the fresh resolution
## succeeds, every step runs regardless, so all the failures show at once;
## the red ones are listed at the end and make exits non-zero. (If the
## resolution itself fails — no network, or a requirement nothing satisfies —
## make stops there with cargo's error; a make without pipefail, a missing jq
## or cargo-audit stops it before that, not as a red msrv or audit after
## every other step ran.)
## Ctrl-C, or a signal to a step's make, stops the run; a step whose cargo
## alone is killed counts as a red step.
CI_STEPS := fmt lint test doctest doc msrv audit
ci:
	@$(need_pipefail) $(need_jq) $(need_audit) $(fresh_copy) cd "$$FRESH_TREE" && set -x && cargo generate-lockfile
	@failed=; \
	for t in $(CI_STEPS); do \
		case $$t in \
		msrv | audit) $(MAKE) --no-print-directory -f "$$SELF" $$t ;; \
		*) $(MAKE) --no-print-directory -f "$$SELF" -C "$$FRESH_TREE" \
			CARGO_TARGET_DIR="$${FRESH_BUILD//\$$/\$$\$$}" $$t ;; \
		esac; rc=$$?; \
		if [ $$rc -gt 128 ]; then exit $$rc; fi; \
		if [ $$rc -ne 0 ]; then failed="$$failed $$t"; fi; \
	done; \
	if [ -n "$$failed" ]; then echo "make ci: FAILED:$$failed"; exit 1; fi; \
	echo "make ci: all $(words $(CI_STEPS)) steps passed"

# --- test job -------------------------------------------------------------
fmt:
	cargo fmt --check

lint:
	cargo clippy --all-targets -- -D warnings

# nextest for the local loop: no fail-fast, so every failure shows at once.
# It does NOT run doctests — that is what the `doctest` target is for.
# Without cargo-nextest it falls back to `cargo test --no-fail-fast`, which
# runs the doctests too.
nt:
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		echo "cargo nextest run --no-fail-fast"; \
		cargo nextest run --no-fail-fast; \
	else \
		echo "cargo test --no-fail-fast (cargo-nextest not installed)"; \
		cargo test --no-fail-fast; \
	fi

# What CI actually runs. Every live-stage suite is #[ignore]d, so this stays
# fully offline.
test:
	cargo test --all-targets

# --all-targets skips the Doc-tests phase entirely; CI runs it separately to
# cover the compile_fail pins and every rustdoc example.
doctest:
	cargo test --doc

doc:
	RUSTDOCFLAGS="-D warnings" cargo doc --no-deps

# --- fresh resolution: ci, msrv, audit ------------------------------------
# Cargo.lock is untracked for this library crate, so every CI job starts
# without one and resolves each dependency fresh: msrv with the MSRV cargo
# itself, the rest with stable. A local lock pins older versions and hides
# exactly what CI would hit (a new release that breaks or deprecates an API
# used here, a dependency floor that needs a newer rustc, a new advisory).
# So `ci`, `msrv` and `audit` run in a COPY of the working tree: every file
# git does not ignore, tracked or not (what `git add -A` would commit), so no
# Cargo.lock. Your own Cargo.lock is never touched. Run them from the crate
# root.
#
# The copy lives in a per-clone cache dir, $(SCRATCH):
# <cache>/ecpay-rs/<hash of the clone's path>, where <cache> is
# $XDG_CACHE_HOME when that is an absolute path (the XDG spec says to ignore
# a relative one), else ~/.cache — the same rule as the pre-push hook.
# - Outside the repo and below no world-writable directory (fresh_copy
#   refuses to run otherwise), because cargo, rustfmt and clippy also read
#   config (.cargo/config.toml, rustfmt.toml, clippy.toml) from every parent
#   directory: neither an ignored one in the repo nor one another user drops
#   into /tmp may reach the copy. (Only the world-writable bit is checked: a
#   directory another user owns, or can write to through group bits or an
#   ACL, is not detected.)
# - Per clone, because clones sharing one copy would refill it under each
#   other mid-run. (Two runs from ONE clone at the same time still share it;
#   don't.)
# It builds into its own target dir there, never the main tree's: two trees
# of one package that share a target dir fill the same artifact slots, and
# cargo then takes the other tree's output as fresh — your next in-place
# build would silently run the copy's code instead of your edits. The copied
# files get the copy time as their mtime, so every run rebuilds this crate
# (not its registry dependencies): with the original mtimes, a file saved
# during a run can be older than that run's build and never be rebuilt.
# (The copy is extracted after a cd, not with tar -C: GNU tar un-escapes
# backslashes in the -C operand.)
CACHE_HOME := $(shell case "$$XDG_CACHE_HOME" in (/*) printf %s "$$XDG_CACHE_HOME" ;; \
	(*) printf %s/.cache "$${HOME:-$$(unset HOME; echo ~)}" ;; esac)
SCRATCH := $(CACHE_HOME)/ecpay-rs/$(shell pwd -P | git hash-object --stdin)
FRESH_TREE := $(SCRATCH)/ci/tree
FRESH_BUILD := $(SCRATCH)/ci/build
# Recipes read these from the environment too, as with SELF. The ci loop
# doubles any $ in FRESH_BUILD, since make would expand it in a command-line
# variable.
export SCRATCH FRESH_TREE FRESH_BUILD
# Every recipe that pipes opens with this (see the header): [[ -o pipefail ]]
# is true only when the option is on in this shell, whatever turned it off —
# a make older than 3.82, or SHELL / .SHELLFLAGS overridden on the command
# line or through MAKEFLAGS. The message names both. Refusals go to stderr,
# as every check's message here does: ci.yml captures `make -s print-msrv`'s
# stdout into a variable, where a reason would vanish.
need_pipefail = \
	[[ -o pipefail ]] || \
		{ echo "pipefail is off in this recipe's shell (make $(MAKE_VERSION)): either this make is older than 3.82 and takes .SHELLFLAGS for an ordinary variable (macOS ships 3.81 as /usr/bin/make: put Homebrew make's gnubin dir first on PATH), or SHELL / .SHELLFLAGS was overridden on the command line or in MAKEFLAGS" >&2; exit 1; };
# Pipes (git ls-files | ... | tar): the caller opened with need_pipefail.
fresh_copy = \
	[ -f Cargo.toml ] || { echo "no Cargo.toml here: run make from the crate root" >&2; exit 1; }; \
	mkdir -p "$$SCRATCH" && d=$$(cd "$$SCRATCH" && pwd -P) || exit 1; \
	while :; do \
		if [ "$$d" -ef . ]; then \
			echo "$$SCRATCH is inside this clone: set XDG_CACHE_HOME outside it" >&2; exit 1; \
		fi; \
		ww=$$(find "$$d" -prune -perm -0002) || \
			{ echo "could not check whether $$d is world-writable (find failed)" >&2; exit 1; }; \
		[ -z "$$ww" ] || \
			{ echo "$$d is writable by anyone: set XDG_CACHE_HOME to a private dir" >&2; exit 1; }; \
		[ "$$d" = / ] && break; d=$$(dirname "$$d"); \
	done; \
	rm -rf "$$FRESH_TREE" && mkdir -p "$$FRESH_TREE" && \
	git ls-files -z --cached --others --exclude-standard --deduplicate | \
		while IFS= read -r -d '' f; do \
			if [ -f "$$f" ] || [ -L "$$f" ]; then printf '%s\0' "$$f"; fi; \
		done | \
		tar --null --no-recursion -T - -cf - | (cd "$$FRESH_TREE" && tar -xmf -) || exit 1;

# The MSRV is the package's rust-version as cargo itself reads it. read_msrv
# below is the only reader: `msrv` expands it, and ci.yml's msrv job runs
# `make -s print-msrv`, so the number lives only in Cargo.toml and the way it
# is read lives only here (a toolchain pinned in ci.yml would pass silently
# once Cargo.toml is lowered or the pin raised: cargo only refuses a rustc
# OLDER than rust-version). `cargo metadata --no-deps` resolves nothing and
# writes no Cargo.lock, so `msrv` still resolves with the MSRV cargo.
# jq reads the field: a text match on that JSON also hits any rust_version
# key inside a [package.metadata] or [workspace.metadata] table. Two guards,
# for different failures: pipefail (the recipe opened with need_pipefail)
# makes a failed cargo fail the assignment, so the step stops at cargo's own
# error; the regex refuses what a SUCCESSFUL cargo can still print — `null`
# for a package without the field, a line per workspace member, the empty
# string of a workspace with no package — instead of picking a member's
# value. A two-component rust-version names its .0 release: "1.89" is 1.89.0
# to cargo, and the check runs on exactly that floor, not on the newest
# 1.89.x that the channel `1.89` would select. rustup keeps `1.89` and
# `1.89.0` as separate toolchains, so `cargo +1.89.0` may need
# `rustup toolchain install 1.89.0` first (rustup does that itself when its
# auto-install is on).
need_jq = \
	command -v jq >/dev/null 2>&1 || \
		{ echo "jq not found: make msrv reads cargo metadata's JSON with it" >&2; exit 1; };
read_msrv = \
	msrv=$$(cargo metadata --no-deps --offline --format-version 1 | \
		jq -r '.packages[].rust_version') || exit 1; \
	[[ $$msrv =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$$ ]] || \
		{ echo "no single plain rust-version in Cargo.toml (cargo metadata: '$$msrv')" >&2; exit 1; }; \
	case $$msrv in *.*.*) ;; *) msrv=$$msrv.0 ;; esac;
msrv:
	@$(need_pipefail) $(need_jq) $(fresh_copy) cd "$$FRESH_TREE" && \
	$(read_msrv) \
	export CARGO_TARGET_DIR="$$FRESH_BUILD" && set -x && cargo +$$msrv check --all-targets

## print-msrv — print the MSRV toolchain (rust-version, .0 added to a
## two-component value) and nothing else; ci.yml's msrv job reads it with
## `make -s print-msrv`. Reads the manifest in place: no copy, no build.
print-msrv:
	@$(need_pipefail) $(need_jq) $(read_msrv) echo "$$msrv"

# A red audit is often a NEW upstream advisory against an OLD requirement,
# not a regression you introduced. Kept out of `gates` for that reason.
# `cargo audit` is an external subcommand that cargo also finds in
# $CARGO_HOME/bin when that is not on PATH, so the probe is the subcommand
# itself, not `command -v cargo-audit`.
need_audit = \
	cargo audit --version >/dev/null 2>&1 || \
		{ echo "cargo audit does not run: make audit needs cargo-audit (cargo install cargo-audit)" >&2; exit 1; };
audit:
	@$(need_pipefail) $(need_audit) $(fresh_copy) cd "$$FRESH_TREE" && set -x && cargo generate-lockfile && cargo audit

# --- setup ----------------------------------------------------------------
## hooks — install the tracked pre-push hook (opt-in, per clone).
## core.hooksPath replaces the hooks directory in effect until now (.git/hooks,
## or a global core.hooksPath) wholesale, so any hook there stops running for
## this clone; the recipe names them.
hooks:
	@old="$$(git rev-parse --git-path hooks)"; \
	echo "git config core.hooksPath .githooks"; \
	git config core.hooksPath .githooks || exit 1; \
	if [ "$$(cd "$$old" 2>/dev/null && pwd -P)" != "$$(cd .githooks && pwd -P)" ]; then \
		for h in "$$old"/*; do \
			case "$$h" in *.sample) continue ;; esac; \
			if [ -f "$$h" ] && [ -x "$$h" ]; then \
				echo "note: $$h no longer runs — move it into .githooks/ to keep it"; \
			fi; \
		done; \
	fi
	@echo "pre-push hook active — bypass a single push with: git push --no-verify"

## stage-run — trigger the LIVE stage jobs on GitHub, where the log is kept.
## Creates permanent records on the shared public test accounts: a
## workflow_dispatch runs stage-smoke AND stage-sandbox AND stage-manual
## (the record-creating probes). Not something to run casually.
## GitHub runs the tip of STAGE_REF as it is on origin (default: the current
## branch; a bare `gh workflow run` would dispatch the default branch
## instead), so for the current branch that tip must be exactly HEAD.
stage-run:
	@ref="$${STAGE_REF:-$$(git branch --show-current)}"; \
	if [ -z "$$ref" ]; then \
		echo "detached HEAD: run as 'make stage-run STAGE_REF=<branch>'"; exit 1; \
	fi; \
	if [ "$$ref" = "$$(git branch --show-current)" ]; then \
		if ! remote="$$(git ls-remote origin "refs/heads/$$ref")"; then \
			echo "could not read '$$ref' from origin (git ls-remote failed: network or auth?) — nothing triggered."; exit 1; \
		fi; \
		if [ -z "$$remote" ]; then \
			echo "'$$ref' is not on origin — push it first."; exit 1; \
		fi; \
		if [ "$${remote%%[[:space:]]*}" != "$$(git rev-parse HEAD)" ]; then \
			echo "origin's '$$ref' is not HEAD (unpushed commits, or origin moved) — sync first."; exit 1; \
		fi; \
	fi; \
	echo "This mints permanent records on ECPay stage accounts 2000132 and 3002607."; \
	echo "It runs stage-smoke + stage-sandbox + stage-manual (probes included)"; \
	echo "against the pushed tip of '$$ref'."; \
	printf "Type 'yes' to continue: "; read ans; [ "$$ans" = yes ] || exit 1; \
	gh workflow run ci.yml --ref "$$ref"
