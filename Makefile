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

# Read from Cargo.toml's rust-version (ci.yml's msrv job pins its own copy).
MSRV := $(shell sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml)

.DEFAULT_GOAL := gates
.PHONY: ci gates fmt lint nt test doctest doc msrv audit hooks stage-run
# The steps are meant to run one after another in the listed order; `make -j`
# would otherwise start every cargo step at once.
.NOTPARALLEL:

## gates — the fast pre-push loop: fmt, clippy, nextest. The pre-push hook
## runs the same three commands. Not a full CI mirror: nextest runs each test
## in its own process, while CI's `cargo test` runs a test binary's tests in
## one shared process (see the shared HTTP client note in src/client.rs) —
## `make test` / `make ci` cover that.
gates: fmt lint nt

## ci — the full mirror of ci.yml's non-stage jobs, in the order GitHub runs
## them (audit fetches the advisory DB, so this one is not fully offline).
ci: fmt lint test doctest doc msrv audit

# --- test job -------------------------------------------------------------
fmt:
	cargo fmt --check

lint:
	cargo clippy --all-targets -- -D warnings

# nextest for the local loop: no fail-fast, so every failure shows at once.
# It does NOT run doctests — that is what the `doctest` target is for.
# Without cargo-nextest it falls back to cargo test, like the hook does.
nt:
	@if command -v cargo-nextest >/dev/null 2>&1; then \
		echo "cargo nextest run --no-fail-fast"; \
		cargo nextest run --no-fail-fast; \
	else \
		echo "cargo test --all-targets --no-fail-fast (cargo-nextest not installed)"; \
		cargo test --all-targets --no-fail-fast; \
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

# --- msrv job -------------------------------------------------------------
# NOTE: CI resolves dependencies FRESH (Cargo.lock is untracked for this
# library crate), so it catches dependency floors that need a newer rustc.
# Locally a Cargo.lock usually exists and pins them away, so a green local
# msrv is weaker evidence than a green CI msrv. Delete Cargo.lock first if
# you want the real thing.
msrv:
	@[ -n "$(MSRV)" ] || { echo "rust-version not found in Cargo.toml"; exit 1; }
	cargo +$(MSRV) check --all-targets

# --- audit job ------------------------------------------------------------
# CI has no Cargo.lock, so its audit covers a fresh resolution. Locally this
# audits the Cargo.lock you build with and only generates one when none
# exists: `cargo generate-lockfile` would re-resolve every dependency to its
# latest version and silently discard any local pin. As with msrv, delete
# Cargo.lock first to audit exactly what CI audits.
# A red audit is often a NEW upstream advisory against an OLD requirement,
# not a regression you introduced. Kept out of `gates` for that reason.
audit:
	[ -f Cargo.lock ] || cargo generate-lockfile
	cargo audit

# --- setup ----------------------------------------------------------------
## hooks — install the tracked pre-push hook (opt-in, per clone).
## core.hooksPath replaces .git/hooks wholesale, so any hook already there
## stops running; the recipe names them.
hooks:
	git config core.hooksPath .githooks
	@old="$$(git rev-parse --git-common-dir)/hooks"; \
	for h in "$$old"/*; do \
		case "$$h" in *.sample | "$$old/*") ;; \
		*) echo "note: $$h no longer runs — move it into .githooks/ to keep it" ;; \
		esac; \
	done
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
	if [ "$$ref" = "$$(git branch --show-current)" ] && \
	   [ "$$(git rev-parse HEAD)" != "$$(git ls-remote origin "refs/heads/$$ref" | cut -f1)" ]; then \
		echo "origin's '$$ref' is not HEAD (unpushed commits, not pushed, or origin moved) — sync first."; exit 1; \
	fi; \
	echo "This mints permanent records on ECPay stage accounts 2000132 and 3002607."; \
	echo "It runs stage-smoke + stage-sandbox + stage-manual (probes included)"; \
	echo "against the pushed tip of '$$ref'."; \
	printf "Type 'yes' to continue: "; read ans; [ "$$ans" = yes ] || exit 1; \
	gh workflow run ci.yml --ref "$$ref"
