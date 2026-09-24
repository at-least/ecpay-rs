# Local mirror of .github/workflows/ci.yml — everything GitHub checks on a
# push, runnable before you push it.
#
# DELIBERATELY ABSENT: the stage-smoke / stage-sandbox / stage-manual jobs.
# They hit ECPay's SHARED PUBLIC test account (2000132) and leave records
# that no endpoint can remove — ECPay has no B2C logistics cancel at all,
# and Express/CancelC2COrder needs the store-confirmation codes an
# unconfirmed OTP order never obtains. Running them locally costs exactly
# what running them in CI costs, with nobody reading the log. Trigger them
# on GitHub instead (see `make stage-run`).

MSRV := 1.89

.DEFAULT_GOAL := gates
.PHONY: ci gates fmt lint test doctest doc msrv audit hooks stage-run

## gates — the fast pre-push loop (~/.claude/CLAUDE.md "Rust projects").
## This is what the pre-push hook runs. Catches nearly every CI red.
gates: fmt lint nt

## ci — the full offline mirror of ci.yml, in the same order GitHub runs it.
ci: fmt lint test doctest doc msrv audit

# --- test job -------------------------------------------------------------
fmt:
	cargo fmt --check

lint:
	cargo clippy --all-targets -- -D warnings

# nextest for the local loop: no fail-fast, so every failure shows at once.
# It does NOT run doctests — that is what the `doctest` target is for.
.PHONY: nt
nt:
	cargo nextest run --no-fail-fast

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
	cargo +$(MSRV) check --all-targets

# --- audit job ------------------------------------------------------------
# A red audit is often a NEW upstream advisory against an OLD requirement,
# not a regression you introduced. Kept out of `gates` for that reason.
audit:
	cargo generate-lockfile
	cargo audit

# --- setup ----------------------------------------------------------------
## hooks — install the tracked pre-push hook (opt-in, per clone).
hooks:
	git config core.hooksPath .githooks
	@echo "pre-push hook active — bypass a single push with: git push --no-verify"

## stage-run — trigger the LIVE stage jobs on GitHub, where the log is kept.
## Creates permanent records on the shared public test account: a
## workflow_dispatch runs stage-smoke AND stage-sandbox AND stage-manual
## (the record-creating probes). Not something to run casually.
stage-run:
	@echo "This mints permanent records on ECPay stage account 2000132."
	@echo "It runs stage-smoke + stage-sandbox + stage-manual (probes included)."
	@printf "Type 'yes' to continue: " && read ans && [ "$$ans" = yes ]
	gh workflow run CI
