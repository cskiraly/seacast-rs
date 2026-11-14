# rustfmt.toml relies on nightly-only options, and min-publish-age is a nightly
# cargo feature. Everything else runs on the stable pin in rust-toolchain.toml,
# so lints and tests always match the shipped compiler.
nightly := "nightly-2026-06-21"

# Update dependencies under the publish-age cooldown (.cargo/config.toml):
# versions published less than 14 days ago are excluded from resolution.
# Resolution done on stable (cargo add, plain cargo update) is NOT covered;
# this recipe is the intended path for routine updates. Git dependencies are
# outside the cooldown entirely — no publish age exists for them. Ours are
# rev-pinned, so review the rev when you bump it by hand.
update *args:
  rustup toolchain install {{nightly}} --profile minimal > /dev/null 2>&1 && \
  cargo +{{nightly}} update -Z min-publish-age {{args}}

# Escape hatch for an urgent update to a version younger than the cooldown,
# e.g. `just update-allow h2 0.4.16`. The bypass applies to the WHOLE
# resolution of this invocation (transitive picks included), so review the
# full Cargo.lock diff, not just the target package.
update-allow package version:
  @echo "NOTE: the cooldown bypass is invocation-global; review the full Cargo.lock diff."
  rustup toolchain install {{nightly}} --profile minimal > /dev/null 2>&1 && \
  CARGO_RESOLVER_INCOMPATIBLE_PUBLISH_AGE=allow \
  cargo +{{nightly}} update -Z min-publish-age -p {{package}} --precise {{version}}

# Warn when the committed Cargo.lock pins crates younger than the cooldown.
cooldown-check:
  @rustup toolchain install {{nightly}} --profile minimal > /dev/null 2>&1 || \
  { echo "SKIPPED: could not install {{nightly}}"; exit 0; }; \
  out=$(cargo +{{nightly}} update --dry-run -Z min-publish-age 2>&1 | grep -E "Downgrading|is too new" || true); \
  if [ -n "$out" ]; then echo "WARNING: lockfile pins crates younger than the publish-age cooldown:"; echo "$out"; fi

fmt:
  rustup toolchain install {{nightly}} --component rustfmt > /dev/null 2>&1 && \
  cargo +{{nightly}} fmt

fmt-check:
  rustup toolchain install {{nightly}} --component rustfmt > /dev/null 2>&1 && \
  cargo +{{nightly}} fmt --check

clippy: 
	cargo clippy --locked --all-features --no-deps -- -D warnings -A clippy::collapsible_if

clippy-fix:
	cargo clippy --fix --locked --all-features --no-deps --allow-dirty -- -D warnings -A clippy::collapsible_if

machete:
  cargo install --locked cargo-machete && \
  cargo machete

# Same features/crates as CI, but optimised (opt-level 3) with debug-assertions
# on so invariant checks run. Run `just ef-tests-download` + `just
# checkpoint-fixtures` first if you don't have the fixtures locally.
test:
  cargo test --locked --workspace --no-fail-fast 2>&1

# As above but using `nextest`
nextest:
  cargo install --locked cargo-nextest && \
  cargo nextest r --locked --no-fail-fast --status-level skip

