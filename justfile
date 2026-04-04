# helmet justfile (Rust workspace)

set positional-arguments

default:
    @just --list

# === Installation ===

install:
    cargo install --path .

install-all:
    @for crate in $(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.targets[] | .kind[] == "bin") | .manifest_path | split("/") | .[-2]'); do \
        echo "Installing $crate..."; \
        cargo install --path crates/$crate; \
    done

install-crate CRATE:
    cargo install --path crates/{{CRATE}}

# === Building ===

build:
    remote-build build

build-release:
    remote-build build --release

build-crate CRATE:
    remote-build build -p {{CRATE}}

build-all:
    remote-build build --all-features

check:
    remote-build check

check-crate CRATE:
    remote-build check -p {{CRATE}}

clean:
    cargo clean

# === Testing ===

test:
    remote-build test

test-crate CRATE:
    remote-build test -p {{CRATE}}

test-all:
    remote-build test --all-features

test-v:
    remote-build test -- --nocapture

test-one TEST:
    remote-build test {{TEST}}

# === Code Quality ===

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

clippy:
    remote-build clippy

lint: clippy

clippy-crate CRATE:
    remote-build clippy -p {{CRATE}}

fix:
    remote-build clippy --fix --allow-dirty

check-all: fmt-check clippy test

# === Performance ===

bench:
    cargo bench -p helmet-core --bench guard_hot_path

bench-save:
    cargo bench -p helmet-core --bench guard_hot_path -- --save-baseline main

perf-gate:
    scripts/perf-gate.sh

perf-gate-dry:
    scripts/perf-gate.sh --dry-run

# === Documentation ===

docs:
    cargo doc --workspace --no-deps

docs-open:
    cargo doc --workspace --no-deps --open

docs-crate CRATE:
    cargo doc -p {{CRATE}} --no-deps --open

# === Dependencies ===

update:
    cargo update

outdated:
    cargo outdated --workspace

# === Workspace Info ===

list:
    @cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | "\(.name) (\(.version))"'

list-bins:
    @cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.targets[] | .kind[] == "bin") | .name'

list-libs:
    @cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.targets[] | .kind[] == "lib") | .name'

# === Release ===

release: build-release
    @echo "Binary sizes:"
    @find target/release -maxdepth 1 -type f -perm +111 ! -name "*.d" -exec ls -lh {} \; 2>/dev/null || true

release-tag VERSION:
    git tag v{{VERSION}}
    git push --tags

setup-secrets:
    byt secrets setup helmet
