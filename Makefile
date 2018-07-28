all: check build test

todos:
	rg --vimgrep -g '!Makefile' -i todo 

check:
	cargo check

build:
	cargo build

test:
	cargo test --all --no-fail-fast

docs: man
	
man:
	$(MAKE) -C docs

release: release-bump all
	git commit -am "Bump to version $$(cargo read-manifest | jq .version)"
	git tag v$$(cargo read-manifest | jq -r .version)

release-bump:
	cargo bump

publish:
	git push && git push --tags

install:
	cargo install --force

clippy:
	cargo +nightly clippy

fmt:
	cargo +nightly fmt

duplicate_libs:
	cargo tree -d

_update-clippy_n_fmt:
	rustup update
	rustup component add clippy-preview --toolchain=nightly
	rustup component add rustfmt-preview --toolchain=nightly

_cargo_install:
	cargo install -f cargo-tree
	cargo install -f cargo-bump

.PHONY: tests

