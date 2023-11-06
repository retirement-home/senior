.PHONY: help build install uninstall

PREFIX ?= /usr
BINARY := $(PREFIX)/local/bin/senior
BINARYAGENT := $(PREFIX)/local/bin/senior-agent
BINARYMENU := $(PREFIX)/local/bin/seniormenu
ZSHCOMPLETION := $(PREFIX)/local/share/zsh/site-functions/_senior
BASHCOMPLETION := $(PREFIX)/local/share/bash-completion/completions/senior
MANDIR := $(PREFIX)/local/share/man/man1

RUSTDIR := src/senior

build: $(RUSTDIR)/target/release/senior $(RUSTDIR)/target/release/senior-agent src/man/senior.1

$(RUSTDIR)/target/release/senior $(RUSTDIR)/target/release/senior-agent src/man/senior.1: src/senior/src/*
	cargo build --manifest-path $(RUSTDIR)/Cargo.toml --bins --locked --release --target-dir $(RUSTDIR)/target

help:
	$(info run `make && sudo make install` or `sudo make uninstall`)

install: build
	mkdir -p $(shell dirname $(BINARY))
	mkdir -p $(shell dirname $(ZSHCOMPLETION))
	mkdir -p $(shell dirname $(BASHCOMPLETION))
	mkdir -p $(MANDIR)
	cp $(RUSTDIR)/target/release/senior $(BINARY)
	killall senior-agent || true # Ignore error
	cp $(RUSTDIR)/target/release/senior-agent $(BINARYAGENT)
	cp src/seniormenu $(BINARYMENU)
	cp src/completions/senior.zsh $(ZSHCOMPLETION)
	cp src/completions/senior.bash $(BASHCOMPLETION)
	cp src/man/* $(MANDIR)

uninstall:
	rm -f $(BINARY)
	rm -f $(BINARYAGENT)
	rm -f $(BINARYMENU)
	rm -f $(ZSHCOMPLETION)
	rm -f $(BASHCOMPLETION)
	rm -f $(MANDIR)/senior*.1

