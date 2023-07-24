.PHONY: howto clean_completions build install uninstall

PREFIX ?= /usr
BINARY := $(PREFIX)/local/bin/senior
BINARYAGENT := $(PREFIX)/local/bin/senior-agent
BINARYMENU := $(PREFIX)/local/bin/seniormenu
ZSHCOMPLETION := $(PREFIX)/local/share/zsh/site-functions/_senior
BASHCOMPLETION := $(PREFIX)/local/share/bash-completion/completions/senior

RUSTDIR := src/senior

howto:
	$(info run `make build && sudo make install` or `sudo make uninstall`)

$(RUSTDIR)/target/release/senior $(RUSTDIR)/target/release/senior-agent: src/senior/src/*
	cargo build --manifest-path $(RUSTDIR)/Cargo.toml --bins --locked --release --target-dir $(RUSTDIR)/target

build: $(RUSTDIR)/target/release/senior $(RUSTDIR)/target/release/senior-agent

install: build
	mkdir -p $(shell dirname $(BINARY))
	mkdir -p $(shell dirname $(ZSHCOMPLETION))
	mkdir -p $(shell dirname $(BASHCOMPLETION))
	cp $(RUSTDIR)/target/release/senior $(BINARY)
	cp $(RUSTDIR)/target/release/senior-agent $(BINARYAGENT)
	cp src/seniormenu $(BINARYMENU)
	cp src/completions/senior.zsh $(ZSHCOMPLETION)
	cp src/completions/senior.bash $(BASHCOMPLETION)

uninstall:
	rm -f $(BINARY)
	rm -f $(BINARYAGENT)
	rm -f $(BINARYMENU)
	rm -f $(ZSHCOMPLETION)
	rm -f $(BASHCOMPLETION)

