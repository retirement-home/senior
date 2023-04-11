.PHONY: howto clean_completions install uninstall

ifeq ($(PREFIX),)
PREFIX := /usr
endif
BINARY := $(PREFIX)/local/bin/senior
BINARYAGENT := $(PREFIX)/local/bin/senior-agent
BINARYMENU := $(PREFIX)/local/bin/seniormenu
ZSHCOMPLETION := $(PREFIX)/local/share/zsh/site-functions/_senior
BASHCOMPLETION := $(PREFIX)/local/share/bash-completion/completions/senior

howto:
	$(info run `sudo make install` or `sudo make uninstall`)

target/release/senior target/release/senior-agent:
	RUSTUP_TOOLCHAIN=nightly cargo build --bins --locked --release --target-dir target

install: target/release/senior target/release/senior-agent
	mkdir -p $(shell dirname $(BINARY))
	mkdir -p $(shell dirname $(ZSHCOMPLETION))
	mkdir -p $(shell dirname $(BASHCOMPLETION))
	cp target/release/senior $(BINARY)
	cp target/release/senior-agent $(BINARYMENU)
	cp src/seniormenu $(BINARYMENU)
	cp completions/senior.zsh-completion $(ZSHCOMPLETION)
	cp completions/senior.bash-completion $(BASHCOMPLETION)

uninstall:
	rm -f $(BINARY)
	rm -f $(BINARYAGENT)
	rm -f $(BINARYMENU)
	rm -f $(ZSHCOMPLETION)
	rm -f $(BASHCOMPLETION)

