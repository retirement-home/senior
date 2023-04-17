.PHONY: howto clean_completions install uninstall

ifeq ($(PREFIX),)
PREFIX := /usr
endif
BINARY := $(PREFIX)/local/bin/senior
BINARYAGENT := $(PREFIX)/local/bin/senior-agent
BINARYMENU := $(PREFIX)/local/bin/seniormenu
ZSHCOMPLETION := $(PREFIX)/local/share/zsh/site-functions/_senior
BASHCOMPLETION := $(PREFIX)/local/share/bash-completion/completions/senior

RUSTDIR := src/senior

howto:
	$(info run `sudo make install` or `sudo make uninstall`)

$(RUSTDIR)/target/release/senior $(RUSTDIR)/target/release/senior-agent:
	RUSTUP_TOOLCHAIN=nightly cargo build --manifest-path $(RUSTDIR)/Cargo.toml --bins --locked --release --target-dir $(RUSTDIR)/target

install: $(RUSTDIR)/target/release/senior $(RUSTDIR)/target/release/senior-agent
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

