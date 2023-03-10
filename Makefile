.PHONY: howto clean_completions install uninstall

ifeq ($(PREFIX),)
	PREFIX := "/usr"
endif
BINARY := $(PREFIX)/local/bin/senior
ZSHCOMPLETION := $(PREFIX)/local/share/zsh/site-functions/_senior
BASHCOMPLETION := $(PREFIX)/local/share/bash-completion/completions/senior

howto:
	$(info run `sudo make install` or `sudo make uninstall`)

clean_completions:
	rm -rf target/release/build/

install:
	cargo build --release
	mkdir -p $(shell dirname $(BINARY))
	mkdir -p $(shell dirname $(ZSHCOMPLETION))
	mkdir -p $(shell dirname $(BASHCOMPLETION))
	cp target/release/senior $(BINARY)
	cp completions/senior.zsh-completion $(ZSHCOMPLETION)
	cp completions/senior.bash-completion $(BASHCOMPLETION)

uninstall:
	rm $(BINARY)
	rm $(ZSHCOMPLETION)
	rm $(BASHCOMPLETION)

