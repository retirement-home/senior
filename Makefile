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

install: clean_completions
	cargo build --release
	mkdir -p $(shell dirname $(BINARY))
	mkdir -p $(shell dirname $(ZSHCOMPLETION))
	mkdir -p $(shell dirname $(BASHCOMPLETION))
	cp target/release/senior $(BINARY)
	cp target/release/build/senior-*/out/_senior $(ZSHCOMPLETION)
	cp target/release/build/senior-*/out/senior.bash $(BASHCOMPLETION)

uninstall:
	rm $(BINARY)
	rm $(ZSHCOMPLETION)
	rm $(BASHCOMPLETION)

