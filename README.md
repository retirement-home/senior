# senior

A Password Manager Using [age](https://github.com/FiloSottile/age) as Backend

## Install
On arch based systems you can simply use the provided [PKGBUILD](PKGBUILD)

```sh
SRCDEST=/tmp/senior-src SRCPKGDEST=/tmp/senior-srcpkg PKGDEST=/tmp/senior-pkg BUILDDIR=/tmp/senior-build makepkg -sic ; rm -rf target ; git restore PKGBUILD
```

Otherwise you can use

```sh
cargo install --path .
```
Make sure you have the dependencies installed (look at `depends` and `makedepends` in the [PKGBUILD](PKGBUILD))
