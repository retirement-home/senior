# senior

A Password Manager Using [age](https://github.com/FiloSottile/age) as Backend

## Install

### Arch BASED Systems
Simply use the provided [PKGBUILD](PKGBUILD)
```sh
# Download the PKGBUILD into an empty directory
curl -O "https://gitlab.com/retirement-home/senior/-/raw/main/PKGBUILD"
# Install the package with all its dependencies
makepkg -sic
```

### Other Systems
Use cargo to install the package
```sh
cargo install --path .
```
Make sure you have the dependencies installed (look at `depends` and `makedepends` in the [PKGBUILD](PKGBUILD))
