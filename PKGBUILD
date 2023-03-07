pkgname=senior
pkgver=r38.b0762ff
pkgrel=1
pkgdesc="password manager using age as backend; inspired by pass"
arch=("any")
depends=(age wl-clipboard tree)
optdepends=(git)
makedepends=(cargo)
source=("$pkgname"::"git+file://$(pwd)")
md5sums=('SKIP')

pkgver() {
	cd "$pkgname"
	printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

package() {
    cd "$pkgname"
	cargo build --release
	install -Dm755 target/release/senior "$pkgdir"/usr/bin/senior
}
