pkgname=senior
pkgver=r40.00596ec
pkgrel=1
pkgdesc="password manager using age as backend; inspired by pass"
arch=("any")
url="https://gitlab.com/retirement-home/senior"
license=("AGPL3")
depends=(age wl-clipboard tree)
optdepends=(git)
makedepends=(cargo)
source=(git+${url}.git)
md5sums=("SKIP")

pkgver() {
	cd "$pkgname"
	printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

package() {
    cd "$pkgname"
	cargo build --release
	install -Dm755 target/release/senior "$pkgdir"/usr/bin/senior
}
