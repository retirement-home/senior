pkgname=senior
pkgver=r46.50cfcab
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
	install -Dm755 target/release/senior -t "$pkgdir"/usr/bin/
	install -Dm644 target/release/build/senior-*/out/_senior -t "$pkgdir"/usr/share/zsh/site-functions/
	install -Dm644 target/release/build/senior-*/out/senior.bash "$pkgdir"/usr/share/bash-completion/completions/senior
}
