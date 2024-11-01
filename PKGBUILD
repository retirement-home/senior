# Maintainer: Stefan <stefan@gehr.xyz>
pkgname=seniorpw
replaces=(senior)
pkgver=r203.77aa38a
pkgrel=1
pkgdesc='password manager using age as backend; inspired by pass'
arch=('any')
url='https://gitlab.com/retirement-home/seniorpw'
license=('AGPL3')
depends=(tree)
optdepends=(git wl-clipboard)
makedepends=(cargo git)
source=("git+${url}.git")
md5sums=('SKIP')
_rustdir="src/seniorpw"

pkgver() {
	cd "$pkgname"
	printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
	cd "$pkgname/$_rustdir"
	cargo build --bins --locked --release --target-dir target
}

package() {
	cd "$pkgname"
	install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
	install -Dm755 $_rustdir/target/release/senior -t "$pkgdir"/usr/bin/
	install -Dm755 $_rustdir/target/release/senior-agent -t "$pkgdir"/usr/bin/
	install -Dm755 src/seniormenu -t "$pkgdir"/usr/bin/
	install -Dm644 src/completions/senior.zsh "$pkgdir"/usr/share/zsh/site-functions/_senior
	install -Dm644 src/completions/senior.bash "$pkgdir"/usr/share/bash-completion/completions/senior
	install -Dm644 src/man/* -t "$pkgdir"/usr/share/man/man1
}
