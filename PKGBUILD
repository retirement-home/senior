# Maintainer: Stefan <stefangehr@protonmail.com>
pkgname=senior
pkgver=r142.0ca64d1
pkgrel=1
pkgdesc='password manager using age as backend; inspired by pass'
arch=('any')
url='https://gitlab.com/retirement-home/senior'
license=('AGPL3')
depends=(wl-clipboard tree)
optdepends=(git)
makedepends=(cargo git)
source=("git+${url}.git")
md5sums=('SKIP')
rustdir="src/senior"

pkgver() {
	cd "$pkgname"
	printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
	cd "$pkgname/$rustdir"
	cargo build --bins --locked --release --target-dir target
}

package() {
	cd "$pkgname"
	install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
	install -Dm755 $rustdir/target/release/senior -t "$pkgdir"/usr/bin/
	install -Dm755 $rustdir/target/release/senior-agent -t "$pkgdir"/usr/bin/
	install -Dm755 src/seniormenu -t "$pkgdir"/usr/bin/
	install -Dm644 src/completions/senior.zsh "$pkgdir"/usr/share/zsh/site-functions/_senior
	install -Dm644 src/completions/senior.bash "$pkgdir"/usr/share/bash-completion/completions/senior
	install -Dm644 src/man/* -t "$pkgdir"/usr/share/man/man1
}
