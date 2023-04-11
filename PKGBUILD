# Maintainer: Stefan <stefangehr@protonmail.com>
pkgname=senior
pkgver=r52.b5aa61f
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

pkgver() {
	cd "$pkgname"
	printf "r%s.%s" "$(git rev-list --count HEAD)" "$(git rev-parse --short HEAD)"
}

build() {
	cd "$pkgname"
	cargo +nightly build --bins --locked --release --target-dir target
}

package() {
	cd "$pkgname"
	install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
	install -Dm755 target/release/senior -t "$pkgdir"/usr/bin/
	install -Dm755 target/release/senior-agent -t "$pkgdir"/usr/bin/
	install -Dm755 src/seniormenu -t "$pkgdir"/usr/bin/
	install -Dm644 completions/senior.zsh-completion "$pkgdir"/usr/share/zsh/site-functions/_senior
	install -Dm644 completions/senior.bash-completion "$pkgdir"/usr/share/bash-completion/completions/senior
}
