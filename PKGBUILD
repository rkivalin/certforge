# Maintainer: Roman Kivalin <roman@shl.dev>
pkgname=certforge
pkgver=0.4.0
pkgrel=1
pkgdesc='ACME certificate manager with DANE and systemd integration'
arch=('x86_64' 'aarch64')
url='https://github.com/rkivalin/certforge'
license=('MIT')
depends=('systemd-libs')
makedepends=('rustup')
backup=('etc/certforge/config.toml')
options=(!lto)

prepare() {
  cd "$startdir"
  export RUSTUP_TOOLCHAIN=stable
  cargo fetch --locked --target "$( rustc -vV | sed -n 's/host: //p' )"
}

build() {
  cd "$startdir"
  export RUSTUP_TOOLCHAIN=stable
  export CARGO_TARGET_DIR=target
  cargo build --frozen --release
}

check() {
  cd "$startdir"
  export RUSTUP_TOOLCHAIN=stable
  export CARGO_TARGET_DIR=target
  cargo test --frozen
}

package() {
  cd "$startdir"

  install -Dm755 "target/release/$pkgname" "$pkgdir/usr/bin/$pkgname"
  install -Dm644 examples/certforge.service "$pkgdir/usr/lib/systemd/system/certforge.service"
  install -Dm644 examples/certforge.timer "$pkgdir/usr/lib/systemd/system/certforge.timer"
  install -Dm644 examples/config.toml "$pkgdir/etc/certforge/config.toml"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"

  install -dm750 "$pkgdir/etc/certforge/certs"
  install -dm700 "$pkgdir/var/lib/certforge"
}
