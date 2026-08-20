#!/usr/bin/env bash
set -euo pipefail

version=v0.11.0
case "$(uname -m)" in
  x86_64)
    archive=bpf-linker-x86_64-unknown-linux-musl.tar.zst
    checksum=10f62ba9ab7e544d538370552660efcb4f1a19153d5752bbf0f6b51f3bada450
    ;;
  aarch64)
    archive=bpf-linker-aarch64-unknown-linux-musl.tar.zst
    checksum=d09ddd83303e9ab1443f51e0e284680154009646a3ce141c63d838ee61b73eb9
    ;;
  *)
    echo "unsupported architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

install_root=${INSTALL_ROOT:-"$HOME/.local/bin"}
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
url="https://github.com/aya-rs/bpf-linker/releases/download/$version/$archive"
curl --fail --location --proto '=https' --tlsv1.2 --output "$temporary/$archive" "$url"
printf '%s  %s\n' "$checksum" "$temporary/$archive" | sha256sum --check --status
mkdir -p "$install_root"
tar --zstd --extract --file "$temporary/$archive" --directory "$install_root" bpf-linker
chmod 0755 "$install_root/bpf-linker"
"$install_root/bpf-linker" --version
