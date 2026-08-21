#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || ! $1 =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  echo "usage: $0 VERSION" >&2
  exit 2
fi

version=$1
sed -i -E "0,/^version = \"[^\"]+\"$/s//version = \"${version}\"/" Cargo.toml

for package in ncda ncda-common ncda-ebpf; do
  awk -v package="$package" -v version="$version" '
    /^\[\[package\]\]$/ { in_package = 0 }
    $0 == "name = \"" package "\"" { in_package = 1 }
    in_package && /^version = "/ {
      $0 = "version = \"" version "\""
      in_package = 0
    }
    { print }
  ' Cargo.lock > Cargo.lock.tmp
  mv Cargo.lock.tmp Cargo.lock
done

cargo metadata --locked --no-deps --format-version 1 >/dev/null
