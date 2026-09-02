{
  pkgs,
  lib,
  rustPlatform,
  bpfLinker,
  ebpfArch,
  llvmPackages_22,
}:
let
  manifest = builtins.fromTOML (builtins.readFile ../Cargo.toml);
  inherit (manifest.workspace.package) version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../ncda
      ../ncda-common
      ../ncda-ebpf
    ];
  };

  workspaceCargoDeps = rustPlatform.importCargoLock {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "aya-0.13.2" = "sha256-zfSKuCeXg23Pkiw0ashRXX91aEuY4MFUfSxOzJ8Y+X8=";
    };
  };
  sysrootCargoDeps = rustPlatform.importCargoLock {
    lockFile = ./rust-std-Cargo.lock;
  };

  # `-Z build-std=core` resolves registry dependencies from rust-src's lock
  # file. Add those crates to Cargo's offline workspace vendor directory. Keep
  # this output name because importCargoLock's generated source paths use it.
  cargoDeps = pkgs.runCommand "cargo-vendor-dir" { } ''
    mkdir "$out"
    cp -a ${workspaceCargoDeps}/. "$out/"
    chmod u+w "$out"

    for dependency in ${sysrootCargoDeps}/*; do
      [[ -d "$dependency" ]] || continue
      destination="$out/$(basename "$dependency")"
      if [[ ! -e "$destination" ]]; then
        ln -s "$dependency" "$destination"
      fi
    done
    test -e "$out/rustc-literal-escaper-0.0.8"
  '';
in
rustPlatform.buildRustPackage {
  pname = "ncda-ebpf";
  inherit version src cargoDeps;

  nativeBuildInputs = [ bpfLinker ];

  buildPhase = ''
    runHook preBuild

    separator=$'\x1f'
    export CARGO_ENCODED_RUSTFLAGS="--cfg=bpf_target_arch=\"${ebpfArch}\"''${separator}-Cdebuginfo=2''${separator}-Clink-arg=--btf"
    cargo build \
      --locked \
      --offline \
      --release \
      -j "$NIX_BUILD_CORES" \
      --package ncda-ebpf \
      --bin ncda \
      --target bpfel-unknown-none \
      -Z build-std=core

    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall

    install -Dm0444 \
      target/bpfel-unknown-none/release/ncda \
      "$out/lib/ncda/ncda-ebpf"

    runHook postInstall
  '';

  auditable = false;
  dontStrip = true;
  doCheck = false;
  doInstallCheck = true;
  nativeInstallCheckInputs = [ llvmPackages_22.llvm ];
  installCheckPhase = ''
    runHook preInstallCheck

    sections=$(llvm-readelf --sections "$out/lib/ncda/ncda-ebpf")
    llvm-readelf --file-header "$out/lib/ncda/ncda-ebpf" | grep -F 'Machine:' | grep -F 'Linux BPF'
    printf '%s\n' "$sections" | grep -F '.BTF'
    printf '%s\n' "$sections" | grep -F '.BTF.ext'

    runHook postInstallCheck
  '';

  passthru = {
    targetArch = ebpfArch;
    toolchain = "nightly-2026-08-04";
    bpfLinkerVersion = bpfLinker.version;
  };

  meta = {
    description = "eBPF capture programs embedded in ncda";
    homepage = manifest.workspace.package.homepage;
    license = lib.licenses.mit;
    platforms = [
      "aarch64-linux"
      "x86_64-linux"
    ];
  };
}
