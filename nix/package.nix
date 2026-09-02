{
  lib,
  rustPlatform,
  ncdaEbpf,
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
in
rustPlatform.buildRustPackage {
  pname = "ncda";
  inherit version src;

  cargoDeps = rustPlatform.importCargoLock {
    lockFile = ../Cargo.lock;
    outputHashes = {
      "aya-0.13.2" = "sha256-zfSKuCeXg23Pkiw0ashRXX91aEuY4MFUfSxOzJ8Y+X8=";
    };
  };

  NCDA_EBPF_OBJECT = "${ncdaEbpf}/lib/ncda/ncda-ebpf";
  NCDA_EBPF_TARGET_ARCH = ncdaEbpf.targetArch;
  NCDA_EBPF_TOOLCHAIN = ncdaEbpf.toolchain;
  NCDA_BPF_LINKER_VERSION = "bpf-linker ${ncdaEbpf.bpfLinkerVersion}";

  cargoBuildFlags = [
    "--package"
    "ncda"
    "--bins"
  ];

  doInstallCheck = true;
  installCheckPhase = ''
    runHook preInstallCheck

    "$out/bin/ncda" --help >/dev/null
    "$out/bin/ncda" --version
    "$out/bin/ncda-bench" --help >/dev/null
    "$out/bin/ncda-bench" --version

    runHook postInstallCheck
  '';

  meta = {
    description = "ncdu-like terminal monitor for live Linux file I/O";
    homepage = manifest.workspace.package.homepage;
    changelog = "${manifest.workspace.package.repository}/blob/v${manifest.workspace.package.version}/CHANGELOG.md";
    license = lib.licenses.mit;
    mainProgram = "ncda";
    platforms = [
      "aarch64-linux"
      "x86_64-linux"
    ];
  };
}
