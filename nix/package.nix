{
  lib,
  rustPlatform,
  rustupShim,
  bpfLinker,
}:
let
  manifest = builtins.fromTOML (builtins.readFile ../Cargo.toml);
in
rustPlatform.buildRustPackage {
  pname = "ncda";
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

  # Cargo.lock contains Aya git dependencies. fetchCargoVendor turns the full
  # lock into one fixed-output source tree and keeps the nested eBPF build
  # offline as well.
  cargoHash = lib.fakeHash;

  nativeBuildInputs = [
    rustupShim
    bpfLinker
  ];

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
