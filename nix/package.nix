{
  pkgs,
  lib,
  rustPlatform,
  rustupShim,
  bpfLinker,
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

  # `-Z build-std=core` also resolves registry dependencies from rust-src's
  # lock file. Merge those crates into the normal workspace vendor tree while
  # preserving the workspace Cargo.lock and Git source configuration. Naming
  # the result cargo-vendor-dir keeps importCargoLock's relative path valid.
  sysrootCargoDeps = rustPlatform.importCargoLock {
    lockFile = ./rust-std-Cargo.lock;
  };
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
  pname = "ncda";
  inherit version src cargoDeps;

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
