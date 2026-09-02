{
  lib,
  rustPlatform,
  fetchFromGitHub,
  btfdump,
  llvmPackages_22,
  zlib,
  libxml2,
}:
rustPlatform.buildRustPackage rec {
  pname = "bpf-linker";
  version = "0.11.0";

  src = fetchFromGitHub {
    owner = "aya-rs";
    repo = "bpf-linker";
    tag = "v${version}";
    hash = "sha256-uMpLQR2FAI96MYfWo8lR9pUeWhswY6wMUOxQwq3hCdw=";
  };

  cargoHash = "sha256-asCS4oLMXJ4y4vCDRsq2kuTOOPHebT0Dd+AE20GkZvI=";

  buildNoDefaultFeatures = true;
  buildFeatures = [ "llvm-22" ];

  buildInputs = [
    zlib
    libxml2
    (lib.getLib llvmPackages_22.llvm)
  ];

  nativeCheckInputs = [
    btfdump
    llvmPackages_22.clang.cc
    llvmPackages_22.llvm
  ];

  meta = {
    description = "Simple BPF static linker";
    homepage = "https://github.com/aya-rs/bpf-linker";
    changelog = "https://github.com/aya-rs/bpf-linker/releases/tag/v${version}";
    license = with lib.licenses; [
      asl20
      mit
    ];
    mainProgram = "bpf-linker";
    platforms = [
      "aarch64-linux"
      "x86_64-linux"
    ];
  };
}
