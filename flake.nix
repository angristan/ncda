{
  description = "Live Linux file I/O monitor powered by eBPF";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";

    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      rust-overlay,
    }:
    let
      systems = [
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      packageContext =
        system:
        let
          pkgs = import nixpkgs {
            inherit system;
            overlays = [ rust-overlay.overlays.default ];
          };
          userspaceRust = pkgs.rust-bin.stable."1.97.1".default;
          ebpfRust = pkgs.rust-bin.nightly."2026-08-04".minimal.override {
            extensions = [ "rust-src" ];
          };
          rustPlatform = pkgs.makeRustPlatform {
            cargo = userspaceRust;
            rustc = userspaceRust;
          };
          ebpfRustPlatform = pkgs.makeRustPlatform {
            cargo = ebpfRust;
            rustc = ebpfRust;
          };
          bpfLinker = pkgs.callPackage ./nix/bpf-linker.nix {
            rustPlatform = ebpfRustPlatform;
          };
          rustupShim = pkgs.callPackage ./nix/rustup-shim.nix {
            inherit ebpfRust;
          };
          ncda = pkgs.callPackage ./nix/package.nix {
            inherit
              bpfLinker
              rustPlatform
              rustupShim
              ;
          };
        in
        {
          inherit
            bpfLinker
            ebpfRust
            ncda
            pkgs
            rustupShim
            userspaceRust
            ;
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          context = packageContext system;
        in
        {
          inherit (context) ncda;
          default = context.ncda;
        }
      );

      apps = forAllSystems (system: {
        default = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/ncda";
        };
        ncda-bench = {
          type = "app";
          program = "${self.packages.${system}.default}/bin/ncda-bench";
        };
      });

      checks = forAllSystems (
        system:
        let
          context = packageContext system;
        in
        {
          package = context.ncda;

          formatting = context.pkgs.runCommand "ncda-formatting" {
            nativeBuildInputs = [ context.userspaceRust ];
          } ''
            cargo fmt --all --manifest-path ${self}/Cargo.toml -- --check
            touch "$out"
          '';

          toolchains = context.pkgs.runCommand "ncda-toolchains" {
            nativeBuildInputs = [
              context.bpfLinker
              context.rustupShim
              context.userspaceRust
            ];
          } ''
            rustc --version | grep -F 'rustc 1.97.1 '
            nightly_version=$(rustup run nightly-2026-08-04 rustc --version --verbose)
            printf '%s\n' "$nightly_version" \
              | grep -F 'commit-hash: 504869653f510b279c542e65ccd1ea9710c119ba'
            printf '%s\n' "$nightly_version" | grep -F 'LLVM version: 22.'
            bpf-linker --version | grep -Fx 'bpf-linker 0.11.0'
            touch "$out"
          '';
        }
      );

      devShells = forAllSystems (
        system:
        let
          context = packageContext system;
        in
        {
          default = context.pkgs.mkShell {
            packages = [
              context.bpfLinker
              context.rustupShim
              context.userspaceRust
            ];
          };
        }
      );

      formatter = forAllSystems (system: (packageContext system).pkgs.nixfmt);
    };
}
