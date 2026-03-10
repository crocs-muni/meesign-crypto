{
  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix.url = "github:nix-community/fenix";
  };

  outputs = {
    self,
    flake-utils,
    nixpkgs,
    fenix,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = (import nixpkgs) {
          inherit system;
          overlays = [fenix.overlays.default];
        };

        # kudos to: https://jordankaye.dev/posts/rust-wasm-nix/
        f = with fenix.packages.${system}; combine [
          stable.toolchain
          targets.wasm32-unknown-unknown.stable.rust-std
        ];

        meesign-crypto = pkgs.callPackage ./default.nix { wasm = true; };
      in rec {
        defaultPackage = meesign-crypto;

        devShell = pkgs.mkShell {
          nativeBuildInputs = with pkgs; [
            f 
            protobuf

            pcsclite
            pkg-config
            rust-analyzer

            wasm-pack
            wasm-bindgen-cli_0_2_106
          ];
        };
      }
    );
}
