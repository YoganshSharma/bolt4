{
  description = "Lightning route builder";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{
      self,
      nixpkgs,
      flake-utils,
      fenix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        rustPackages = fenix.packages.${system}.stable;
      in
      {
        devShells = {
          default = pkgs.mkShell {
            buildInputs =
              [ rustPackages.toolchain ]
              ++ (
                with pkgs;
                lib.optionals stdenv.isDarwin [
                  libiconv
                  darwin.apple_sdk.frameworks.Security
                ]
              );
          };
        };

        # packages = { default = ... };
      }
    );
}
