{
  description = "OpenClaw Scanner - Continuous compliance scanning daemon";

  inputs = {
    nixpkgs.follows = "substrate/nixpkgs";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    substrate = {
      url = "github:pleme-io/substrate";
      inputs.fenix.follows = "fenix";
    };
    forge = {
      url = "github:pleme-io/forge";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.fenix.follows = "fenix";
      inputs.substrate.follows = "substrate";
      inputs.crate2nix.follows = "crate2nix";
    };
    crate2nix = {
      url = "github:nix-community/crate2nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # Follow substrate's devenv pin — fleet source of truth (Pillar 12).
    devenv.follows = "substrate/devenv";
  };

  outputs = { self, nixpkgs, substrate, forge, crate2nix, devenv, ... }:
    (import "${substrate}/lib/rust-service-flake.nix" {
      inherit nixpkgs substrate forge crate2nix devenv;
    }) {
      inherit self;
      serviceName = "openclaw-scanner";
      registry = "ghcr.io/pleme-io/openclaw-scanner";
      packageName = "openclaw-scanner";
      namespace = "openclaw-system";
      architectures = ["amd64" "arm64"];
      ports = { api = 9090; health = 9090; metrics = 9090; };
      moduleDir = null;
      nixosModuleFile = null;
    };
}
