{
  description = "Docker-based ClamAV real-time file creation scanner";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};
    in {
      devShells.default = pkgs.mkShell {
        name = "clamav-scanner-devshell";
        packages = with pkgs; [
          docker
          docker-compose
          inotify-tools
          python3
          libnotify
          curl
          netcat
        ];

        shellHook = ''
          export PATH="$PWD/bin:$PATH"
          echo "🛡️ ClamAV Sentinel devShell active."
          echo "Run 'clamav-sentinel --help' for available commands."
        '';
      };
    });
}
