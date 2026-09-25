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
  }: let
    perSystem = flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {inherit system;};
      clamav-sentinel = pkgs.stdenv.mkDerivation {
        pname = "clamav-sentinel";
        version = "1.0.0";
        src = ./.;

        nativeBuildInputs = [pkgs.makeWrapper];
        buildInputs = [pkgs.python3];

        installPhase = ''
          mkdir -p $out/bin $out/share/clamav-scanner
          cp -r src $out/share/clamav-scanner/
          cp -r tests $out/share/clamav-scanner/
          cp docker-compose.yml $out/share/clamav-scanner/
          cp bin/clamav-sentinel $out/bin/clamav-sentinel
          chmod +x $out/bin/clamav-sentinel $out/share/clamav-scanner/src/sentinel.py

          wrapProgram $out/bin/clamav-sentinel \
            --prefix PATH : ${pkgs.lib.makeBinPath [
            pkgs.python3
            pkgs.docker
            pkgs.docker-compose
            pkgs.inotify-tools
            pkgs.libnotify
            pkgs.coreutils
            pkgs.curl
            pkgs.netcat
          ]} \
            --set CLAMAV_SCANNER_DIR "$out/share/clamav-scanner" \
            --set PYTHON "${pkgs.python3}/bin/python3"
        '';

        meta = with pkgs.lib; {
          description = "Real-time inotify file creation scanner with ClamAV daemon";
          license = licenses.mit;
          platforms = platforms.linux;
        };
      };
    in {
      packages.default = clamav-sentinel;
      packages.clamav-sentinel = clamav-sentinel;

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
          clamav-sentinel
        ];

        shellHook = ''
          export PATH="$PWD/bin:$PATH"
          echo "🛡️  ClamAV Sentinel devShell active."
          echo "Run 'clamav-sentinel --help' for available commands."
        '';
      };
    });
  in
    perSystem
    // {
      nixosModules.default = {
        config,
        lib,
        pkgs,
        ...
      }:
        with lib; let
          cfg = config.services.clamav-sentinel;
          pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        in {
          options.services.clamav-sentinel = {
            enable = mkEnableOption "ClamAV real-time file creation sentinel";

            watchDir = mkOption {
              type = types.str;
              default = ".";
              description = "Directory to watch for newly created files";
            };

            quarantineDir = mkOption {
              type = types.str;
              default = ".quarantine";
              description = "Directory to store quarantined threats";
            };

            auditLog = mkOption {
              type = types.str;
              default = "clamav-audit.jsonl";
              description = "Path to JSONL audit log file";
            };

            autoQuarantine = mkOption {
              type = types.bool;
              default = true;
              description = "Automatically move infected files to quarantine and strip permissions";
            };
          };

          config = mkIf cfg.enable {
            environment.systemPackages = [pkg];

            systemd.user.services.clamav-sentinel = {
              description = "ClamAV Real-time File Creation Sentinel";
              after = ["default.target"];
              wantedBy = ["default.target"];
              serviceConfig = {
                ExecStart =
                  "${pkg}/bin/clamav-sentinel watch ${cfg.watchDir} --quarantine-dir ${cfg.quarantineDir} --audit-log ${cfg.auditLog}"
                  + (optionalString (!cfg.autoQuarantine) " --no-quarantine");
                Restart = "always";
                RestartSec = 5;
                Environment = [
                  "PYTHONUNBUFFERED=1"
                ];
              };
            };
          };
        };

      nixosModules.clamav-sentinel = self.nixosModules.default;
    };
}
