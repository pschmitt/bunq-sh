{
  description = "bunq.sh CLI wrapper";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        version =
          let
            rev =
              if self ? shortRev then
                self.shortRev
              else if self ? dirtyShortRev then
                self.dirtyShortRev
              else
                "unknown-dirty";
          in
          "${pkgs.lib.substring 0 8 self.lastModifiedDate}-${rev}";

        bunq = pkgs.stdenvNoCC.mkDerivation {
          pname = "bunq";
          inherit version;
          src = ./.;

          nativeBuildInputs = [
            pkgs.makeWrapper
          ];

          installPhase = ''
            runHook preInstall

            mkdir -p "$out/bin" "$out/libexec/bunq"
            cp bunq.sh "$out/libexec/bunq/bunq.sh"
            chmod +x "$out/libexec/bunq/bunq.sh"

            makeWrapper "$out/libexec/bunq/bunq.sh" "$out/bin/bunq" \
              --prefix PATH : ${pkgs.lib.makeBinPath [
                pkgs.bash
                pkgs.coreutils
                pkgs.curl
                pkgs.jq
                pkgs.openssl
                pkgs.util-linux
              ]}

            runHook postInstall
          '';

          meta = with pkgs.lib; {
            description = "Shell client for the bunq API";
            license = licenses.gpl3Plus;
            platforms = platforms.linux ++ platforms.darwin;
            mainProgram = "bunq";
          };
        };
      in
      {
        packages.default = bunq;
        packages.bunq = bunq;

        apps.default = {
          type = "app";
          program = "${bunq}/bin/bunq";
        };

        devShells.default = pkgs.mkShell {
          packages = [
            pkgs.bash
            pkgs.coreutils
            pkgs.curl
            pkgs.jq
            pkgs.nixfmt-rfc-style
            pkgs.openssl
            pkgs.shellcheck
            pkgs.util-linux
          ];
        };
      }
    );
}
