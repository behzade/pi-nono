{
  description = "pi-nono native sandbox, approval transport, and background-job extension";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs = { nixpkgs, self, ... }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-darwin"
        "aarch64-linux"
        "x86_64-linux"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          piNono = pkgs.callPackage ./nix/pi-nono.nix {
            nono = pkgs.nono;
          };
        in
        {
          pi-nono = piNono;
          default = piNono;
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          pi-nono = self.packages.${system}.pi-nono;
          pi-nono-tests = pkgs.runCommand "pi-nono-tests" {
            nativeBuildInputs = [ pkgs.nodejs ];
          } ''
            cp ${self}/extensions/sandbox/*.ts .
            cp ${self}/extensions/sandbox/package-lock.test.mjs .
            cp ${self}/extensions/sandbox/package-lock.json .
            cp -R ${self.packages.${system}.pi-nono}/node_modules .
            chmod -R u+w node_modules
            node --test package-lock.test.mjs ${self}/packaging/npm/build-packages.test.mjs
            node --import ./test-setup.ts --test \
              approval-transport.test.ts \
              native-process-sessions.test.ts \
              process-sessions.test.ts \
              io-permissions.test.ts \
              io-policy.test.ts \
              linux-deny-layer.test.ts \
              native-sandbox-ops.test.ts \
              network-policy.test.ts \
              nono-client.test.ts \
              packaged-executables.test.ts \
              project-policy.test.ts \
              sandbox-config.test.ts \
              sandbox-policy.test.ts \
              session-policy-store.test.ts \
              tool-schemas.test.ts
            touch "$out"
          '';
        }
      );
    };
}
