{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/4590696c8693fea477850fe379a01544293ca4e2";
    nixpkgs-master.url = "github:NixOS/nixpkgs/e2dde111aea2c0699531dc616112a96cd55ab8b5";
    utils.url = "https://flakehub.com/f/numtide/flake-utils/0.1.102";

    pivy = {
      url = "github:amarbel-llc/pivy";
      inputs.nixpkgs.follows = "nixpkgs";
      inputs.nixpkgs-master.follows = "nixpkgs-master";
      inputs.utils.follows = "utils";
    };

  };

  outputs =
    {
      self,
      nixpkgs,
      nixpkgs-master,
      utils,
      pivy,
    }:
    (utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        pkgs-master = import nixpkgs-master { inherit system; };

        runtimeDeps = [
          pivy.packages.${system}.default
          pkgs.git
          pkgs.tree
          pkgs.qrencode
          pkgs.getopt
          pkgs.gnugrep
          pkgs.coreutils
        ];
      in
      {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "piggy";
          version = "0.1.0";

          src = ./.;

          nativeBuildInputs = [ pkgs.makeWrapper ];

          installPhase = ''
            mkdir -p $out/lib/piggy/platform $out/bin

            install -m 0755 src/piggy.sh $out/lib/piggy/piggy
            if [ -f src/platform/darwin.sh ]; then
              install -m 0644 src/platform/darwin.sh $out/lib/piggy/platform/darwin.sh
            fi
            if [ -f src/platform/linux.sh ]; then
              install -m 0644 src/platform/linux.sh $out/lib/piggy/platform/linux.sh
            fi

            makeWrapper $out/lib/piggy/piggy $out/bin/piggy \
              --prefix PATH : ${pkgs.lib.makeBinPath runtimeDeps}
          '';

          meta = with pkgs.lib; {
            description = "PIV-based password store using pivy-box and ebox templates";
            license = licenses.gpl2Plus;
            platforms = platforms.linux ++ platforms.darwin;
          };
        };

        devShells.default = pkgs.mkShell {
          packages = runtimeDeps ++ [
            pkgs-master.just
          ];
        };
      }
    ));
}
