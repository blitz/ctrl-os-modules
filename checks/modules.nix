{
  pkgs,
  nixosModules,
}:

let
  inherit (pkgs) lib;
  check = import ../lib/check-modules-no-ops.nix {
    inherit pkgs;
    modules = removeAttrs nixosModules (
      if lib.versionAtLeast lib.version "26.11" then
        [ ]
      else
        [
          # See the module for reasons why this is disabled.
          "image"
        ]
    );
  };
in
builtins.seq check.result (
  (pkgs.writeText "modules-check" (builtins.toJSON check.result)) // { inherit check; }
)
