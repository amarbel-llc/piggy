# NixOS module — `piggy.secrets` via home-manager.
#
# Adds the home-manager piggy-secrets module to every
# home-manager-managed user on this host, so callers can write:
#
#   home-manager.users.alice.piggy.secrets.db-password = {
#     eboxFile = ./secrets/db-password.ebox;
#   };
#
# Requires that the NixOS configuration also imports the home-manager
# NixOS module (e.g. `home-manager.nixosModules.home-manager` from the
# home-manager flake, or `<home-manager/nixos>` on channels). Without it,
# evaluation fails on the unknown `home-manager.sharedModules` option — a
# clear pointer to the missing import.
#
# Re-exported under the home-manager namespace rather than a parallel
# NixOS-native surface, mirroring `nixosModules.piggy-agent`: piggy
# decryption is PIV-interactive (needs the card + agent), so it belongs in
# the user's session, not a root boot-time activation. See the header of
# nix/hm/piggy-secrets.nix.
{ ... }:
{
  home-manager.sharedModules = [ ../hm/piggy-secrets.nix ];
}
