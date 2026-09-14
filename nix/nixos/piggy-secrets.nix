# NixOS module — `services.piggy-secrets` via home-manager.
#
# Adds the home-manager piggy-secrets module to every home-manager-managed
# user on this host, so callers can write:
#
#   home-manager.users.alice.services.piggy-secrets = {
#     enable = true;
#     files.api-token = {
#       source = ./secrets/api-token.ebox;
#       target = ".config/app/token";
#     };
#   };
#
# Requires that the NixOS configuration also imports the home-manager NixOS
# module; without it, evaluation fails on the unknown
# `home-manager.sharedModules` option. Re-exported under the home-manager
# namespace rather than as a NixOS-native surface, like piggy-agent: PIV
# decryption needs the card or a forwarded agent in the user's session, so
# it has no root/boot-time form (FDR 0003).
{ ... }:
{
  home-manager.sharedModules = [ ../hm/piggy-secrets.nix ];
}
