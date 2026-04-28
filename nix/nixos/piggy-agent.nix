# NixOS module — `services.piggy-agent` via home-manager.
#
# Adds the home-manager piggy-agent module to every
# home-manager-managed user on this host, so callers can write:
#
#   home-manager.users.alice.services.piggy-agent = {
#     enable = true;
#     guid = "ABCD1234ABCD1234ABCD1234ABCD1234";
#   };
#
# Requires that the NixOS configuration also imports the home-manager
# NixOS module (e.g. `home-manager.nixosModules.home-manager` from
# the home-manager flake, or `<home-manager/nixos>` on channels).
# Without it, evaluation fails on the unknown
# `home-manager.sharedModules` option — a clear pointer to the
# missing import.
#
# Per the v1.0 scoping decision (OQ4 in
# docs/plans/2026-04-27-piggy-agent-nix-module.md): re-export under
# the home-manager namespace rather than provide a parallel
# NixOS-native surface. Users who don't run home-manager are out of
# scope for v1.0.
{ ... }:
{
  home-manager.sharedModules = [ ../hm/piggy-agent.nix ];
}
