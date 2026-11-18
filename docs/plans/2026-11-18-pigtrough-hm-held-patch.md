# pigtrough: the held home-manager change for the card sitting

Status: HELD. Nothing here is applied anywhere. It is the change the
operator's host needs so steps 3 and 4 of `2026-11-18-pigtrough-card-sitting.md`
are copy-paste: `services.pigtrough` enabled with the two routes, so
`systemctl --user start pigtrough-load` has something to load. The host's
home-manager file is circus's; this note gives its content, and a circus
session applies it in the operator's deploy window.

Written against piggy master (`nix/hm/pigtrough.nix`, options `package`,
`piggyPackage`, `dir`, `routes`, `loadEnvironment`). Not evaluated against
the real host config: that needs the host's flake, which this session has not
seen. Run `just test-nix-hm-pigtrough-module` here only checks the module
with synthetic routes.

## What it needs (open until circus answers)

| Value | Where it comes from | Status |
|---|---|---|
| the module import | piggy flake output `homeManagerModules.pigtrough`, imported beside `homeManagerModules.piggy-agent` on the operator's host | file unknown; asked circus/free-baobab |
| `package` | `piggy.packages.${system}.pigtrough` | as the module's comment says: no silent fallback |
| `piggyPackage` | the host's existing piggy package | |
| Forgejo host | the forge's name as clients use it | asked circus; `smith auth list` also prints it |
| CA PEM | the file that signs the forge's TLS certificate | asked circus; unknown |
| `secret` names | `github/forgejo-mirror` (the pilot's entry, known) and the Forgejo read-only token entry | the second is the operator's: `piggy pass ls \| grep -i forgejo` |
| `loadEnvironment` | what `piggy pass show` needs in a user unit: the agent socket and the askpass display | the operator's session values; see below |

## The change (shape, to be filled in)

    # in the operator's home-manager config, beside piggy-agent
    imports = [ piggy.homeManagerModules.pigtrough ];

    services.pigtrough = {
      enable = true;
      package = piggy.packages.${pkgs.system}.pigtrough;
      piggyPackage = piggy.packages.${pkgs.system}.default;   # or the host's existing one
      dir = "/run/user/1000/pigtrough";                        # short; the default also works

      routes = [
        # With any route in `routes`, the compiled-in github-api route is GONE:
        # restate it, byte for byte what pigtrough(1) says it serves.
        {
          name = "github-api";
          upstream = "api.github.com";
          auth = "bearer";
          secret = "github/forgejo-mirror";
          owners = [ "amarbel-llc" ];
          forward_headers = [ "accept" "content-type" "user-agent" "x-github-api-version" "if-none-match" "if-modified-since" ];
          allow = [
            { method = "GET";   path = [ "repos" "{owner}" "{name}" ]; }
            { method = "POST";  path = [ "orgs" "{owner}" "repos" ]; }
            { method = "PATCH"; path = [ "repos" "{owner}" "{name}" ]; }
            { method = "PUT";   path = [ "repos" "{owner}" "{name}" "topics" ]; }
            { method = "GET";   path = [ "repos" "{owner}" "{name}" "commits" "{ref}" ]; }
            { method = "GET";   path = [ "repos" "{owner}" "{name}" "compare" "{ref-range}" ]; }
          ];
        }
        {
          name = "forgejo-api";
          upstream = "FORGEJO_HOST";                   # FILL-IN
          auth = "token";                              # smith sends `token`, never Bearer
          secret = "FORGEJO_SECRET_ENTRY";             # FILL-IN
          owners = [ "FORGEJO_OWNER" ];                # FILL-IN
          extra_roots = [ "/path/to/forge-ca.pem" ];   # FILL-IN
          loopback_port = 8731;                        # only if smith goes through TCP
          allow = [
            { method = "GET"; path = [ "api" "v1" "repos" "{owner}" "{name}" ]; }
          ];
        }
      ];

      loadEnvironment = {
        # What the load unit's `piggy pass show` needs; a user unit does not
        # inherit the shell. Fill from the operator's session (`systemctl
        # --user show-environment`; compare `env | grep -e SSH -e DISPLAY`).
        SSH_AUTH_SOCK = "FILL-IN";
        # SSH_ASKPASS / SSH_ASKPASS_REQUIRE / WAYLAND_DISPLAY or DISPLAY, as
        # the operator's piggy needs them.
      };
    };

Two points a reviewer should check, both from reading the module, neither
run:

1. **The github route must be restated.** The module serves the compiled-in
   `github-api` route only when `routes` is empty; any route replaces it, and
   `pigtrough load github-api` would then fail "unknown route". The block
   above restates it field for field from the test
   `the_compiled_in_github_route_round_trips` in
   `crates/pigtrough/src/table.rs` (`auth = "bearer"`, the six allow rows and
   the `forward_headers` list), which asserts the TOML equals the compiled-in
   route. Read, not run.
2. **`extra_roots` is read by the serve unit**, a user unit with
   `NoNewPrivileges` and no filesystem restrictions, so a PEM readable by the
   operator is enough. A store path from nix is simplest.

## After it is applied

    home-manager switch              # or the host's usual switch
    systemctl --user restart pigtrough
    systemctl --user status pigtrough --no-pager | head -5
    systemctl --user start pigtrough-load

(the same four commands as steps 3 and 4 of the sitting). Expected: the
status shows `active (running)` and `serving route github-api ... serving
route forgejo-api ... (no secret loaded)` in `journalctl --user -u
pigtrough -n 5`; the load unit ends `all 2 routes loaded`.

## Not decided here

- Whether `loadEnvironment` can be left empty on this host. Untested: the
  card sitting's step 3 is what finds out.
- The Forgejo `allow` list: the sitting needs one GET; smith's own list
  (issues, pulls, contents, ...) is in
  `2026-11-17-pigtrough-forgejo-route.md` and is a separate, later step.
