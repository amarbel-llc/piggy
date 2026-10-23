# Operator-act dialog on darwin: zenity, GTK, native, or tty only

Status: exploration note for piggy#334, 2026-10-23. No code. Written after the
piggy#332 series (RFC 0012 §2.6 input hold, tty locks, zenity refusal, GTK
cancel hold and 100-column wrap). Facts are cited to the tree; anything
untested on a Mac is marked as such.

## Where things stand

An operator-act prompt must, per RFC 0012 §2.6 as amended and the operator's
2026-10-23 decisions:

1. hold **all** input, cancel included, for at least 2 s after the text is
   first shown, discarding (not queueing) what arrives, with the hold visible;
2. show the act's **class** recognisably before the text is read (band colour
   and symbol, piggy#319);
3. show the **text verbatim**, never elided, with each markl-id's leading
   characters emphasized by attributes, not markup (option (a));
4. **refuse a too-tall text** before any dialog opens (24 rendered lines at
   100 columns, piggy#322);
5. take the PIN in a field that **cannot be pre-filled** by anything but the
   operator's keystrokes after the hold.

Surfaces today:

| Surface | Where | 1 hold | 2 class | 3 verbatim + emphasis | 4 tall refusal | 5 PIN field |
|---|---|---|---|---|---|---|
| `piggy-askpass-gtk` | Linux only (`flake.nix`: `platforms = linux`) | yes, incl. cancel (095fca0) | yes | yes (c8cd5f5) | yes (script) | yes, insensitive during the hold |
| zenity | both | **no**: no way to make fields insensitive for a while | partial (markup band in a form) | needs escaping; no emphasis without markup | yes (script) | no hold |
| askpass tty branch | both | yes (c8c64ba) | banner line | verbatim; no emphasis yet | no limit needed | echo off, drained |
| agent `/dev/tty` prompt | both | yes (c8c64ba) | `Context:` line | verbatim | no limit needed | echo off, `tcflush` |

Operator acts are now refused on zenity (4887680).

**The darwin gap is larger than "tty only".** The home-manager module runs the
agent as a launchd agent on darwin (and a systemd user unit on Linux) with
`SSH_ASKPASS_REQUIRE=force` (`nix/hm/piggy-agent.nix`, the launchd block
around line 1033). Under `force` the agent always spawns the askpass
(`card_oracle.rs`, `pin_route`), and the askpass skips its tty branch. So
for the **service** agent on darwin, with zenity refused, there is today **no
surface at all** for an operator act. The two tty locks only serve an agent
the operator runs in a terminal (`piggy agent -D`, `SSH_ASKPASS_REQUIRE`
unset or `never`). A launchd agent has no controlling terminal to prompt on.

## Options

### A. zenity as is (undo the refusal on darwin)

- Enforces: 4 only. Not 1: zenity has no way to hold input, so a keystroke
  meant for another window can fill in or confirm the act. Not 5 for the same
  reason. 2 and 3 only through Pango markup, which the RFC forbids reading in
  the text and which then needs careful escaping (the escaping removed in
  4887680).
- Cost: none.
- Verdict: fails the RFC as amended. Not an option without an RFC exception
  for darwin, which would make a darwin operator act weaker evidence than a
  Linux one; a verifier cannot tell which platform the act came from.

### B. GTK on darwin (build `piggy-askpass-gtk` for darwin too)

- Enforces: all five, from the same code as Linux.
- Cost:
  - The derivation is Linux-only today; GTK 4 on darwin builds against a
    Quartz backend. **Not tried here**: whether nixpkgs' `gtk4` builds and
    runs well on darwin, and whether a launchd-spawned GTK app can open a
    window and take focus in the Aqua session, are unverified.
  - GTK on macOS looks and behaves foreign: focus stealing, keyboard focus on
    first open, and Spaces/full-screen behaviour are the things to test. The
    dialog's value depends on taking focus when it opens (the hold clock
    assumes the operator is looking at it).
  - A large closure (GTK, GLib, Pango, Cairo, fonts) in the askpass wrapper on
    every darwin host.
- Verdict: the cheapest way to equal behaviour, if it works. The first thing to
  try, as an exploration recipe, before writing anything new.

### C. A native macOS dialog (a small AppKit program)

- Enforces: all five. AppKit can disable controls for 2 s, swallow key events
  (`NSEvent` local monitor), draw the band and clock, set attributed text for
  the emphasis, size to content, and use `NSSecureTextField`, which on macOS
  also turns on secure event input (other processes cannot read the
  keystrokes while it has focus), something the GTK dialog does not get.
- Cost:
  - A second dialog implementation to keep in step with the GTK one (same
    options, same exit codes, same clock rules), in Swift or Objective-C, or in
    Rust over `objc2`/AppKit bindings.
  - A darwin build in the flake (Swift in nixpkgs on darwin, or the Rust
    route). **Not tried here.**
  - It looks right on a Mac and takes focus the native way.
- Verdict: the best result on a Mac, at the price of two dialogs.

### D. tty-only darwin policy

- Enforces: 1, 3 (no emphasis yet), 5 on the tty; 2 as a banner line; 4 is not
  needed. Already implemented (c8c64ba).
- Cost: none in code, but as shown above the **service** agent cannot use it.
  It would mean: on darwin, operator acts only from an agent run in a terminal
  with `SSH_ASKPASS_REQUIRE` not `force`, and the launchd agent refuses them.
  That is a usable stopgap for an operator who signs operator acts rarely, not
  a steady state.

### E. One shared toolkit for both platforms (for completeness)

Replace the GTK dialog with a cross-platform Rust UI (for example egui over
winit) and build it for both. Enforces all five, one codebase. Cost: a rewrite
of a dialog that works on Linux today, an immediate-mode UI's accessibility and
input-method gaps (a PIN is digits, so input methods matter little), and still
an untested focus story on macOS. Not recommended now; worth revisiting only if
B fails and C's second implementation becomes a burden.

## Recommendation

1. **Now: D, stated plainly.** Document that on darwin the launchd agent
   refuses operator acts (it already does: zenity is refused, the tty branch
   is skipped under `force`), and that an operator act on a Mac is signed from
   an agent run in a terminal. Make the refusal reason say so on darwin, so
   the caller knows where to go.
2. **Next: try B** as an exploration recipe on a Mac: build
   `piggy-askpass-gtk` for darwin, run it from a launchd-spawned askpass, and
   check focus, the hold, the clock and the band. If it works acceptably, ship
   it and darwin reaches parity with one dialog.
3. **If B does not work well: C**, a native AppKit dialog with the same
   command-line contract as `piggy-askpass-gtk`, so `piggy-askpass.sh` picks
   whichever is on PATH. Its secure-input property is a reason to prefer it
   even if B merely works.
4. **Keep zenity** for routine PIN prompts only, where none of the five rules
   apply; it costs nothing and is the fallback on hosts without either dialog.
   Retire it when both platforms ship a dialog of their own.

Open: whether the operator signs operator acts from a Mac at all in practice;
if not, D is enough and B/C can wait.

## Related

piggy#332 (the series this follows), piggy#322 (height limit), piggy#319
(class bands), RFC 0012 §2.6, FDR 0006 (the holder and its display
surfaces), `contrib/piggy-askpass.sh`, `crates/piggy-askpass-gtk`.
