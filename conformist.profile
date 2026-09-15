---
# conformist profile (POC v1): the justfile convention linters, delivered as
# cache-pulled artifacts rather than through a Nix module. Hand-written, and
# copied verbatim by each consuming repo (circus, just-us, igloo,
# cutting-garden). See docs/rfcs/0005.
! toml-conformist_profile-v1
---

# ---------------------------------------------------------------------------
# ARTIFACTS
#
# Pins are purpose-full markl-ids (piggy RFC 0011) under conformist's own
# purpose, `conformist-artifact-digest-v1`, in any markl content-digest format
# (sha256 or blake2b256).
#
# All artifacts come from ONE just-us release (v0.1.2), so the binaries and the
# check for their output format move together: the static `just`, one build
# per system (RFC 0005 §2.3), and the platform-independent recipe-model jq
# prelude describing what it emits. Pins were computed from the bytes the urls
# actually serve (`just explore-markl-pin <url>`), not from reported digests.
#
# Linux only: macOS cannot be cross-built from Linux, and the only Mac is
# inactive (RFC 0005 §2.3). A darwin host gets a clear "no build for this
# system" error rather than a wrong binary.
# ---------------------------------------------------------------------------

[artifact.just]
form = "static"

[artifact.just.system.x86_64-linux]
url = "https://code.linenisgreat.com/just-us/releases/download/v0.1.2/just-static-x86_64-unknown-linux-musl"
markl = "conformist-artifact-digest-v1@sha256-c6hhldrmgk8e57kv7a6ptfaf454r053p5udl5g02ue0p2964mqas4q7rq2"

[artifact.just.system.aarch64-linux]
url = "https://code.linenisgreat.com/just-us/releases/download/v0.1.2/just-static-aarch64-unknown-linux-musl"
markl = "conformist-artifact-digest-v1@sha256-q9yzyt2gq6wfjye5v959pw89q3zsk85nutkhwjnw4emehx74n2fsff9g0w"

[artifact.recipe-model-jq]
form = "static"
executable = false
url = "https://code.linenisgreat.com/just-us/releases/download/v0.1.2/recipe-model-v1.jq"
markl = "conformist-artifact-digest-v1@sha256-a4kk3vqnc76j7m4xhlp49ww7wl2ypyn74pa46jx2fakty5msd3fq0jp2xs"

# NOTE: the rule logic is NOT an artifact here. It is authored alongside this
# profile, so it travels inline on the stanza below and inherits this document's
# integrity — no second pin to keep correct. A data artifact remains the right
# home for a rule that is large, shared between profiles, or build-produced
# (RFC 0005 §4.4).

# ---------------------------------------------------------------------------
# LINTER STANZAS
#
# Schema per RFC 0001, plus the inline `rule` field (RFC 0005 §4.4). The runner
# passes `rule` to the tool via a file or stdin — never through a shell command
# line, which is the whole point: the filter below may contain apostrophes and
# needs no escaping.
#
# One requirement this surfaced and the first draft missed: `just` must be
# reachable by BARE NAME, so the runner must put executable artifacts on PATH.
# Otherwise every command interpolates a path for its own tool.
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# PRELUDES
#
# Definitions shared by every rule that lists them, written once. The resolver
# joins a rule's preludes, in the order it lists them, in front of the rule.
# ---------------------------------------------------------------------------

# The recipe-model schema/version pin (`def model`). Not optional: a rule
# reading an absent field such as `doc_prelude` would otherwise pass vacuously
# against any `just` that emitted a different model. It describes just-us's
# output format, so just-us publishes it; its own Nix linters read the same file.
[prelude.recipe-model]
rule-tool = "jq"
artifact = "recipe-model-jq"

# conformist's eng policy over the model's raw data (just-us FDR 0003 policy
# boundary): what counts as public, and what a recipe's verb is.
[prelude.eng-taxonomy]
rule-tool = "jq"
rule = '''
  def public: map(select(.private | not));
  def verb: .name | split("-") | .[0];
'''

# ---------------------------------------------------------------------------
# LINTERS
# ---------------------------------------------------------------------------

[linter.justfile-recipe-names]
command = "just --dump --dump-format model"
rule-tool = "jq"
includes = ["justfile"]
passes-files = false
preludes = ["recipe-model", "eng-taxonomy"]
rule = '''
  ["build","test","validate","verify","lint","run","list","codemod","install",
   "deploy","load","migrate","provision","restart","bump","update","clean",
   "debug","explore"] as $verbs
  | ["default","tag","release"] as $exceptions
  | model
  | .recipes
  | public
  | .[]
  | .name as $name
  | verb as $verb
  | select(($exceptions | index($name)) == null)
  | select(($verbs | index($verb)) == null)
  | "'\(.namepath)' does not start with a known verb (conformist-justfile(7) VERB LIST)"
'''

# conformist-justfile(7) RECIPE DESCRIPTIONS: `just --list` shows only the ONE
# comment line directly above a recipe, so a block of comment lines leaves the
# rest invisible and the description a truncated fragment. Reads the fork-only
# `doc_prelude` field. Covers every public recipe, debug/explore included, and
# has no repair: the fix is editorial. Ported from just-us's
# justfile-orphan-summary module.
[linter.justfile-orphan-summary]
command = "just --dump --dump-format model"
rule-tool = "jq"
includes = ["justfile"]
passes-files = false
preludes = ["recipe-model", "eng-taxonomy"]
rule = '''
  model
  | .recipes
  | public
  | .[]
  | select((.doc_prelude | length) > 0)
  | "recipe '\(.namepath)' has comment lines above its doc comment; `just --list` shows ONLY the last comment line, so the rest is invisible and the description reads as a truncated fragment - separate the prose from the one-line summary with a bare `#` line (or a blank line), and make that summary a whole sentence fragment that stands alone (conformist-justfile(7) RECIPE DESCRIPTIONS)"
'''

# ---------------------------------------------------------------------------
# WHAT WRITING THIS FILE SETTLED
#
# A linter is not a tool. `justfile-recipe-names` is a pipeline over `just`
# (fork-only), `jq`, and a program that IS the rule. Delivering the fork's
# `just` delivered only a third of it; conformist now embeds jq (gojq) and runs
# it in-process, so a consumer needs no jq of its own.
#
# Both carriers for that program are REQUIRED (RFC 0005 §4.4), because they
# answer different questions about where the rule's integrity comes from:
#
#   INLINE, as above — the rule travels in this document, so whatever protects
#   the document protects the rule. No second pin to keep correct. Right for a
#   rule authored alongside its profile, which is most of them.
#
#   DATA ARTIFACT — fetched and pinned separately. Right when the rule is large,
#   shared across profiles, or build-produced, since then it does not travel in
#   the document and needs its own pin.
#
# Inlining into `command` stays REJECTED either way: the program would reach the
# tool through a shell command line, which is the quoting hazard that moving
# these filters into files removed in the first place.
#
# A stanza carrying a rule BOTH ways is an operational error, not a precedence
# question — otherwise a profile's effective rule would not be the one its
# author is reading.
#
# Consequence for v1: this profile needs no artifact-reference syntax at all,
# because its rules are inline. That mechanism is still specified (§4.2) and
# still needed for the artifact case, but it is no longer on v1's critical path.
#
# Porting a SECOND rule surfaced a gap the first could not: shared definitions.
# just-us's Nix modules prepend one jq prelude to every rule; a profile could
# not, so each rule carried its own copy of the model pin. Named preludes (RFC
# 0005 §4.5) close it: each rule LISTS what it depends on, so a reader sees it,
# and a change to the model pin is one edit however many rules use it.
# ---------------------------------------------------------------------------
