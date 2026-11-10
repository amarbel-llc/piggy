piggy-acts(7)

# NAME

piggy-acts - operator acts, the chain, and the stencil stack, in plain words

# DESCRIPTION

An *act* is a small signed document. It says one thing: this key belongs
to this session, or this session may do these things, or this session may
now do one more thing, or this decision is approved, or that earlier act
is cancelled. The operator's PIV card signs the acts that start a chain
and the acts that add anything. A session's own key signs the acts that
hand down less.

This page explains how acts combine, without the formal language. The
normative text is RFC 0013 (*docs/rfcs/0013-signed-hyphence-acts.md*).
The wire protocol the card uses to sign one is RFC 0012. RFC 0013 was
accepted on 2026-11-10. The document, its seal, the producer (*piggy act
seal*) and the chain walk (*piggy act verify*, *piggy*(1)) are built.

# THE CHAIN

Every chain starts at the card. The operator sees the act's text at the
PIN prompt, enters the PIN, touches the card, and the act is signed. That
act is a *root*: it binds a session's key to the session's name and lists
the rights the session may use.

A session may hand down a *link* to a child it spawns, signed with its own
key, no prompt. The link may list only rights the parent holds. A session
may also *narrow* itself, dropping rights for the rest of its life. Nobody
needs the card for any of this, because none of it adds anything.

Adding is the card's alone. An *escalation* gives one session more than
its chain allows, for a bounded time. An *approval* records that the
operator saw a decision and said yes; it confers no right. A *revocation*
cancels an act and everything under it. The card may revoke anything, at
its own prompt; a session may revoke, without the card, an act it signed
or any act below it on its chain, because cancelling only takes away.

The rule under all of it: *rights move down, never up, without the card.*

# RIGHTS AND CONDITIONS

An act carries two kinds of permission, and they are checked differently.

*Rights*
	Short names a tool owns, like *spinclass:merge* or *moxy:kind:write*.
	A right is the coarse ceiling. An act's rights are checked as a set:
	a child's set must sit inside its parent's. That check is cheap and
	always has an answer.

*Conditions*
	The fine detail: which tools, which paths, which recipe groups, which
	argument values. Conditions live in a *capability profile*, a tree of
	allowed things that the act pins by digest (the *profile* line), or in
	the act's body, a patch written in the same family of formats (the
	stencil fragment of trellis, cutting-garden RFC 0014 and FDR 0028)
	that may only take things away. Conditions are never compared between
	a child and its parent. They are stacked. The next section says what
	that means.

# THE STENCIL STACK

Think of each document on a chain as a stencil: a sheet with holes cut
in it. A hole is an allowance ("folio may read under this worktree").
A call is a beam of light aimed at the stack; it passes only where
*every* stencil has a hole. Every hand-down adds a stencil, nobody cuts a
hole in someone else's stencil (a child may only add a sheet with fewer
holes, or a solid *patch* over a hole, which is a *deny*), and only the
card hands out a stencil with more holes (an escalation, which replaces
the one it names while the sheets above still apply). Conditions are
therefore never compared, only stacked, and a deny can never let more
light through.

The stencil, its grammar (the stencil fragment: the null id \_, the temp id
+, and the tags *deny* and *subtree*), the patch rules and the evaluator
belong to cutting-garden and
are explained in full, with the pictures, in *ajour*(7) and
cutting-garden FDR 0028. The names are shared: the arrangement is the
*stencil stack*, the invariant the *stencil rule*, each document a
*stencil*, each hole an *allowance*, and a call that passes *admitted*.

# HOW ONE CALL IS CHECKED

When a tool call arrives (say, *folio read* on a path), the enforcer
walks the chain and answers in this order. Any "no" refuses the call.

- Is the tool present in every stencil on the chain? A tool absent from
  any one of them is forbidden; absence is the default.
- Does any patch say *deny* for this value (this path, this argument)?
- Does every stencil say *allow* for every value the call constrains? A
  value a stencil does not mention is refused by that stencil, not
  admitted; only patches are transparent where they are silent.
- Is the tool's right in the last act's right set, and in every act above
  it?
- Is the chain itself sound: every signature good, nothing expired,
  nothing revoked, no link wider than its parent?

The first three checks are the stencil stack. The last two are the chain
and the rights. piggy's verifier does the last two. The enforcer that
dispatches the call (moxy for its tools, a clown hook for the harness's
own, spinclass for its verbs) does the first three, because only it knows
what the call is.

# WHAT PIGGY CHECKS AND WHAT IT DOES NOT

piggy owns the envelope and the chain. Its verifier checks that every act
is well formed, that its signature verifies under its key, that the chain
reaches a trusted card key, that rights only shrink along software links,
that nothing has expired or been revoked, and that each escalation and
narrowing names the act it changes. A narrow never makes a child invalid;
it cuts the child's rights too. A session may also hand down a *grant*
over a thing (an *object*) it holds a grant over. Its rights over that
object add up across the grants it holds, while their stencils all stack
over the grant it hands down. The verifier returns the verdict together
with every *profile* line and body on the chain, untouched, in order, for
the enforcer.

piggy does not define the right names (the tools do), does not define the
profile document or the espalier node types (clown and cutting-garden
do), does not evaluate a single condition, and does not store or
distribute acts (the consumers do). An act's words carry no authority:
the description line, the body's text, and the *producer* name are shown
to the operator and signed, and ignored by every rule.

# WHAT THE OPERATOR SEES

A card act's whole head is the PIN prompt, every line, in a fixed order.
The askpass may bold *kind*, *subject*, each *right* and *not-after*; it
may not hide, shorten or reorder a line. A head must fit one screen
(4096 bytes hard; about fifteen lines is comfortable). A producer that
needs more names a profile by digest instead of listing everything.

# SEE ALSO

*piggy*(1) (*operator-sign*), *piggy-agent*(1) (the *operator-act@piggy*
extension), RFC 0013 (the act document and chain rules), RFC 0012 (the
signing extension and the prompt), RFC 0011 (markl ids), hyphence RFC
0001 to 0003 (the carrier), *ajour*(7) and cutting-garden FDR 0028 (the
stencil fragment and the evaluator), cutting-garden RFC 0014 (espalier),
*piggy-piv-slots*(7) (slot 9C).
