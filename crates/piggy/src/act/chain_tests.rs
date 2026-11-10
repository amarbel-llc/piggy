//! The chain walk (RFC 0013 §4, §5.2, §5.3) over an in-memory store of acts
//! sealed with fixed software keys. The "card" is an Ed25519 key spelled as
//! a `piggy-piv_sig-v1` key and trusted as the anchor: the walk judges keys
//! by the anchor set, never by the hardware behind them.

use std::collections::BTreeSet;

use ed25519_dalek::Signer;
use piggy_markl::{FormatId, Id, PurposeId};

use super::store::MemoryStore;
use super::verify::{Options, Outcome, Role, Step, Verifier, timestamp};
use super::{Act, parse};
use crate::operator_act::{HashAlgorithm, signed_data};

const AT: &str = "2026-11-10T12:00:00Z";
const LATER: &str = "2026-11-11T00:00:00Z";
const RECORD: &str =
    "piggy-record-digest-v1@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400";

struct Key {
    sk: ed25519_dalek::SigningKey,
}

impl Key {
    fn new(seed: u8) -> Key {
        Key {
            sk: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
        }
    }

    fn spelled(&self, purpose: PurposeId) -> String {
        Id::new(
            Some(purpose),
            FormatId::SshEd25519Pub,
            self.sk.verifying_key().to_bytes().to_vec(),
        )
        .unwrap()
        .to_wire()
    }

    fn card(&self) -> String {
        self.spelled(PurposeId::PiggyPivSigV1)
    }

    fn principal(&self) -> String {
        self.spelled(PurposeId::PiggyPrincipalPubV1)
    }
}

fn card_namespace(kind: &str) -> &'static str {
    match kind {
        "root" | "link" => "piggy-certificate-v1",
        "grant" | "escalation" => "piggy-escalation-v1",
        "approval" => "piggy-approval-v1",
        "revocation" => "piggy-revocation-v1",
        other => panic!("no card namespace for {other}"),
    }
}

/// Seal an act of `kind` with `key`: a card act when `card`, else a software
/// act whose `lines` carry `issuer` and `issuer-record`. `body`, when given,
/// follows the head.
fn seal(key: &Key, card: bool, kind: &str, lines: &[String], body: Option<&str>) -> Act {
    let (signing, namespace, issuer, assurance) = if card {
        (
            key.card(),
            card_namespace(kind),
            "- issuer = operator\n",
            "piggy:hardware",
        )
    } else {
        (key.principal(), "piggy-record-v1", "", "piggy:software")
    };
    let mut doc = format!("---\n- kind = {kind}\n- producer = test:chain-v1\n{issuer}");
    for line in lines {
        doc.push_str(&format!("- {line}\n"));
    }
    doc.push_str(&format!(
        "- issuer-key = {signing}\n- issued-at = 2026-11-10T00:00:00Z\n\
         - assurance = {assurance}\n- key = {signing}\n- namespace = {namespace}\n\
         - hash = sha256\n! piggy-act-v1\n---\n"
    ));
    if let Some(body) = body {
        doc.push('\n');
        doc.push_str(body);
    }

    let act = parse(doc.as_bytes()).unwrap_or_else(|r| panic!("{r}\n{doc}"));
    let data = signed_data(namespace, HashAlgorithm::Sha256, &act.canonical());
    let signature = Id::new(
        Some(PurposeId::PiggyRecordSigV1),
        FormatId::Ed25519Sig,
        key.sk.sign(&data).to_bytes().to_vec(),
    )
    .unwrap();
    act.with_signature(&signature)
}

fn rights(rights: &[&str]) -> Vec<String> {
    rights.iter().map(|r| format!("right = {r}")).collect()
}

/// A world: the card, a store, and helpers that seal acts into it.
struct World {
    card: Key,
    store: MemoryStore,
}

impl World {
    fn new() -> World {
        World {
            card: Key::new(1),
            store: MemoryStore::new(),
        }
    }

    fn add(&mut self, act: Act) -> String {
        self.store.insert(act).expect("sealed")
    }

    fn root(&mut self, subject: &str, key: &Key, r: &[&str], not_after: &str) -> String {
        let mut lines = vec![
            format!("subject = {subject}"),
            format!("subject-key = {}", key.principal()),
            format!("not-after = {not_after}"),
        ];
        lines.extend(rights(r));
        let act = seal(&self.card, true, "root", &lines, None);
        self.add(act)
    }

    /// A software link from `issuer` (holding `issuer_key`, certified by
    /// `record`) to `subject`.
    #[allow(clippy::too_many_arguments)]
    fn link(
        &mut self,
        issuer: &str,
        issuer_key: &Key,
        record: &str,
        subject: &str,
        key: &Key,
        r: &[&str],
        extra: &[String],
    ) -> String {
        let mut lines = vec![
            format!("subject = {subject}"),
            format!("subject-key = {}", key.principal()),
            format!("issuer = {issuer}"),
            format!("issuer-record = {record}"),
        ];
        lines.extend(rights(r));
        lines.extend(extra.iter().cloned());
        let act = seal(issuer_key, false, "link", &lines, None);
        self.add(act)
    }

    fn narrow(
        &mut self,
        subject: &str,
        key: &Key,
        record: &str,
        names: &[&str],
        r: &[&str],
    ) -> String {
        let mut lines = vec![
            format!("subject = {subject}"),
            format!("issuer = {subject}"),
            format!("issuer-record = {record}"),
        ];
        lines.extend(rights(r));
        lines.extend(names.iter().map(|n| format!("names = {n}")));
        let act = seal(key, false, "narrow", &lines, None);
        self.add(act)
    }

    fn escalation(
        &mut self,
        subject: &str,
        names: &[&str],
        r: &[&str],
        extra: &[String],
        body: Option<&str>,
    ) -> String {
        let mut lines = vec![format!("subject = {subject}")];
        lines.extend(rights(r));
        lines.extend(names.iter().map(|n| format!("names = {n}")));
        lines.extend(extra.iter().cloned());
        let act = seal(&self.card, true, "escalation", &lines, body);
        self.add(act)
    }

    fn card_revocation(&mut self, names: &[&str]) -> String {
        let lines: Vec<String> = names.iter().map(|n| format!("names = {n}")).collect();
        let act = seal(&self.card, true, "revocation", &lines, None);
        self.add(act)
    }

    fn software_revocation(
        &mut self,
        issuer: &str,
        key: &Key,
        record: &str,
        names: &[&str],
    ) -> String {
        let mut lines = vec![
            format!("issuer = {issuer}"),
            format!("issuer-record = {record}"),
        ];
        lines.extend(names.iter().map(|n| format!("names = {n}")));
        let act = seal(key, false, "revocation", &lines, None);
        self.add(act)
    }

    fn verifier(&self) -> Verifier<MemoryStore> {
        Verifier::new(
            self.store.clone(),
            Options {
                at: AT.into(),
                anchors: BTreeSet::from([self.card.card()]),
                revocation_source: true,
            },
        )
    }

    fn verify(&self, digest: &str) -> Outcome {
        self.verifier().verify(&self.get(digest))
    }

    fn get(&self, digest: &str) -> Act {
        use super::store::ActStore;
        self.store.get(digest).expect("in the store").act
    }
}

fn valid(outcome: &Outcome) -> &super::verify::Valid {
    match outcome {
        Outcome::Valid(v) => v,
        other => panic!("not valid: {other:?}"),
    }
}

fn failed(outcome: &Outcome) -> (Step, String) {
    match outcome {
        Outcome::Invalid(f) => (f.step, f.act.clone()),
        other => panic!("not invalid: {other:?}"),
    }
}

fn set(r: &[&str]) -> Option<BTreeSet<String>> {
    Some(r.iter().map(|s| s.to_string()).collect())
}

/// A root for `s:a` with key 2, and a link from it to `s:b` with key 3.
fn two_link_world() -> (World, Key, Key, String, String) {
    let mut w = World::new();
    let (ka, kb) = (Key::new(2), Key::new(3));
    let root = w.root("s:a", &ka, &["x:check", "x:merge", "x:close"], LATER);
    let link = w.link("s:a", &ka, &root, "s:b", &kb, &["x:check", "x:merge"], &[]);
    (w, ka, kb, root, link)
}

#[test]
fn a_root_and_a_link_are_valid_with_their_chain() {
    let (w, ka, _kb, root, link) = two_link_world();

    let v = w.verify(&link).clone();
    let v = valid(&v);
    assert_eq!(v.chain, vec![root.clone(), link.clone()]);
    assert_eq!(v.chain_start_key, w.card.card());
    assert_eq!(v.rights, set(&["x:check", "x:merge"]));
    assert_eq!(v.effective_expiry.as_deref(), Some(LATER));
    assert_eq!(v.assurance, "piggy:software");
    let _ = ka;

    let r = w.verify(&root);
    assert_eq!(valid(&r).assurance, "piggy:hardware");
    assert_eq!(valid(&r).chain, vec![root]);
}

// §4.1, §5.2 step 4: the chain edge.

#[test]
fn an_issuer_record_certifying_another_key_or_subject_is_refused() {
    let (mut w, _ka, kb, root, _link) = two_link_world();
    let stranger = Key::new(9);

    // Signed by a key the root does not certify.
    let other_key = w.link("s:a", &stranger, &root, "s:c", &kb, &["x:check"], &[]);
    assert_eq!(failed(&w.verify(&other_key)), (Step::ChainEdge, other_key));

    // Claims an issuer the root does not name.
    let ka = Key::new(2);
    let other_subject = w.link("s:z", &ka, &root, "s:c", &kb, &["x:check"], &[]);
    assert_eq!(
        failed(&w.verify(&other_subject)),
        (Step::ChainEdge, other_subject)
    );
}

#[test]
fn a_card_act_whose_key_is_not_an_anchor_is_refused() {
    let mut w = World::new();
    w.card = Key::new(7);
    let root = w.root("s:a", &Key::new(2), &["x:check"], LATER);
    w.card = Key::new(1);
    assert_eq!(failed(&w.verify(&root)), (Step::ChainEdge, root));
}

#[test]
fn an_unresolvable_issuer_record_is_undetermined() {
    let mut w = World::new();
    let link = w.link(
        "s:a",
        &Key::new(2),
        RECORD,
        "s:b",
        &Key::new(3),
        &["x:check"],
        &[],
    );
    match w.verify(&link) {
        Outcome::Undetermined(u) => assert_eq!(u.digests, vec![RECORD.to_owned()]),
        other => panic!("{other:?}"),
    }
}

#[test]
fn without_a_revocation_source_valid_becomes_undetermined() {
    let (w, .., link) = two_link_world();
    let act = w.get(&link);
    assert!(w.verifier().verify(&act).is_valid());

    let verifier = Verifier::new(
        w.store.clone(),
        Options {
            at: AT.into(),
            anchors: BTreeSet::from([w.card.card()]),
            revocation_source: false,
        },
    );
    match verifier.verify(&act) {
        Outcome::Undetermined(u) => {
            assert!(u.digests.is_empty());
            assert!(u.reason.contains("revocation source"), "{}", u.reason);
        }
        other => panic!("{other:?}"),
    }
}

// §4.2: rights never widen without the card.

#[test]
fn a_software_link_with_a_right_its_issuer_lacks_is_refused() {
    let (mut w, ka, kb, root, _) = two_link_world();
    let wide = w.link("s:a", &ka, &root, "s:c", &kb, &["x:deploy"], &[]);
    assert_eq!(failed(&w.verify(&wide)), (Step::KindRule, wide));
}

#[test]
fn a_narrow_signed_by_another_key_is_refused() {
    let (mut w, _ka, kb, root, link) = two_link_world();
    // s:b, certified by the link, narrows the root, which is s:a's.
    let not_its_own = w.narrow("s:b", &kb, &link, &[&root], &["x:check"]);
    assert_eq!(
        failed(&w.verify(&not_its_own)),
        (Step::Annotations, not_its_own)
    );
    // And the root is untouched by it.
    assert_eq!(
        valid(&w.verify(&root)).rights,
        set(&["x:check", "x:close", "x:merge"])
    );
}

// §4.3: effective rights.

#[test]
fn an_escalation_replaces_and_a_narrow_intersects() {
    let (mut w, _ka, kb, _root, link) = two_link_world();

    let esc = w.escalation(
        "s:b",
        &[&link],
        &["x:check", "x:merge", "x:deploy"],
        &[],
        None,
    );
    assert_eq!(
        valid(&w.verify(&link)).rights,
        set(&["x:check", "x:deploy", "x:merge"])
    );

    // A narrow cuts the escalated set whatever the issue order.
    w.narrow("s:b", &kb, &link, &[&link], &["x:check", "x:deploy"]);
    assert_eq!(
        valid(&w.verify(&link)).rights,
        set(&["x:check", "x:deploy"])
    );
    let _ = esc;
}

#[test]
fn an_escalation_naming_the_narrow_lifts_it() {
    let (mut w, _ka, kb, _root, link) = two_link_world();
    let narrow = w.narrow("s:b", &kb, &link, &[&link], &["x:check"]);
    assert_eq!(valid(&w.verify(&link)).rights, set(&["x:check"]));

    // An escalation that does not name the narrow leaves it cutting.
    let first = w.escalation("s:b", &[&link], &["x:check", "x:merge"], &[], None);
    assert_eq!(valid(&w.verify(&link)).rights, set(&["x:check"]));

    // One that names it (and supersedes the first) lifts it.
    w.escalation(
        "s:b",
        &[&link, &narrow, &first],
        &["x:check", "x:merge"],
        &[],
        None,
    );
    assert_eq!(valid(&w.verify(&link)).rights, set(&["x:check", "x:merge"]));
}

#[test]
fn two_unsuperseded_escalations_make_the_act_invalid() {
    let (mut w, _ka, _kb, _root, link) = two_link_world();
    w.escalation("s:b", &[&link], &["x:check"], &[], None);
    w.escalation("s:b", &[&link], &["x:merge"], &[], None);
    assert_eq!(failed(&w.verify(&link)), (Step::Annotations, link));
}

#[test]
fn a_parents_narrow_intersects_a_wider_child_and_does_not_refuse_it() {
    let (mut w, ka, kb, root, link) = two_link_world();
    w.narrow("s:a", &ka, &root, &[&root], &["x:check"]);
    let v = w.verify(&link);
    assert_eq!(valid(&v).rights, set(&["x:check"]));

    // A grandchild issued wider than the narrowed set intersects too.
    let kc = Key::new(4);
    let grandchild = w.link("s:b", &kb, &link, "s:c", &kc, &["x:merge"], &[]);
    assert_eq!(valid(&w.verify(&grandchild)).rights, set(&[]));
}

// §4.1, §5.2 step 6: names and records.

#[test]
fn an_escalation_with_an_unresolvable_or_mismatched_names_entry() {
    let (mut w, _ka, _kb, root, link) = two_link_world();

    let unresolved = w.escalation("s:b", &[&link, RECORD], &["x:check"], &[], None);
    match w.verify(&unresolved) {
        Outcome::Undetermined(u) => assert_eq!(u.digests, vec![RECORD.to_owned()]),
        other => panic!("{other:?}"),
    }

    let other_subject = w.escalation("s:b", &[&root], &["x:check"], &[], None);
    assert_eq!(
        failed(&w.verify(&other_subject)),
        (Step::Annotations, other_subject)
    );
}

#[test]
fn records_are_never_resolved() {
    let mut w = World::new();
    let mut lines = vec![
        "subject = s:a".to_owned(),
        format!("subject-key = {}", Key::new(2).principal()),
        format!("not-after = {LATER}"),
        format!("records = {RECORD}"),
    ];
    lines.extend(rights(&["x:check"]));
    let act = seal(&w.card, true, "root", &lines, None);
    let root = w.add(act);
    assert!(w.verify(&root).is_valid());
}

// §4.5: effective expiry.

#[test]
fn a_child_of_an_expired_root_is_invalid_and_a_child_inherits_the_roots_expiry() {
    let mut w = World::new();
    let (ka, kb) = (Key::new(2), Key::new(3));
    let root = w.root("s:a", &ka, &["x:check"], "2026-11-10T13:00:00Z");
    let link = w.link("s:a", &ka, &root, "s:b", &kb, &["x:check"], &[]);
    assert_eq!(
        valid(&w.verify(&link)).effective_expiry.as_deref(),
        Some("2026-11-10T13:00:00Z")
    );

    let mut verifier = w.verifier();
    verifier.set_at("2026-11-10T13:00:00Z".into());
    assert_eq!(
        failed(&verifier.verify(&w.get(&link))),
        (Step::Annotations, root.clone())
    );

    let shorter = w.link(
        "s:a",
        &ka,
        &root,
        "s:c",
        &kb,
        &["x:check"],
        &["not-after = 2026-11-10T12:30:00Z".into()],
    );
    assert_eq!(
        valid(&w.verify(&shorter)).effective_expiry.as_deref(),
        Some("2026-11-10T12:30:00Z")
    );
}

#[test]
fn not_before_is_honoured() {
    let (mut w, ka, kb, root, _) = two_link_world();
    let early = w.link(
        "s:a",
        &ka,
        &root,
        "s:c",
        &kb,
        &["x:check"],
        &["not-before = 2026-11-10T18:00:00Z".into()],
    );
    assert_eq!(failed(&w.verify(&early)), (Step::Annotations, early));
}

// §4.6: revocation.

#[test]
fn an_act_below_a_revoked_link_is_invalid() {
    let (mut w, _ka, kb, _root, link) = two_link_world();
    let kc = Key::new(4);
    let below = w.link("s:b", &kb, &link, "s:c", &kc, &["x:check"], &[]);
    assert!(w.verify(&below).is_valid());

    w.card_revocation(&[&link]);
    assert_eq!(failed(&w.verify(&below)), (Step::Annotations, link));
}

#[test]
fn a_software_revocation_by_the_parents_key_is_accepted_and_by_a_stranger_refused() {
    let (mut w, ka, kb, root, link) = two_link_world();
    let kc = Key::new(4);
    let below = w.link("s:b", &kb, &link, "s:c", &kc, &["x:check"], &[]);

    // s:c's own key, certified by `below`, is neither the signer of `link`
    // nor an ancestor key on its chain.
    let stranger = w.software_revocation("s:c", &kc, &below, &[&link]);
    assert_eq!(failed(&w.verify(&stranger)), (Step::KindRule, stranger));
    assert!(w.verify(&below).is_valid());

    // s:a's key signed `link` (and is the ancestor key of `below`).
    let by_parent = w.software_revocation("s:a", &ka, &root, &[&below]);
    assert!(w.verify(&by_parent).is_valid());
    assert_eq!(failed(&w.verify(&below)), (Step::Annotations, below));
}

#[test]
fn an_ancestor_key_further_up_may_revoke() {
    let (mut w, ka, kb, root, link) = two_link_world();
    let kc = Key::new(4);
    let below = w.link("s:b", &kb, &link, "s:c", &kc, &["x:check"], &[]);
    let kd = Key::new(5);
    let lowest = w.link("s:c", &kc, &below, "s:d", &kd, &["x:check"], &[]);

    // ka did not sign `lowest`; it is the subject-key of the root, on
    // `lowest`'s issuer-record path.
    w.software_revocation("s:a", &ka, &root, &[&lowest]);
    assert_eq!(failed(&w.verify(&lowest)), (Step::Annotations, lowest));
}

#[test]
fn a_revocation_naming_a_revocation_is_refused() {
    let (mut w, _ka, _kb, _root, link) = two_link_world();
    let first = w.card_revocation(&[&link]);
    let second = w.card_revocation(&[&first]);
    assert_eq!(failed(&w.verify(&second)), (Step::Annotations, second));
    // The first still revokes.
    assert_eq!(failed(&w.verify(&link)), (Step::Annotations, link));
}

// §4.9, §5.3: layers.

#[test]
fn layers_are_returned_in_chain_order_marked_stencil_or_patch() {
    let mut w = World::new();
    let (ka, kb) = (Key::new(2), Key::new(3));
    let p1 = "base@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400";
    let p2 = "child@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400";

    let mut lines = vec![
        "subject = s:a".to_owned(),
        format!("subject-key = {}", ka.principal()),
        format!("not-after = {LATER}"),
        format!("profile = {p1}"),
    ];
    lines.extend(rights(&["x:check"]));
    let root = seal(&w.card, true, "root", &lines, None);
    let root = w.add(root);

    let body = "[x !y-v1 deny]\n";
    let mut lines = vec![
        "subject = s:b".to_owned(),
        format!("subject-key = {}", kb.principal()),
        "issuer = s:a".to_owned(),
        format!("issuer-record = {root}"),
        format!("profile = {p2}"),
    ];
    lines.extend(rights(&["x:check"]));
    let link = seal(&ka, false, "link", &lines, Some(body));
    let link = w.add(link);

    let v = w.verify(&link);
    let layers: Vec<_> = valid(&v)
        .layers
        .iter()
        .map(|l| (l.act.clone(), l.role, l.content.clone()))
        .collect();
    assert_eq!(
        layers,
        vec![
            (root.clone(), Role::Stencil, p1.to_owned()),
            (link.clone(), Role::Stencil, p2.to_owned()),
            (link.clone(), Role::Patch, body.to_owned()),
        ]
    );

    // An escalation carrying only a profile replaces the link's profile and
    // leaves its deny patch in place.
    let p3 = "wider@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400";
    let esc = w.escalation(
        "s:b",
        &[&link],
        &["x:check"],
        &[format!("profile = {p3}")],
        None,
    );
    let v = w.verify(&link);
    let layers: Vec<_> = valid(&v)
        .layers
        .iter()
        .map(|l| (l.act.clone(), l.role, l.content.clone()))
        .collect();
    assert_eq!(
        layers,
        vec![
            (root, Role::Stencil, p1.to_owned()),
            (esc, Role::Stencil, p3.to_owned()),
            (link, Role::Patch, body.to_owned()),
        ]
    );
}

// §5.2 step 5 for grants: grants hand down over their object.

#[test]
fn a_software_grant_hands_down_from_a_card_grant_over_the_same_object() {
    let mut w = World::new();
    let ka = Key::new(2);
    let root = w.root("s:a", &ka, &["x:check"], LATER);
    let profile = "manager@blake2b256-qqqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0s6vk400";

    let mut lines = vec![
        "subject = s:a".to_owned(),
        "object = x:profiles".to_owned(),
        format!("profile = {profile}"),
    ];
    lines.extend(rights(&["x:profile:dev", "x:profile:ops"]));
    let card_grant = seal(&w.card, true, "grant", &lines, None);
    let card_grant = w.add(card_grant);

    let soft = |w: &mut World, r: &[&str], object: &str| {
        let mut lines = vec![
            "subject = s:b".to_owned(),
            format!("object = {object}"),
            "issuer = s:a".to_owned(),
            format!("issuer-record = {root}"),
        ];
        lines.extend(rights(r));
        let act = seal(&ka, false, "grant", &lines, None);
        w.add(act)
    };

    let ok = soft(&mut w, &["x:profile:dev"], "x:profiles");
    let v = w.verify(&ok);
    assert_eq!(valid(&v).rights, set(&["x:profile:dev"]));
    assert_eq!(valid(&v).object.as_deref(), Some("x:profiles"));
    // The card grant's stencil stacks over the grant handed down from it.
    assert!(
        valid(&v)
            .layers
            .iter()
            .any(|l| l.act == card_grant && l.role == Role::Stencil),
        "{:?}",
        valid(&v).layers
    );

    let too_wide = soft(&mut w, &["x:profile:root"], "x:profiles");
    assert_eq!(failed(&w.verify(&too_wide)), (Step::KindRule, too_wide));

    let other_object = soft(&mut w, &["x:profile:dev"], "x:elsewhere");
    assert_eq!(
        failed(&w.verify(&other_object)),
        (Step::KindRule, other_object)
    );
}

// §5.2's last paragraph: memoization.

#[test]
fn a_memoized_answer_is_dropped_when_a_revocation_naming_its_chain_is_learned() {
    let (w, _ka, _kb, root, link) = two_link_world();
    let mut verifier = w.verifier();
    let act = w.get(&link);
    assert!(verifier.verify(&act).is_valid());

    let revocation = seal(
        &w.card,
        true,
        "revocation",
        &[format!("names = {root}")],
        None,
    );
    verifier.store_mut().insert(revocation.clone());
    // Before it is told, the memo answers.
    assert!(verifier.verify(&act).is_valid());
    verifier.learned(&revocation);
    assert!(!verifier.verify(&act).is_valid());
}

#[test]
fn a_memoized_answer_expires_with_the_act() {
    let (w, .., link) = two_link_world();
    let mut verifier = w.verifier();
    let act = w.get(&link);
    assert!(verifier.verify(&act).is_valid());
    verifier.set_at(LATER.into());
    assert!(!verifier.verify(&act).is_valid());
}

#[test]
fn the_depth_cap_bounds_the_walk() {
    let mut w = World::new();
    let keys: Vec<Key> = (2..40).map(Key::new).collect();
    let mut record = w.root("s:0", &keys[0], &["x:check"], LATER);
    for i in 1..keys.len() {
        record = w.link(
            &format!("s:{}", i - 1),
            &keys[i - 1],
            &record,
            &format!("s:{i}"),
            &keys[i],
            &["x:check"],
            &[],
        );
    }
    assert_eq!(failed(&w.verify(&record)).0, Step::ChainEdge);
}

/// §3.5: verifiers accept a `names` or `issuer-record` entry under sha256.
#[test]
fn a_sha256_act_digest_resolves_like_a_blake2b256_one() {
    use super::seal::{DigestFormat, act_digest};
    let (mut w, _ka, _kb, _root, link) = two_link_world();
    let by_sha = act_digest(&w.get(&link), DigestFormat::Sha256).unwrap();
    w.card_revocation(&[&by_sha]);
    assert_eq!(failed(&w.verify(&link)), (Step::Annotations, link));

    let json = format!(
        "{{\"acts\": [{}]}}",
        serde_json::to_string(
            &String::from_utf8(w.get(&by_sha).sealed_canonical().unwrap()).unwrap()
        )
        .unwrap()
    );
    let store = MemoryStore::from_json(json.as_bytes()).unwrap();
    assert_eq!(store.len(), 1);
}

#[test]
fn timestamps_are_spelled_as_section_2_spells_them() {
    assert_eq!(timestamp(0), "1970-01-01T00:00:00Z");
    assert_eq!(timestamp(1_709_164_800), "2024-02-29T00:00:00Z");
    assert_eq!(timestamp(1_762_776_000), "2025-11-10T12:00:00Z");
}
