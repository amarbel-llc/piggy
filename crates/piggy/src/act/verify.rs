//! The chain walk (RFC 0013 §4, §5.2 steps 2 to 7, §5.3): given an act, a
//! time and a store, answer valid, invalid or undetermined.
//!
//! Step 1 is [`super::parse`]; every act in a store passed it on the way in.
//! The walk recurses through `issuer-record` (step 4) and, for every act it
//! evaluates, through the escalations, narrows and revocations the store
//! holds naming it (step 6). It never evaluates a condition: the `profile`
//! edges and bodies it meets are returned as layers, as given (§4.9).
//!
//! Rights are compared as sets of their parsed values (§4.2). Two sets are
//! kept per certifying act: the *certified* rights (§4.3 steps 1 to 3: the
//! chain and its escalations, no narrow anywhere), which bound what a
//! software link or grant may hand down, and the *effective* rights (steps 1
//! to 4), which are what the act may use. A narrow cuts downwards and never
//! refuses a child.
//!
//! Cycles: a narrow or revocation whose `issuer-record` chain passes back
//! through an act still being evaluated is taken as valid for that inner
//! check once its own steps 2, 3 and §4.5 hold; both kinds only remove. Any
//! other cycle answers undetermined.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};

use super::seal::verify_seal;
use super::store::{ActStore, StoredAct};
use super::{Act, Refusal, parsed_bytes};

/// The chain depth cap (RFC 0013 Tuning Levers).
pub const DEPTH_CAP: usize = 32;

/// The step of RFC 0013 §5.2 that refused an act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    Parse,
    Seal,
    Rules,
    ChainEdge,
    KindRule,
    Annotations,
}

impl Step {
    pub fn as_str(self) -> &'static str {
        match self {
            Step::Parse => "5.2.1",
            Step::Seal => "5.2.2",
            Step::Rules => "5.2.3",
            Step::ChainEdge => "5.2.4",
            Step::KindRule => "5.2.5",
            Step::Annotations => "5.2.6",
        }
    }
}

/// What the caller supplies besides the store (§5.1, §5.2).
#[derive(Debug, Clone)]
pub struct Options {
    /// The time T, spelled as §2's timestamps are; equal spellings order as
    /// instants do.
    pub at: String,
    /// The trust anchors: card keys spelled as an act's `key` field is.
    pub anchors: BTreeSet<String>,
    /// The caller asserts the store holds every revocation there is. Without
    /// it no answer is better than undetermined (§4.6, §5.3).
    pub revocation_source: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// A `profile` edge: admits only what it names.
    Stencil,
    /// A body: transparent where silent, every leaf a `deny`.
    Patch,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Stencil => "stencil",
            Role::Patch => "patch",
        }
    }
}

/// One layer (§4.9), as given: a `profile` edge or a body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layer {
    pub act: String,
    pub kind: String,
    pub role: Role,
    /// The `profile` edge (`<name>@<digest>`) or the body bytes as text.
    pub content: String,
}

/// A valid answer (§5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Valid {
    pub act: String,
    pub kind: String,
    pub subject: Option<String>,
    pub object: Option<String>,
    /// `None`: a card annotating act with no `not-after` (§4.5).
    pub effective_expiry: Option<String>,
    pub assurance: String,
    pub chain_start_key: String,
    /// From the chain start down to this act.
    pub chain: Vec<String>,
    /// The effective rights, for a certifying act or a grant.
    pub rights: Option<BTreeSet<String>>,
    /// §4.3 steps 1 to 3 only, for a certifying act or a grant.
    certified: Option<BTreeSet<String>>,
    /// For a certifying act or a grant; empty otherwise.
    pub layers: Vec<Layer>,
    /// This act's consumer fields, each as a set.
    pub prefixed: BTreeMap<String, Vec<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub step: Step,
    /// The act that failed: the one asked about or one it rests on.
    pub act: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unresolved {
    /// The digests that could not be resolved; empty when what is missing
    /// is a revocation source.
    pub digests: Vec<String>,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    Valid(Valid),
    Invalid(Failure),
    Undetermined(Unresolved),
}

impl Outcome {
    pub fn is_valid(&self) -> bool {
        matches!(self, Outcome::Valid(_))
    }
}

fn invalid(step: Step, act: &StoredAct, reason: impl Into<String>) -> Outcome {
    Outcome::Invalid(Failure {
        step,
        act: act.digest.clone(),
        reason: reason.into(),
    })
}

fn refused(step: Step, act: &StoredAct, refusal: Refusal) -> Outcome {
    invalid(step, act, refusal.to_string())
}

fn undetermined(digests: Vec<String>, reason: impl Into<String>) -> Outcome {
    Outcome::Undetermined(Unresolved {
        digests,
        reason: reason.into(),
    })
}

fn spelled(act: &Act, name: &str) -> Option<String> {
    act.field(name).map(parsed_bytes)
}

fn rights(act: &Act) -> BTreeSet<String> {
    act.values("right").map(parsed_bytes).collect()
}

fn is_certifying(act: &Act) -> bool {
    matches!(act.kind(), "root" | "link")
}

fn carries_rights(act: &Act) -> bool {
    matches!(act.kind(), "root" | "link" | "grant")
}

/// The act's own layers: its `profile` edge, then its body.
fn own_layers(act: &StoredAct) -> (Option<Layer>, Option<Layer>) {
    let layer = |role, content| Layer {
        act: act.digest.clone(),
        kind: act.act.kind().to_owned(),
        role,
        content,
    };
    (
        spelled(&act.act, "profile").map(|p| layer(Role::Stencil, p)),
        act.act
            .body()
            .map(|b| layer(Role::Patch, String::from_utf8_lossy(b).into_owned())),
    )
}

/// The structural facts of an act's chain, which no annotation changes: the
/// path from the chain start, the start's key, the effective expiry (§4.5).
struct Lineage {
    chain: Vec<String>,
    start_key: String,
    expiry: Option<String>,
    /// The `subject-key` of every certifying act above this one (§4.6).
    ancestor_keys: BTreeSet<String>,
}

fn earliest(a: Option<String>, b: Option<String>) -> Option<String> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

/// The chain verifier over a store (§5.4), memoizing valid answers (§5.2's
/// last paragraph).
pub struct Verifier<S> {
    store: S,
    options: Options,
    /// Valid top-level answers by act digest, with the time they were given.
    memo: RefCell<HashMap<String, (String, Valid)>>,
}

impl<S: ActStore> Verifier<S> {
    pub fn new(store: S, options: Options) -> Verifier<S> {
        Verifier {
            store,
            options,
            memo: RefCell::new(HashMap::new()),
        }
    }

    pub fn store(&self) -> &S {
        &self.store
    }

    /// The store, to add acts to; tell [`Verifier::learned`] about each.
    pub fn store_mut(&mut self) -> &mut S {
        &mut self.store
    }

    pub fn set_at(&mut self, at: String) {
        self.options.at = at;
    }

    /// Forget the memoized answers an act just added to the store can
    /// change: an escalation, narrow or revocation naming an act on their
    /// chain, or any grant (it may add a layer to a grant handed down over
    /// its object, §5.2 step 5).
    pub fn learned(&mut self, act: &Act) {
        let kind = act.kind();
        let names: Vec<String> = act.values("names").map(parsed_bytes).collect();
        let memo = self.memo.get_mut();
        match kind {
            "grant" => memo.clear(),
            "escalation" | "narrow" | "revocation" => memo.retain(|_, (_, valid)| {
                !valid.chain.iter().any(|on_chain| {
                    names.iter().any(|name| {
                        name == on_chain
                            || self
                                .store
                                .get(on_chain)
                                .is_some_and(|stored| stored.is_named_by(name))
                    })
                })
            }),
            _ => {}
        }
    }

    /// Verify an act at the options' time (§5.2).
    pub fn verify(&self, act: &Act) -> Outcome {
        let Some(stored) = StoredAct::new(act.clone()) else {
            return Outcome::Invalid(Failure {
                step: Step::Seal,
                act: String::new(),
                reason: "missing-field: the act is not sealed; `signature` is absent".into(),
            });
        };

        let outcome = match self.memoized(&stored.digest) {
            Some(valid) => Outcome::Valid(valid),
            None => {
                let outcome = self.eval(&stored, &mut Vec::new());
                if let Outcome::Valid(valid) = &outcome {
                    self.memo.borrow_mut().insert(
                        stored.digest.clone(),
                        (self.options.at.clone(), valid.clone()),
                    );
                }
                outcome
            }
        };

        match outcome {
            Outcome::Valid(_) if !self.options.revocation_source => undetermined(
                Vec::new(),
                "no revocation source: the store is not asserted to hold every revocation",
            ),
            other => other,
        }
    }

    fn memoized(&self, digest: &str) -> Option<Valid> {
        let memo = self.memo.borrow();
        let (since, valid) = memo.get(digest)?;
        let at = &self.options.at;
        let unexpired = valid.effective_expiry.as_ref().is_none_or(|e| at < e);
        (since <= at && unexpired).then(|| valid.clone())
    }

    fn eval(&self, x: &StoredAct, stack: &mut Vec<String>) -> Outcome {
        if stack.len() >= DEPTH_CAP {
            return invalid(
                Step::ChainEdge,
                x,
                format!("the chain is deeper than {DEPTH_CAP}"),
            );
        }
        stack.push(x.digest.clone());
        let outcome = self.eval_act(x, stack);
        stack.pop();
        outcome
    }

    fn eval_act(&self, x: &StoredAct, stack: &mut Vec<String>) -> Outcome {
        let a = &x.act;
        let kind = a.kind();

        // Step 2.
        if let Err(r) = verify_seal(a) {
            return refused(Step::Seal, x, r);
        }
        // Step 3.
        if let Err(r) = a.check_issuer_binding() {
            return refused(Step::Rules, x, r);
        }
        if let Err(r) = a.check_namespace_pairing() {
            return refused(Step::Rules, x, r);
        }

        // Step 4: the chain edge.
        let lineage = match self.lineage(x) {
            Ok(lineage) => lineage,
            Err(outcome) => return outcome,
        };
        let parent = if a.is_card_act() {
            if !self.is_anchor(a) {
                return invalid(
                    Step::ChainEdge,
                    x,
                    "a card act whose `key` is not a trust anchor",
                );
            }
            None
        } else {
            let p = self
                .store
                .get(&spelled(a, "issuer-record").unwrap_or_default())
                .expect("lineage resolved issuer-record");
            if !is_certifying(&p.act) {
                return invalid(
                    Step::ChainEdge,
                    x,
                    format!(
                        "`issuer-record` names a {}, not a certifying act",
                        p.act.kind()
                    ),
                );
            }
            if spelled(&p.act, "subject-key") != spelled(a, "key") {
                return invalid(
                    Step::ChainEdge,
                    x,
                    "`issuer-record` certifies another key than `key`",
                );
            }
            if p.act.text("subject") != a.text("issuer") {
                return invalid(
                    Step::ChainEdge,
                    x,
                    "`issuer-record` certifies another subject than `issuer`",
                );
            }
            if stack.contains(&p.digest) {
                if matches!(kind, "narrow" | "revocation") {
                    // Taken as valid for this inner check; P is being
                    // evaluated further up and its answer decides.
                    Some(None)
                } else {
                    return undetermined(
                        vec![p.digest.clone()],
                        format!("a cycle through {}", p.digest),
                    );
                }
            } else {
                match self.eval(&p, stack) {
                    Outcome::Valid(v) => Some(Some(v)),
                    other => return other,
                }
            }
        };
        let parent: Option<&Valid> = parent.as_ref().and_then(Option::as_ref);

        let mut pending: Vec<String> = Vec::new();
        let mut layers: Vec<Layer> = parent.map(|p| p.layers.clone()).unwrap_or_default();

        // Step 5: the kind's rule against P (§4.1, §4.2). A card act is
        // bounded by no P.
        if let Some(p) = parent {
            let certified = p.certified.as_ref().expect("a certifying parent");
            match kind {
                "link" => {
                    if let Some(excess) = rights(a).difference(certified).next() {
                        return invalid(
                            Step::KindRule,
                            x,
                            format!("right {excess} exceeds the issuer's certified rights"),
                        );
                    }
                }
                "grant" => match self.grant_bound(x, certified, stack) {
                    Ok(held) => layers.extend(held),
                    Err(outcome) => return outcome,
                },
                _ => {}
            }
        }

        // Step 6: names.
        let mut named = Vec::new();
        let mut missing = Vec::new();
        for name in a.values("names").map(parsed_bytes) {
            match self.store.get(&name) {
                Some(n) => named.push(n),
                None => missing.push(name),
            }
        }
        if !missing.is_empty() {
            return undetermined(missing, "a `names` entry is not in the store");
        }
        if let Some(outcome) = self.check_names(x, &named) {
            return outcome;
        }

        // Step 6: time (§4.5).
        let at = &self.options.at;
        if let Some(not_before) = a.text("not-before") {
            if not_before > at.as_str() {
                return invalid(
                    Step::Annotations,
                    x,
                    format!("not valid before {not_before}"),
                );
            }
        }
        if let Some(expiry) = &lineage.expiry {
            if expiry <= at {
                return invalid(Step::Annotations, x, format!("expired at {expiry}"));
            }
        }

        // Step 6: revocation (§4.6).
        let naming = self.store.naming(x);
        for r in naming.iter().filter(|r| r.act.kind() == "revocation") {
            match self.eval_annotation(r, stack) {
                Outcome::Valid(_) => {
                    return invalid(Step::Annotations, x, format!("revoked by {}", r.digest));
                }
                Outcome::Undetermined(u) => pending.extend(u.digests),
                Outcome::Invalid(_) => {}
            }
        }

        // Step 6: effective rights (§4.3) and layers (§4.9).
        let (certified, effective) = if carries_rights(a) {
            let own = rights(a);
            let (mut certified, mut effective) = match parent {
                Some(p) if kind == "link" => (
                    own.clone(),
                    own.intersection(p.rights.as_ref().expect("a certifying parent"))
                        .cloned()
                        .collect(),
                ),
                _ => (own.clone(), own),
            };

            let escalations = self.valid_annotations(&naming, "escalation", stack, &mut pending);
            let unsuperseded: Vec<&StoredAct> = escalations
                .iter()
                .filter(|e| !escalations.iter().any(|other| other.names(e)))
                .collect();
            if unsuperseded.len() > 1 {
                let digests: Vec<&str> = unsuperseded.iter().map(|e| e.digest.as_str()).collect();
                return invalid(
                    Step::Annotations,
                    x,
                    format!("conflicting escalations: {}", digests.join(", ")),
                );
            }
            let applied = unsuperseded.first().copied();

            let (mut profile, mut body) = own_layers(x);
            if let Some(e) = applied {
                certified = rights(&e.act);
                effective = certified.clone();
                // Each layer kind the escalation carries replaces the act's
                // own of that kind; a kind it does not carry stays.
                let (e_profile, e_body) = own_layers(e);
                profile = e_profile.or(profile);
                body = e_body.or(body);
            }
            layers.extend(profile);
            layers.extend(body);

            let mut narrows = self.valid_annotations(&naming, "narrow", stack, &mut pending);
            narrows.retain(|n| !applied.is_some_and(|e| e.names(n)));
            narrows.sort_by(|m, n| m.digest.cmp(&n.digest));
            for n in &narrows {
                let cut = rights(&n.act);
                effective.retain(|r| cut.contains(r));
                let (profile, body) = own_layers(n);
                layers.extend(profile);
                layers.extend(body);
            }

            (Some(certified), Some(effective))
        } else {
            layers.clear();
            (None, None)
        };

        if !pending.is_empty() {
            pending.sort();
            pending.dedup();
            return undetermined(pending, "an act naming this chain could not be evaluated");
        }

        // Step 7.
        Outcome::Valid(Valid {
            act: x.digest.clone(),
            kind: kind.to_owned(),
            subject: a.text("subject").map(str::to_owned),
            object: carries_rights(a).then(|| spelled(a, "object")).flatten(),
            effective_expiry: lineage.expiry,
            assurance: a.text("assurance").unwrap_or_default().to_owned(),
            chain_start_key: lineage.start_key,
            chain: lineage.chain,
            rights: effective,
            certified,
            layers,
            prefixed: a.prefixed_fields(),
        })
    }

    /// §5.1: the act's `key` is one the verifier trusts as a root signer.
    fn is_anchor(&self, act: &Act) -> bool {
        spelled(act, "key").is_some_and(|k| self.options.anchors.contains(&k))
    }

    /// The chain path, start key, effective expiry and ancestor keys,
    /// resolving `issuer-record` without judging validity.
    fn lineage(&self, x: &StoredAct) -> Result<Lineage, Outcome> {
        let mut path = vec![x.clone()];
        while !path.last().unwrap().act.is_card_act() {
            if path.len() > DEPTH_CAP {
                return Err(invalid(
                    Step::ChainEdge,
                    x,
                    format!("the chain is deeper than {DEPTH_CAP}"),
                ));
            }
            let record = spelled(&path.last().unwrap().act, "issuer-record").unwrap_or_default();
            match self.store.get(&record) {
                Some(p) => path.push(p),
                None => {
                    return Err(undetermined(
                        vec![record],
                        "an `issuer-record` is not in the store",
                    ));
                }
            }
        }

        let start = path.last().unwrap();
        let mut expiry = start.act.text("not-after").map(str::to_owned);
        for step in path.iter().rev().skip(1) {
            expiry = earliest(expiry, step.act.text("not-after").map(str::to_owned));
        }
        Ok(Lineage {
            chain: path.iter().rev().map(|p| p.digest.clone()).collect(),
            start_key: spelled(&start.act, "key").unwrap_or_default(),
            expiry,
            ancestor_keys: path
                .iter()
                .skip(1)
                .filter(|p| is_certifying(&p.act))
                .filter_map(|p| spelled(&p.act, "subject-key"))
                .collect(),
        })
    }

    /// §4.1's rules on what an act names (§5.2 step 6), and a software
    /// revocation's signer (§4.6, the kind's rule of step 5).
    fn check_names(&self, x: &StoredAct, named: &[StoredAct]) -> Option<Outcome> {
        let a = &x.act;
        let same_subject = |n: &StoredAct| n.act.text("subject") == a.text("subject");

        match a.kind() {
            "narrow" => {
                for n in named {
                    if !carries_rights(&n.act) || !same_subject(n) {
                        return Some(invalid(
                            Step::Annotations,
                            x,
                            format!(
                                "a narrow names {}, which is not a certifying act or grant of its subject",
                                n.digest
                            ),
                        ));
                    }
                }
            }
            "escalation" => {
                let primary: Vec<&StoredAct> =
                    named.iter().filter(|n| carries_rights(&n.act)).collect();
                let [primary] = primary.as_slice() else {
                    return Some(invalid(
                        Step::Annotations,
                        x,
                        format!(
                            "an escalation names {} certifying acts or grants; it names one",
                            primary.len()
                        ),
                    ));
                };
                if !same_subject(primary) {
                    return Some(invalid(
                        Step::Annotations,
                        x,
                        format!("the escalation's subject is not {}'s", primary.digest),
                    ));
                }
                for n in named.iter().filter(|n| !carries_rights(&n.act)) {
                    let on_it = matches!(n.act.kind(), "escalation" | "narrow") && n.names(primary);
                    if !on_it {
                        return Some(invalid(
                            Step::Annotations,
                            x,
                            format!(
                                "an escalation names {}, which is not an escalation or narrow on {}",
                                n.digest, primary.digest
                            ),
                        ));
                    }
                }
            }
            "revocation" => {
                if let Some(n) = named.iter().find(|n| n.act.kind() == "revocation") {
                    return Some(invalid(
                        Step::Annotations,
                        x,
                        format!("revocations are final: {} is a revocation", n.digest),
                    ));
                }
                if !a.is_card_act() {
                    let key = spelled(a, "key");
                    for n in named {
                        let ancestors = match self.lineage(n) {
                            Ok(l) => l.ancestor_keys,
                            Err(outcome) => return Some(outcome),
                        };
                        let signer = spelled(&n.act, "key") == key;
                        let ancestor = key.as_ref().is_some_and(|k| ancestors.contains(k));
                        if !signer && !ancestor {
                            return Some(invalid(
                                Step::KindRule,
                                x,
                                format!(
                                    "a software revocation of {} by a key that neither signed it nor is an ancestor key on its chain",
                                    n.digest
                                ),
                            ));
                        }
                    }
                }
            }
            _ => {}
        }
        None
    }

    /// §5.2 step 5 for a software grant: its rights within the issuer's
    /// certified rights plus the effective rights of every valid grant the
    /// issuer holds over the same `object`. Returns those grants' layers,
    /// which stack over the grant handed down from them.
    fn grant_bound(
        &self,
        x: &StoredAct,
        certified: &BTreeSet<String>,
        stack: &mut Vec<String>,
    ) -> Result<Vec<Layer>, Outcome> {
        let a = &x.act;
        let issuer = a.text("issuer").unwrap_or_default();
        let object = spelled(a, "object").unwrap_or_default();

        let mut bound = certified.clone();
        let mut layers = Vec::new();
        let mut pending = Vec::new();
        for g in self.store.grants(issuer, &object) {
            // A grant being evaluated further up (grants handed round in a
            // circle) is not counted: leaving it out can only shrink.
            if stack.contains(&g.digest) {
                continue;
            }
            match self.eval(&g, stack) {
                Outcome::Valid(v) => {
                    bound.extend(v.rights.clone().unwrap_or_default());
                    layers.extend(v.layers);
                }
                Outcome::Undetermined(u) => pending.extend(u.digests),
                Outcome::Invalid(_) => {}
            }
        }

        match rights(a).difference(&bound).next() {
            None => Ok(layers),
            Some(_) if !pending.is_empty() => Err(undetermined(
                pending,
                "a grant the issuer holds over this object could not be evaluated",
            )),
            Some(excess) => Err(invalid(
                Step::KindRule,
                x,
                format!("right {excess} exceeds the issuer's rights over the object"),
            )),
        }
    }

    /// The valid acts of `kind` among `naming`; undetermined ones are added
    /// to `pending`.
    fn valid_annotations(
        &self,
        naming: &[StoredAct],
        kind: &str,
        stack: &mut Vec<String>,
        pending: &mut Vec<String>,
    ) -> Vec<StoredAct> {
        let mut valid = Vec::new();
        for n in naming.iter().filter(|n| n.act.kind() == kind) {
            match self.eval_annotation(n, stack) {
                Outcome::Valid(_) => valid.push(n.clone()),
                Outcome::Undetermined(u) => pending.extend(u.digests),
                Outcome::Invalid(_) => {}
            }
        }
        valid
    }

    /// Evaluate an annotating act met while evaluating the acts it names.
    /// One already being evaluated (a narrow or revocation whose chain
    /// passes back through here) is taken as valid once its steps 2, 3 and
    /// §4.5 hold.
    fn eval_annotation(&self, n: &StoredAct, stack: &mut Vec<String>) -> Outcome {
        let lineage = match self.lineage(n) {
            Ok(lineage) => lineage,
            Err(outcome) => return outcome,
        };
        let in_cycle = lineage.chain.iter().any(|d| stack.contains(d));
        if !in_cycle {
            return self.eval(n, stack);
        }
        if !matches!(n.act.kind(), "narrow" | "revocation") {
            return undetermined(
                vec![n.digest.clone()],
                format!("a cycle through {}", n.digest),
            );
        }

        // Its chain passes back through an act being evaluated: steps 2 and
        // 3, the structure of step 4 (the edge, not the parent's validity,
        // which the walk above is deciding), what it names (§4.1, and a
        // software revocation's signer, §4.6), and §4.5.
        let a = &n.act;
        let at = self.options.at.as_str();
        let edge_holds = a.is_card_act()
            || self
                .store
                .get(&spelled(a, "issuer-record").unwrap_or_default())
                .is_some_and(|p| {
                    is_certifying(&p.act)
                        && spelled(&p.act, "subject-key") == spelled(a, "key")
                        && p.act.text("subject") == a.text("issuer")
                });
        let named: Option<Vec<StoredAct>> = a
            .values("names")
            .map(|v| self.store.get(&parsed_bytes(v)))
            .collect();
        let holds = verify_seal(a).is_ok()
            && a.check_issuer_binding().is_ok()
            && a.check_namespace_pairing().is_ok()
            && edge_holds
            && named.is_some_and(|named| self.check_names(n, &named).is_none())
            && a.text("not-before").is_none_or(|nb| nb <= at)
            && lineage.expiry.as_deref().is_none_or(|e| e > at);
        if holds {
            Outcome::Valid(Valid {
                act: n.digest.clone(),
                kind: a.kind().to_owned(),
                subject: None,
                object: None,
                effective_expiry: None,
                assurance: String::new(),
                chain_start_key: String::new(),
                chain: Vec::new(),
                rights: None,
                certified: None,
                layers: Vec::new(),
                prefixed: BTreeMap::new(),
            })
        } else {
            invalid(Step::Annotations, n, "fails steps 2, 3 or §4.5")
        }
    }
}

/// The current time in §2's one spelling.
pub fn now() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or_default();
    timestamp(secs)
}

/// Unix seconds in §2's spelling (Howard Hinnant's civil-from-days).
pub fn timestamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}
