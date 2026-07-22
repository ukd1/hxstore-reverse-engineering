//! A named key -> value map for each record.
//!
//! The parser in `record.rs` decides what each string means by its shape, one
//! field at a time. That works, but every new junk value needs a new rule.
//! This module takes the other approach: build a map of *named* fields per
//! record, so extraction becomes a lookup rather than a guess.
//!
//! The names are not invented. Outlook's own protocol logs (SPEC.md 6.1) list
//! the fields it syncs, in order, with `ItemClass_Substrate` -- the `IPM.Note`
//! anchor -- sitting among them:
//!
//! ```text
//!   Topic · NormalizedSubject · Preview · LastDeliveryTime · SentTime ·
//!   SenderDisplayNamesCollection{Name, Address} · From{Name, Address} ·
//!   ChangeKey · ItemClass_Substrate · InternetMessageId · ...
//! ```
//!
//! Two facts make this usable:
//!
//!   * fields are NUL-terminated and variable length, so their *byte offsets*
//!     drift -- a sender address was observed at -74, -82 and +1174 -- and
//!     cannot be indexed directly;
//!   * their *order* is stable. Reading the string runs in sequence around the
//!     anchor gives the same layout in record after record.
//!
//! So a slot is identified by its position in the run sequence, and confirmed
//! by a type check drawn from the schema (an address must parse as an address,
//! a timestamp must fall in a plausible range). A slot that fails its check is
//! left empty rather than filled with whatever happened to sit there.

use std::collections::BTreeMap;

use crate::record::{self, Field};

/// The fields worth naming, using the Osa protocol's own names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Key {
    /// `From` / `SenderDisplayNamesCollection` -> `Address`.
    SenderAddress,
    /// `From` / `SenderDisplayNamesCollection` -> `Name`.
    SenderName,
    /// `ItemClass_Substrate`, always `IPM.Note` here. The anchor.
    ItemClass,
    /// `InternetMessageId`, the RFC822 Message-ID.
    InternetMessageId,
    /// `Preview`, Outlook's cached ~255-character body summary.
    Preview,
    /// `NormalizedSubject` / `Topic` -- stored as an adjacent near-identical
    /// pair, which is what makes the subject identifiable at all.
    NormalizedSubject,
    /// A recipient address, in order of appearance.
    Recipient,
    /// `ConversationId` / `ImmConversationId` / `ImmThreadId`: a hex or GUID
    /// run identifying the thread this message belongs to.
    ///
    /// Not display data, but the key that makes the subject recoverable for the
    /// records that hold none of their own: the store writes `Topic` once per
    /// conversation, not once per message.
    ConversationId,
}

impl Key {
    pub fn as_str(self) -> &'static str {
        match self {
            Key::SenderAddress => "SenderAddress",
            Key::SenderName => "SenderName",
            Key::ItemClass => "ItemClass",
            Key::InternetMessageId => "InternetMessageId",
            Key::Preview => "Preview",
            Key::NormalizedSubject => "NormalizedSubject",
            Key::Recipient => "Recipient",
            Key::ConversationId => "ConversationId",
        }
    }
}

/// A named field, keeping the evidence that produced it.
#[derive(Debug, Clone)]
pub struct Slot {
    pub key: Key,
    pub value: String,
    /// Byte displacement from the anchor -- retained so a mapping can be
    /// checked against the raw record rather than taken on trust.
    pub rel: isize,
    /// Index in the run sequence, negative before the anchor.
    pub seq: isize,
}

/// The named contents of one record.
#[derive(Debug, Default)]
pub struct Map {
    pub slots: Vec<Slot>,
}

impl Map {
    /// First value for `key`.
    pub fn get(&self, key: Key) -> Option<&str> {
        self.slots.iter().find(|s| s.key == key).map(|s| s.value.as_str())
    }

    /// Every value for `key`, in order of appearance.
    pub fn all(&self, key: Key) -> Vec<&str> {
        self.slots.iter().filter(|s| s.key == key).map(|s| s.value.as_str()).collect()
    }

    /// Render as `Key = value` lines, for inspection.
    pub fn dump(&self) -> String {
        let mut out = String::new();
        for s in &self.slots {
            let v: String = s.value.chars().take(88).collect();
            out.push_str(&format!("  {:>4} {:>7}  {:<18} {}\n", s.seq, s.rel, s.key.as_str(), v));
        }
        out
    }
}

/// Is this run a Message-ID rather than prose that merely contains an address?
fn is_message_id(t: &str) -> bool {
    t.starts_with('<') && t.ends_with('>') && t.contains('@') && !t.contains(' ')
}

/// Build the named map for the record anchored at `anchor`.
///
/// `end` bounds the record, so fields never bleed in from the next message.
/// The backward window matters: the sender pair sits before the anchor, but so
/// does the *previous* record. Reading too far back pairs one message's sender
/// with another's subject, so callers pass the distance to the previous anchor.
pub fn build_bounded(blob: &[u8], anchor: usize, end: usize, back: usize) -> Map {
    let mut map = Map::default();

    // Read the runs around the anchor and split them into the sequence before
    // it and the sequence after, which is the axis the schema is ordered on.
    let all = record::fields(blob, anchor, back, end.saturating_sub(anchor));
    let (before, after): (Vec<&Field>, Vec<&Field>) = all.iter().partition(|f| f.rel < 0);

    let mut slots: Vec<Slot> = Vec::new();
    macro_rules! push {
        ($key:expr, $f:expr, $seq:expr, $value:expr) => {
            slots.push(Slot { key: $key, value: $value, rel: $f.rel, seq: $seq })
        };
    }

    // The anchor itself.
    if let Some(f) = all.iter().find(|f| f.rel == 0) {
        push!(Key::ItemClass, f, 0, f.text.clone());
    }

    // Walking backwards from the anchor, the schema puts the sender pair
    // immediately before `ItemClass`: Address then Name. Taking the *nearest*
    // address rather than any address is what keeps a quoted address from the
    // body out of the sender slot.
    // Nearest-first from the anchor: backwards through the runs before it (the
    // common layout), then forwards. Layout B puts the whole header before the
    // anchor, and some records carry the sender only after it.
    //
    // The distance bound matters as much as the ordering. In layout A the
    // sender pair sits within ~120 bytes of the anchor; a match hundreds of
    // bytes back belongs to the *previous* record, and taking it pairs one
    // message's sender with another's subject. Where the header genuinely sits
    // far from the anchor (layout B), the address is still the nearest one,
    // so a generous bound costs nothing while excluding the neighbour.
    const SENDER_MAX_DIST: isize = 320;
    let nearest: Vec<&&Field> = before
        .iter()
        .rev()
        .chain(after.iter())
        .filter(|f| f.rel.abs() <= SENDER_MAX_DIST || f.rel > 0)
        .collect();
    for (i, f) in nearest.iter().enumerate() {
        let t = f.text.trim();
        if record::looks_like_email(t) {
            push!(Key::SenderAddress, f, -(i as isize) - 1, record::undouble_pub(t));
            // The display name is the run *immediately* adjacent to the
            // address -- either just before it (the schema's Name/Address
            // order) or just after. Searching further back finds subject and
            // body text sitting hundreds of bytes away, which is how a
            // signature line ends up in the sender-name column.
            let neighbours = [
                nearest.get(i + 1).copied(),
                i.checked_sub(1).and_then(|k| nearest.get(k).copied()),
            ];
            for n in neighbours.into_iter().flatten() {
                // The name sits beside its address. A run far from it is the
                // subject or preview, which is how subject text reaches the
                // display-name column.
                if (n.rel - f.rel).abs() > 200 {
                    continue;
                }
                // The name slot can hold a packed list of display names rather
                // than a single value; the sender is the first entry.
                let raw = record::undouble_pub(n.text.trim());
                let t = record::split_packed(&raw).into_iter().next().unwrap_or(raw);
                if !record::looks_like_email(&t) && record::looks_like_person(&t) {
                    push!(Key::SenderName, n, -(i as isize) - 2, t);
                    break;
                }
            }
            break;
        }
    }

    // After the anchor the schema runs InternetMessageId, Preview, then the
    // Topic/NormalizedSubject pair. Order is stable but the Message-ID is
    // absent on many records, so each slot is claimed by type, in sequence.
    for (i, f) in after.iter().enumerate() {
        let seq = i as isize + 1;
        let t = f.text.trim();

        if is_message_id(t) && !slots.iter().any(|s| s.key == Key::InternetMessageId) {
            push!(Key::InternetMessageId, f, seq, t.trim_matches(['<', '>']).to_string());
            continue;
        }
        if record::looks_like_email(t) {
            push!(Key::Recipient, f, seq, t.to_lowercase());
            continue;
        }
    }

    // NormalizedSubject and Topic are stored back to back and near-identical.
    // That duplication is the signal: a value appearing twice after the anchor
    // is the subject, where a value appearing once is the preview.
    // `Topic` is the conversation subject with reply/forward prefixes stripped;
    // `NormalizedSubject` keeps them. So the pair reads "Re: BrokerEngine: Touch
    // SMS" / "BrokerEngine: Touch SMS" -- near-identical but not equal, which an
    // exact comparison misses. Strip the prefixes before comparing.
    fn strip_prefix(s: &str) -> &str {
        let mut t = s.trim();
        loop {
            let lower = t.to_ascii_lowercase();
            let cut = ["re:", "fw:", "fwd:", "re :", "aw:", "tr:"]
                .iter()
                .find(|p| lower.starts_with(**p))
                .map(|p| p.len());
            match cut {
                Some(n) => t = t[n..].trim_start(),
                None => return t,
            }
        }
    }
    let key40 = |s: &str| -> String { strip_prefix(s).chars().take(40).collect() };
    // The subject sits close behind the anchor. A candidate thousands of bytes
    // out is inside the body or the trailing binary, not the header.
    const SUBJECT_MAX_REL: isize = 4096;
    // In layout B the metadata sits *before* the anchor, so a record can have
    // no runs after it at all. The duplicate pair is the signal wherever it
    // occurs, so look on both sides -- after the anchor first, since that is
    // where the pair sits in the common layout.
    let ordered: Vec<&&Field> = after
        .iter()
        .filter(|f| f.rel <= SUBJECT_MAX_REL)
        .chain(before.iter().rev())
        .collect();
    // The `Topic` half of the pair is not always a standalone run. It is
    // commonly appended to the packed recipient-name collection, so the record
    // reads `Re: Quarterly Report` … `Alice Turner<sep>Bob NakamuraQuarterly Report`.
    // Comparing whole runs misses that, so compare against the *last* part of
    // a packed run as well: that tail is the Topic.
    let tail_of = |s: &str| -> String {
        let parts = record::split_packed(s);
        parts.last().cloned().unwrap_or_else(|| s.to_string())
    };
    let matches = |a: &str, b: &str| -> bool {
        let (ka, kb) = (key40(a), key40(b));
        if ka == kb {
            return true;
        }
        // The last entry of a packed name run has the Topic concatenated onto
        // it with no separator -- `…Bob NakamuraQuarterly Report` -- so neither an
        // equality nor a whole-run comparison fires. What does hold is that
        // the run *ends with* the subject once reply prefixes are stripped.
        let sa = strip_prefix(a).trim();
        if sa.chars().count() < 4 {
            return false;
        }
        let tb = tail_of(b);
        tb.ends_with(sa) || strip_prefix(b).trim().ends_with(sa) || key40(&tb) == ka
    };
    let subject = ordered.iter().find(|f| {
        let t = record::undouble_pub(f.text.trim());
        record::subject_like(&t)
            && ordered
                .iter()
                .filter(|g| matches(&t, &record::undouble_pub(g.text.trim())))
                .count()
                > 1
    });
    // Fall back to a single unpaired run when it sits exactly where the schema
    // puts the subject. Measured over the store, 63 records (3.2 % of those
    // otherwise missing one) hold a subject-like run just after the anchor with
    // no duplicate -- `You're in! Welcome to …`, `Acme x Widgets`. The
    // position bound is what makes this safe rather than a guess: an unbounded
    // fallback pulls in body previews and the neighbouring record's fields,
    // which is exactly the junk an earlier version of this parser emitted.
    const SUBJECT_SOLO_MAX_REL: isize = 2500;
    let subject = subject.or_else(|| {
        ordered.iter().find(|f| {
            let t = record::undouble_pub(f.text.trim());
            if !(0..=SUBJECT_SOLO_MAX_REL).contains(&f.rel) || !record::subject_like(&t) {
                return false;
            }
            // A packed run is a list of values, not one subject. The quick-reply
            // collection ("Got it, thanks!" + "Yes, will do." + `Anonymous`)
            // lands here otherwise, since each part reads as ordinary text.
            if record::split_packed(&t).len() > 1 || t.ends_with("Anonymous") {
                return false;
            }
            // A run starting mid-word is a fragment of a longer string that
            // began before the window, not a subject in its own right.
            let starts_clean = t
                .chars()
                .next()
                .is_some_and(|c| c.is_uppercase() || c.is_ascii_digit() || !c.is_alphabetic());
            if !starts_clean {
                return false;
            }
            // Real subjects here run to two words or more once a reply prefix
            // is discounted. `looks_like_person` is deliberately *not* used:
            // it rejects short title-case subjects like "Acme API routes".
            t.split_whitespace().count() >= 2
        })
    });
    if let Some(f) = subject {
        let seq = ordered.iter().position(|g| g.rel == f.rel).unwrap_or(0) as isize + 1;
        push!(Key::NormalizedSubject, f, seq, record::undouble_pub(f.text.trim()));
    }

    // Conversation identifiers, for the subject back-fill described above.
    // These are `ImmConversationId` / `ChangeKey` style values: long unbroken
    // hex, or a GUID. They are rejected as display text elsewhere, which is
    // precisely why they are reliable as keys.
    for f in ordered.iter() {
        let t = f.text.trim();
        let hexish = t.len() >= 24 && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
        if hexish {
            let seq = ordered.iter().position(|g| g.rel == f.rel).unwrap_or(0) as isize + 1;
            push!(Key::ConversationId, f, seq, t.to_string());
        }
    }

    // A display name identical to the subject is the subject: the name slot
    // picked up a neighbouring run rather than a real value. Dropping it is
    // right -- an absent name is honest, a duplicated subject is not.
    if let (Some(n), Some(sub)) = (
        slots.iter().position(|s| s.key == Key::SenderName),
        slots.iter().find(|s| s.key == Key::NormalizedSubject).map(|s| s.value.clone()),
    ) {
        if slots[n].value == sub {
            slots.remove(n);
        }
    }

    // Preview: the longest remaining run that is not the subject and not markup.
    let claimed: Vec<isize> = slots.iter().map(|s| s.rel).collect();
    if let Some(f) = after
        .iter()
        .filter(|f| !claimed.contains(&f.rel) && !f.text.trim_start().starts_with('<'))
        .max_by_key(|f| f.text.len())
    {
        let seq = after.iter().position(|g| g.rel == f.rel).unwrap_or(0) as isize + 1;
        push!(Key::Preview, f, seq, f.text.trim().to_string());
    }

    slots.sort_by_key(|s| s.seq);
    map.slots = slots;
    map
}

/// Aggregate statistics: which keys are found, and how consistently.
pub fn tally(maps: &[Map]) -> BTreeMap<&'static str, usize> {
    let mut t = BTreeMap::new();
    for m in maps {
        for k in [
            Key::SenderAddress,
            Key::SenderName,
            Key::ItemClass,
            Key::InternetMessageId,
            Key::Preview,
            Key::NormalizedSubject,
            Key::Recipient,
            Key::ConversationId,
        ] {
            if m.get(k).is_some() {
                *t.entry(k.as_str()).or_insert(0) += 1;
            }
        }
    }
    t
}
