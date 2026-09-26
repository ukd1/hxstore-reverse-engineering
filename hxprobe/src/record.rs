//! Parse a verified, decompressed block into message records.
//!
//! Once a block passes both CRCs and inflates to its declared length (see
//! `block.rs`) its contents are exact, so there is no salvage, no scoring and
//! no guessing left to do here. Message metadata is a sequence of
//! NUL-terminated UTF-16LE runs around the `IPM.Note` anchor:
//!
//! ```text
//!    -84  sender address       "no-reply@example-mailer.net"
//!    -44  sender display name  "Security Verification"
//!      0  ItemClass            "IPM.Note"            <- anchor
//!    +18  Message-ID           "<9e0ce892-...@example-esp.net>"
//!   +116  body / preview       "Your Verification Code Hi Alice, ..."
//! ```
//!
//! Those displacements are illustrative, not a layout. Fields are variable
//! length, so every position depends on the length of everything before it,
//! and a second record layout puts the whole header *before* the anchor. Walk
//! the runs in sequence; never index a fixed offset. `schema.rs` builds the
//! named field map on top of what this module extracts.

/// One message, ready to store.
#[derive(Default, Debug)]
pub struct Record {
    /// Offset of the block this record came from.
    pub offset: usize,
    pub sender: Option<String>,
    pub sender_name: Option<String>,
    pub recipients: Vec<String>,
    /// Folder keys observed across cached revisions; this is not a live view.
    pub folder_ids: std::collections::BTreeSet<u64>,
    pub subject: Option<String>,
    pub message_id: Option<String>,
    /// Plain text, tags stripped and entities decoded.
    pub body: String,
    /// The stored HTML exactly as found, when the message has an HTML part.
    pub html: Option<String>,
    /// Send time as Unix seconds: the earliest .NET tick in the record span.
    pub sent_unix: Option<i64>,
    /// True when the subject came from a sibling record in the same
    /// conversation rather than from this record's own bytes.
    pub subject_inherited: bool,
}

/// Selecting the send time from the ticks in a record.
///
/// The Osa protocol logs pin the encoding: `ReceivedOrRenewTime d="c"` carries
/// the raw value `639201014590000000` while the sibling `LastDeliveryTime`
/// reads `2026-07-19T23:44:19.000Z`, which makes these 100ns units since
/// 0001-01-01 (.NET ticks), not FILETIME.
///
/// Fixed displacements do not work. Fields are variable length, so a byte
/// offset only catches records whose preceding fields happen to be the
/// expected size -- `+255` and `+703` together reached just 4,420 of 16,721
/// records. Scanning the whole record span instead finds a tick in **100%** of
/// records; the problem is choosing which one.
///
/// A record holds 1-12 distinct ticks (2 and 4 are the common cases): the
/// send time plus delivery, last-modified and sync stamps. Ordinal position is
/// not stable either. What is stable is ordering: a message is sent before it
/// is delivered, modified or synced, so the **earliest** tick in the span is
/// the send time.
///
/// Scored over the whole store on how values distribute -- a send time is
/// near-unique per message, a sync stamp collapses onto the few moments
/// Outlook last ran:
///
/// ```text
///   rule              records  distinct  top-value share
///   min (earliest)     16,721     4,682   0.40%   <- send time
///   max (latest)       16,721     3,137   4.43%   <- sync stamp
/// ```
///
/// 2015-01-01 .. 2027-01-01 in .NET ticks. Wide enough for the whole store,
/// narrow enough that arbitrary binary rarely falls inside -- which is what
/// makes scanning for a bare 8-byte value safe.
const TICK_LO: u64 = 0x08d1_f36d_0530_8000;
const TICK_HI: u64 = 0x08df_679a_2dbe_c000;

/// Seconds from 0001-01-01 to the Unix epoch, in ticks.
const UNIX_EPOCH_TICKS: u64 = 621_355_968_000_000_000;

/// Read the message send time from a record span, as Unix seconds.
///
/// `span` is the record's bytes: from the previous anchor to the next, so
/// ticks are never picked up from a neighbouring message.
pub fn read_time(span: &[u8]) -> Option<i64> {
    if span.len() < 8 {
        return None;
    }
    (0..=span.len() - 8)
        .filter_map(|i| {
            let v = u64::from_le_bytes(span[i..i + 8].try_into().ok()?);
            (TICK_LO..TICK_HI).contains(&v).then_some(v)
        })
        .min()
        .map(|v| ((v - UNIX_EPOCH_TICKS) / 10_000_000) as i64)
}

/// A NUL-terminated UTF-16LE string found in a block.
#[derive(Debug, Clone)]
pub struct Field {
    /// Byte offset relative to the anchor.
    pub rel: isize,
    pub text: String,
}

/// UTF-16LE encoding of `IPM.Note`, the ItemClass anchor.
pub fn anchor_needle() -> Vec<u8> {
    "IPM.Note".encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// Extract UTF-16LE string runs in `[anchor-before, anchor+after)`.
pub fn fields(blob: &[u8], anchor: usize, before: usize, after: usize) -> Vec<Field> {
    let lo = anchor.saturating_sub(before);
    let hi = (anchor + after).min(blob.len());
    let mut out = Vec::new();
    let mut i = lo;

    while i + 1 < hi {
        if blob[i + 1] == 0 && (0x20..0x7f).contains(&blob[i]) {
            let start = i;
            let mut s = String::new();
            loop {
                // Plain ASCII, the common case.
                if i + 1 < hi && blob[i + 1] == 0 && (0x20..0x7f).contains(&blob[i]) {
                    s.push(blob[i] as char);
                    i += 2;
                    continue;
                }
                // A non-ASCII BMP character -- an accent in a display name, a
                // curly apostrophe in a subject. These are part of the same
                // string, so decode them instead of ending the run: otherwise
                // "Zoé - Réseau" is stored as "é - Réseau".
                if i + 1 < hi {
                    let u = u16::from_le_bytes([blob[i], blob[i + 1]]);
                    if (0xA0..0xD800).contains(&u) || (0xE000..0xFFFD).contains(&u) {
                        if let Some(c) = char::from_u32(u as u32) {
                            s.push(c);
                            i += 2;
                            continue;
                        }
                    }
                    // A surrogate pair, which is how emoji are encoded. Breaking
                    // the run here splits "PLEASE READ" off its leading emoji
                    // and loses the duplicate-pair match that identifies a
                    // subject, so decode the pair instead.
                    if (0xD800..0xDC00).contains(&u) && i + 3 < hi {
                        let lo = u16::from_le_bytes([blob[i + 2], blob[i + 3]]);
                        if (0xDC00..0xE000).contains(&lo) {
                            let cp = 0x1_0000
                                + ((u as u32 - 0xD800) << 10)
                                + (lo as u32 - 0xDC00);
                            if let Some(c) = char::from_u32(cp) {
                                s.push(c);
                                i += 4;
                                continue;
                            }
                        }
                    }
                }
                break;
            }
            // Single stray characters are field padding, not values, and a run
            // that is mostly binary misread as UTF-16 is not a value either.
            if s.chars().count() >= 3 && !is_binary_run(&s) {
                out.push(Field { rel: start as isize - anchor as isize, text: s });
            }
            continue;
        }
        i += 1;
    }
    out
}

/// Is this run binary that merely decoded as valid UTF-16?
///
/// Every second byte of a UTF-16LE ASCII string is zero, which is a strong
/// signal -- but arbitrary binary still produces code units in the BMP, and
/// those decode to characters without error. The result is runs like
/// `=꼄딂aĀ` or `UƝἵϙ`: structurally valid text, semantically noise.
///
/// This store's text is Latin: ASCII, Latin-1 supplement, Latin Extended-A/B,
/// plus the punctuation Outlook uses for quotes and dashes. Anything else --
/// CJK, Hangul, private-use, unassigned blocks -- is binary. Rejecting the run
/// here keeps every downstream consumer from having to re-derive the test,
/// which is how the same check ended up duplicated across the field
/// classifiers.
///
/// The threshold is deliberately loose: a single accented or CJK character in
/// an otherwise clean subject is real, so a run is rejected only when a
/// meaningful share of it is off-script.
fn is_binary_run(s: &str) -> bool {
    let mut total = 0usize;
    let mut off_script = 0usize;

    for c in s.chars() {
        total += 1;
        let u = c as u32;
        let latin = u < 0x250                       // ASCII, Latin-1, Latin Ext-A/B
            || (0x2000..0x2070).contains(&u)        // general punctuation
            || (0x20A0..0x20D0).contains(&u)        // currency symbols
            || matches!(u, 0x2122 | 0x2190..=0x21FF) // (tm), arrows
            // Emoji and pictographs. Marketing subjects genuinely carry these
            // ("Only 14 days left in your trial. (alarm clock)"), and they sit
            // far from the CJK blocks that indicate misread binary, so
            // admitting them costs nothing.
            || (0x2600..0x27C0).contains(&u)        // misc symbols, dingbats
            || matches!(u, 0x203C | 0x2049 | 0x23E9..=0x23FA | 0x25AA..=0x25FE)
            || (0x1F000..0x1FAFF).contains(&u)      // emoji planes
            || u == 0xFE0F                          // variation selector-16
            || u == 0x200D;                         // zero-width joiner
        if !latin {
            off_script += 1;
        }
    }

    total >= 3 && off_script * 5 >= total
}

fn is_email(s: &str) -> bool {
    let Some(at) = s.find('@') else { return false };
    if at == 0 || at + 1 >= s.len() || s.contains(' ') || s.len() > 254 {
        return false;
    }
    if !s
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'@' | b'.' | b'_' | b'-' | b'+' | b'%'))
    {
        return false;
    }
    let domain = &s[at + 1..];
    let Some(dot) = domain.rfind('.') else { return false };
    let tld = &domain[dot + 1..];
    !domain.starts_with('.')
        && dot > 0
        && (2..=12).contains(&tld.len())
        && tld.bytes().all(|c| c.is_ascii_alphabetic())
}

/// Where a run of single-byte text stops looking like text.
///
/// Used to bound an HTML body that has no closing tag. Scans a sliding window
/// and cuts at the first stretch that is mostly non-printable -- the record's
/// trailing binary, or the start of the next record.
fn text_end(b: &[u8]) -> usize {
    const WIN: usize = 32;
    let printable = |c: u8| (0x20..0x7f).contains(&c) || matches!(c, b'\n' | b'\r' | b'\t');
    let mut i = 0usize;
    while i + WIN <= b.len() {
        let ok = b[i..i + WIN].iter().filter(|&&c| printable(c)).count();
        if ok * 4 < WIN * 3 {
            return i;
        }
        i += WIN;
    }
    b.len()
}

/// Strip tags and decode entities, yielding readable text.
pub fn html_to_text(html: &str) -> String {
    let mut out = String::with_capacity(html.len() / 2);
    let b = html.as_bytes();
    let mut i = 0usize;
    let mut skip = 0usize;

    while i < b.len() {
        if b[i] == b'<' {
            let Some(e) = html[i..].find('>') else { break };
            let end = i + e;
            let name: String = html[i + 1..end]
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '/')
                .collect::<String>()
                .to_ascii_lowercase();
            match name.as_str() {
                "script" | "style" | "head" => skip += 1,
                "/script" | "/style" | "/head" => skip = skip.saturating_sub(1),
                // Block-level closes become a space so words either side of a
                // tag do not run together.
                "br" | "/p" | "/div" | "/tr" | "/li" | "/h1" | "/h2" | "/h3" | "/td"
                    if skip == 0 =>
                {
                    out.push(' ')
                }
                _ => {}
            }
            i = end + 1;
            continue;
        }
        if skip == 0 {
            out.push(b[i] as char);
        }
        i += 1;
    }

    let out = out
        .replace("&nbsp;", " ")
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&mdash;", "-")
        .replace("&ndash;", "-");

    // The stored HTML is UTF-8 read one byte per char, so re-join the
    // multi-byte sequences. Chars above U+00FF are already correct and must be
    // passed through rather than truncated to a byte.
    let decoded = if out.chars().all(|c| (c as u32) < 0x100) {
        let bytes: Vec<u8> = out.chars().map(|c| c as u32 as u8).collect();
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        out
    };

    let mut text = String::with_capacity(decoded.len());
    let mut last_ws = false;
    for c in decoded.chars() {
        if c.is_control() && c != '\n' {
            continue;
        }
        if c.is_whitespace() {
            if !last_ws {
                text.push(' ');
            }
            last_ws = true;
        } else {
            text.push(c);
            last_ws = false;
        }
    }
    text.trim().to_string()
}


/// Values that read like words but are metadata, not content.
///
/// The record interleaves enum fields (sensitivity, scan verdicts) and MIME
/// types with the real strings, so an explicit list is the only way to keep
/// them out of the subject and display-name columns.
fn is_enum_value(t: &str) -> bool {
    const FLAGS: [&str; 14] = [
        "IPM.Note", "Anonymous", "Internal", "External", "Normal", "None",
        "Unknown", "Focused", "Other", "Mailbox", "OneOff", "SMTP", "Personal",
        "Confidential",
    ];
    FLAGS.iter().any(|f| f.eq_ignore_ascii_case(t))
        || t.starts_with("image/")
        || t.starts_with("application/")
        || t.starts_with("text/")
        || t.starts_with("multipart/")
        || is_guid(t)
        || is_opaque_blob(t)
}

/// Machine-readable payloads that sit among the text fields.
///
/// The Osa protocol logs name these explicitly (see SPEC.md): the long base64
/// run is `AntispamSafeLinksMsgData_Substrate`, and the long hex runs are
/// `ImmId` / `ImmConversationId` / `ChangeKey`. They are real fields, not
/// decode errors, but they are never display text.
fn is_opaque_blob(t: &str) -> bool {
    // Base64 JSON: SafeLinks data always begins `{"` -> `eyJ`.
    if t.starts_with("eyJ") {
        return true;
    }
    // A MIME Content-ID for an inline image: "image001.png@01DD024D.A7640430".
    // These sit among the text fields and read as addresses, but they name an
    // attachment part, not a person or a subject.
    if let Some((local, domain)) = t.split_once('@') {
        let stem = local.rsplit('.').next().unwrap_or("");
        if matches!(stem, "png" | "jpg" | "jpeg" | "gif" | "bmp")
            && domain.starts_with("01")
            && domain.chars().all(|c| c.is_ascii_hexdigit() || c == '.')
        {
            return true;
        }
    }
    // A long unbroken hex run is an Imm* identifier, not a subject.
    t.len() >= 24 && t.chars().all(|c| c.is_ascii_hexdigit())
}

/// A bare GUID -- `8-4-4-4-12` hex, with or without braces.
///
/// Exchange stores several of these per message (ConversationId, ChangeKey,
/// MailboxGuid, InstanceKey) as UTF-16LE runs sitting among the text fields,
/// and they repeat, so the "stored twice" subject heuristic latches onto them.
/// They are identifiers, never display text.
fn is_guid(t: &str) -> bool {
    let t = t.trim_matches(|c| c == '{' || c == '}');
    let groups: Vec<&str> = t.split('-').collect();
    groups.len() == 5
        && [8usize, 4, 4, 4, 12] == *groups.iter().map(|g| g.len()).collect::<Vec<_>>()
        && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// An attachment filename or a store path.
///
/// These sit among the header fields and read as plausible text, but they name
/// a file rather than a person or a subject.
fn is_filename(t: &str) -> bool {
    // A store path. A bare '/' is not enough on its own -- real subjects say
    // "Weekly Digest for acme/platform" and "Misc Bugs / Tasks".
    if t.starts_with("~/") || t.starts_with('/') || t.contains("\\") {
        return true;
    }
    matches!(
        t.rsplit('.').next().unwrap_or("").to_ascii_lowercase().as_str(),
        "csv" | "pdf" | "dat" | "png" | "jpg" | "jpeg" | "gif" | "xlsx" | "docx" | "zip" | "eml"
    )
}

/// Does this field read as a subject line rather than body text?
///
/// The fallback path sees the body preview alongside the real subject, and the
/// two are easy to tell apart: a preview carries sentence punctuation, contact
/// details from a signature block, `@mentions`, or a bare address, and it runs
/// long. A subject is a short phrase.
fn is_subject_like(t: &str) -> bool {
    let n = t.chars().count();
    // Real subjects run long -- mailing lists and ticket systems routinely
    // exceed 160 characters. The duplicate-pair rule is the real guard, so the
    // cap only has to exclude whole-body runs.
    if !(3..=400).contains(&n) || is_email(t) || is_filename(t) {
        return false;
    }
    // Links and mail headers quoted out of a body.
    if t.contains("http") || t.contains("mailto:") {
        return false;
    }
    // Prose: more than one sentence. A single ". " is common in real subjects
    // ("Re: Update. Please review"), so only reject a genuine run of them.
    if t.matches(". ").count() >= 2 {
        return false;
    }
    // Mostly letters, not a wall of digits or punctuation. Off-script runs are
    // already rejected by `is_binary_run` when the field is extracted, so this
    // only has to separate a subject from a reference number.
    t.chars().filter(|c| c.is_alphabetic()).count() * 2 >= n
}

/// Split a packed multi-value run into its parts.
///
/// Some fields hold a list rather than a scalar -- the recipient display-name
/// collection is stored as `Alice Turner` `U+1C00` `Bob Nakamura` `U+1400`
/// `Carol Diaz`, where the separators are the per-entry length prefixes
/// decoded as characters. They are always outside the Latin range this store's
/// text uses, so the run splits cleanly on any off-script character.
///
/// Returns the parts in order, dropping any that are not plausible values.
pub fn split_packed(t: &str) -> Vec<String> {
    t.split(|c: char| {
        let u = c as u32;
        !(u < 0x250
            || (0x2000..0x2070).contains(&u)
            || (0x20A0..0x20D0).contains(&u)
            || matches!(u, 0x2122 | 0x2190..=0x21FF))
    })
    .map(str::trim)
    .filter(|p| p.chars().count() >= 2)
    .map(str::to_string)
    .collect()
}

/// Does this field look like a person or organisation name?
fn is_person_name(t: &str) -> bool {
    let n = t.chars().count();
    if !(2..=64).contains(&n) || t.contains('@') || is_enum_value(t) {
        return false;
    }
    // Names are short and word-like; subjects and previews run long and carry
    // sentence punctuation.
    if t.contains(". ") || t.contains(" - http") || n > 48 {
        return false;
    }
    // Body text bleeding into the name slot. A display name never carries a
    // markup fragment, a sign-off comma, or sentence punctuation.
    if t.contains('<') || t.contains('>') || t.ends_with(',') || t.contains(", <") {
        return false;
    }
    if is_filename(t) {
        return false;
    }
    // Binary runs are filtered at extraction, so this only has to separate a
    // name from a reference number.
    t.chars().filter(|c| c.is_alphabetic()).count() * 2 >= n
}

/// Collapse a value the store writes twice with no separator.
///
/// Display names and subjects are commonly stored doubled -- "AcmeAcme",
/// "Alert ServiceAlert Service" -- so halve the string
/// when its two halves are identical.
fn undouble(t: &str) -> String {
    let n = t.chars().count();
    if n.is_multiple_of(2) {
        let half: String = t.chars().take(n / 2).collect();
        if t.chars().skip(n / 2).collect::<String>() == half {
            return half;
        }
    }
    t.to_string()
}

/// Parse the record anchored at `anchor` within a verified block.
/// Extract the message body from a record.
///
/// Only the body and its HTML source come from here. Every other field is
/// resolved by `schema.rs`, which assigns runs to named slots using the
/// protocol field order rather than matching on their shape. Those two paths
/// used to be duplicated; this one is kept because the body is not a UTF-16LE
/// run and so is not part of the named map.
pub fn parse(offset: usize, blob: &[u8], anchor: usize) -> Record {
    let mut rec = Record { offset, ..Default::default() };

    // A block holds records back to back, so bound this one at the next
    // ItemClass anchor. Without that the HTML scan runs into the following
    // record and stores a body that is part one message and part another.
    let end = memchr::memmem::find(&blob[anchor + 2..], &anchor_needle())
        .map_or(blob.len(), |p| anchor + 2 + p);
    let tail = fields(blob, anchor + 18, 0, end.saturating_sub(anchor + 18));

    // Sender pair, as a fallback only. `schema.rs` resolves these by field
    // order and wins wherever it produces a value, but its type checks are
    // stricter and reject roughly 1,200 display names that this shape-based
    // scan recovers. Two record layouts occur: the sender sits just before the
    // anchor, or the whole field group sits after it with the preceding bytes
    // belonging to the previous record. Prefer an address just before the
    // anchor, else take the first inside this record's own span.
    let before = fields(blob, anchor, 300, 0);
    let picked: Option<(String, Vec<Field>)> = before
        .iter()
        .rposition(|f| is_email(f.text.trim()))
        .map(|i| (before[i].text.trim().to_lowercase(), before[i + 1..].to_vec()))
        .or_else(|| {
            tail.iter()
                .position(|f| is_email(f.text.trim()))
                .map(|i| (tail[i].text.trim().to_lowercase(), tail[i + 1..].to_vec()))
        });
    if let Some((addr, rest)) = picked {
        // The display name is the first plausible run after the address, not
        // the longest: the longest pulls in the subject or the body preview,
        // which sit in the same group. Values are often stored doubled
        // ("AcmeAcme"), addresses included.
        rec.sender_name = rest
            .iter()
            .map(|f| undouble(f.text.trim()))
            .find(|t| is_person_name(t));
        rec.sender = Some(undouble(&addr));
    }

    let region = &blob[anchor..end];
    rec.html = ["<html", "<!DOCTYPE", "<body", "<div", "<table"]
        .iter()
        .filter_map(|m| memchr::memmem::find(region, m.as_bytes()))
        .min()
        .map(|s| {
            let tail = &region[s..];
            let end = ["</html>", "</body>"]
                .iter()
                .filter_map(|m| memchr::memmem::find(tail, m.as_bytes()).map(|p| p + m.len()))
                .min()
                .unwrap_or_else(|| text_end(tail));
            // Whatever follows the final closing tag is the next field
            // bleeding in, not part of the message. Anchor on "</…>" so a
            // stray '>' inside an attribute cannot be mistaken for the end.
            let end = match memchr::memmem::rfind(&tail[..end], b"</") {
                Some(p) => match memchr::memchr(b'>', &tail[p..end]) {
                    Some(q) => p + q + 1,
                    None => p,
                },
                None => end,
            };
            // Stored as UTF-8 read byte-wise, so reassemble it as UTF-8.
            let mut s = String::from_utf8_lossy(&tail[..end]).into_owned();
            // Final guard: whatever trails the last '>' is the next field, not
            // markup. Cheap, and it catches the cases the byte-level bounds
            // above cannot see.
            while let Some(p) = s.rfind('>') {
                if p + 1 == s.len() {
                    break;
                }
                // Anything after the final '>' that is too short to be content
                // is the next field's opening bytes; drop it and re-check.
                if s[p + 1..].trim().chars().count() >= 32 {
                    break;
                }
                s.truncate(p + 1);
            }
            s
        });
    // Normalise: a record whose HTML is cut short in storage ends with the
    // first byte or two of the following field. Drop that tail so the column
    // holds markup only.
    if let Some(h) = rec.html.as_mut() {
        while let Some(p) = h.rfind('>') {
            if p + 1 == h.len() {
                break;
            }
            // Count only real content: the tail of a truncated record is a
            // handful of stray bytes, often control characters that `trim`
            // leaves in place, so ignore those when judging its length.
            let trailing = h[p + 1..]
                .chars()
                .filter(|c| !c.is_whitespace() && !c.is_control())
                .count();
            if trailing >= 32 {
                break;
            }
            h.truncate(p + 1);
        }
    }

    rec.body = rec.html.as_deref().map(html_to_text).unwrap_or_default();

    rec.body = rec.html.as_deref().map(html_to_text).unwrap_or_default();

    if rec.body.split_whitespace().count() < 5 {
        if let Some(f) = tail
            .iter()
            .filter(|f| !f.text.starts_with('<'))
            .max_by_key(|f| f.text.len())
        {
            rec.body = f.text.trim().to_string();
        }
    }

    rec
}

// -- Classifiers shared with the schema layer --------------------------------

/// Does this string parse as an email address?
pub fn looks_like_email(s: &str) -> bool {
    is_email(s)
}

/// Does this string read as a person or organisation name?
pub fn looks_like_person(s: &str) -> bool {
    is_person_name(s)
}

/// Does this string read as a subject line rather than body text, an
/// identifier, or a machine payload?
pub fn subject_like(s: &str) -> bool {
    // A packed multi-value run is a name collection, never a subject: the
    // separators are per-entry length prefixes, so a run that splits into
    // several parts is a list even when each part reads as text.
    if split_packed(s).len() > 1 {
        return false;
    }
    is_subject_like(s) && !is_enum_value(s) && !is_opaque_blob(s)
}

/// Collapse a value the store writes twice with no separator.
pub fn undouble_pub(s: &str) -> String {
    undouble(s)
}
