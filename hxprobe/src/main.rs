//! `hxprobe` — a parser for `HxStore.hxd`, the New Outlook for Mac message store.
//!
//! The store is a paged block container: each block carries two CRC-32s and an
//! LZ4-compressed payload holding one or more message records. Because the
//! checksums make every block self-validating, this is a parser rather than a
//! carver — a wrong offset fails loudly instead of yielding plausible garbage.
//!
//! See `SPEC.md` for the format itself. Four commands:
//!
//! ```text
//!   hxprobe blocks <file>            verify every block, report coverage
//!   hxprobe db     <file> [out.db]   build a SQLite database with FTS5 search
//!   hxprobe map    <file> [n]        dump the named field map for n records
//!   hxprobe find   <file> <term>     show records whose text contains <term>
//! ```
//!
//! The file is memory-mapped throughout and never read into an owned buffer, so
//! peak RSS stays near the working set (~67 MB on a 56 MB store) rather than
//! tracking file size.

use std::collections::BTreeMap;
use std::env;
use std::fs::File;

use memmap2::Mmap;

mod block;
mod header;
mod lz;
mod record;
mod schema;

/// Memory-map a store file read-only.
///
/// Mapping rather than reading matters: these stores reach a gigabyte, and
/// `read()`-ing one into a `Vec` is an easy way to exhaust a machine.
fn map(path: &str) -> Mmap {
    let f = File::open(path).unwrap_or_else(|e| panic!("open {path}: {e}"));
    // SAFETY: the file is opened read-only and only read through the slice.
    // A concurrent writer could tear reads, which is why the documented
    // workflow is to snapshot the store while Outlook is closed.
    let mm = unsafe { Mmap::map(&f) }.unwrap_or_else(|e| panic!("mmap {path}: {e}"));

    // Check the header before doing anything else, so pointing this at the
    // wrong file says so instead of reporting zero blocks.
    match header::check(&mm) {
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
        Ok(h) if !h.known => {
            eprintln!(
                "{path}: warning: store version {:?} (0x{:02x}) is untested; \
                 known versions are 'i' (macOS) and 'h' (Windows Mail).\n\
                 Parsing anyway: every block is checksummed, so bad data fails \
                 loudly rather than silently.",
                h.version as char, h.version
            );
        }
        Ok(_) => {}
    }
    mm
}

/// One message record, located and bounded inside a decompressed block.
struct Located<'a> {
    /// Bytes of the record: from the previous anchor to the next.
    span: &'a [u8],
    /// Offset of the anchor within the block payload.
    anchor: usize,
    /// Distance from the anchor back to the start of the span.
    back: usize,
    /// Offset of the anchor's record end within the block payload.
    end: usize,
}

/// Split a decompressed block into its records.
///
/// Records sit back to back with no length field, so each one is bounded by the
/// neighbouring `IPM.Note` anchors. Without that bound fields bleed between
/// messages and pair one message's sender with another's subject.
fn records<'a>(data: &'a [u8], needle: &[u8]) -> Vec<Located<'a>> {
    memchr::memmem::find_iter(data, needle)
        .map(|anchor| {
            let end = memchr::memmem::find(&data[anchor + 2..], needle)
                .map_or(data.len(), |p| anchor + 2 + p);
            let back = memchr::memmem::rfind(&data[..anchor], needle)
                .map_or(anchor.min(2048), |p| anchor - p);
            Located { span: &data[anchor - back..end], anchor, back, end }
        })
        .collect()
}

/// Verify every block in the file and report coverage.
fn cmd_blocks(path: &str) {
    let mm = map(path);
    if let Ok(h) = header::check(&mm) {
        println!(
            "Nostromo version {:?}{}, page size {}",
            h.version as char,
            if h.known { "" } else { " (untested)" },
            h.page_size
        );
    }
    let offs = block::find_all(&mm);
    let needle = record::anchor_needle();

    let (mut ok, mut bytes, mut with_ipm, mut recs) = (0usize, 0usize, 0usize, 0usize);
    let mut by_kind: BTreeMap<u32, usize> = BTreeMap::new();

    for &o in &offs {
        let Some(b) = block::parse(&mm, o) else { continue };
        ok += 1;
        bytes += b.data.len();
        *by_kind.entry(b.kind).or_default() += 1;
        let n = memchr::memmem::find_iter(&b.data, &needle).count();
        if n > 0 {
            with_ipm += 1;
            recs += n;
        }
    }

    println!("{} block signatures found", offs.len());
    println!(
        "verified {ok}/{} ({:.2}%), {:.1} MB decompressed",
        offs.len(),
        100.0 * ok as f64 / offs.len() as f64,
        bytes as f64 / 1e6
    );
    println!("{with_ipm} blocks hold mail, {recs} IPM.Note records");
    for (k, n) in &by_kind {
        println!("  type {k:<3} {n}");
    }
}

/// Dump the named field map for the first `n` records.
///
/// With `n = 0`, prints only the aggregate coverage per key — the numbers
/// quoted in SPEC.md §6.2.
fn cmd_map(path: &str, n: usize) {
    let mm = map(path);
    let needle = record::anchor_needle();
    let mut maps = Vec::new();
    let mut shown = 0usize;

    for o in block::find_all(&mm) {
        let Some(b) = block::parse(&mm, o) else { continue };
        for r in records(&b.data, &needle) {
            let m = schema::build_bounded(&b.data, r.anchor, r.end, r.back);
            if shown < n {
                println!("\n=== block 0x{o:08x}  anchor +{} ===", r.anchor);
                print!("{}", m.dump());
                shown += 1;
            }
            maps.push(m);
        }
    }

    println!("\n{} records\n", maps.len());
    for (k, v) in schema::tally(&maps) {
        println!("  {:<20} {:>6}  {:>5.1}%", k, v, v as f64 * 100.0 / maps.len() as f64);
    }
}

/// Show the records whose span contains `term`, with their field maps.
///
/// Used to check a row in the database against the bytes it came from: if a
/// sender and a subject appear in the same map, they really are stored
/// together.
fn cmd_find(path: &str, term: &str, limit: usize) {
    let mm = map(path);
    let needle = record::anchor_needle();
    let want: Vec<u8> = term.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let mut shown = 0usize;

    for o in block::find_all(&mm) {
        if shown >= limit {
            return;
        }
        let Some(b) = block::parse(&mm, o) else { continue };
        // Cheap reject: skip the whole block before walking its records.
        if memchr::memmem::find(&b.data, &want).is_none() {
            continue;
        }
        for r in records(&b.data, &needle) {
            if shown >= limit {
                return;
            }
            if memchr::memmem::find(r.span, &want).is_none() {
                continue;
            }
            shown += 1;
            let m = schema::build_bounded(&b.data, r.anchor, r.end, r.back);
            println!("\n=== block 0x{o:08x}  anchor +{}  span {} bytes ===", r.anchor, r.span.len());
            print!("{}", m.dump());
        }
    }
    if shown == 0 {
        println!("no records contain {term:?}");
    }
}

/// Parse the whole store into a SQLite database with a full-text index.
fn cmd_db(path: &str, db_path: &str) {
    let mm = map(path);
    let needle = record::anchor_needle();
    let offs = block::find_all(&mm);
    println!("{} blocks -> {db_path}", offs.len());

    for suffix in ["", "-wal", "-shm"] {
        let _ = std::fs::remove_file(format!("{db_path}{suffix}"));
    }
    let mut db = rusqlite::Connection::open(db_path).expect("open db");
    db.execute_batch(
        "PRAGMA journal_mode=WAL;
         CREATE TABLE messages (
             id           INTEGER PRIMARY KEY,
             block        INTEGER,   -- file offset of the source block
             sender       TEXT,
             sender_name  TEXT,
             recipients   TEXT,      -- comma-separated; ordering is not stored
             subject      TEXT,
             message_id   TEXT,
             body         TEXT,      -- plain text, tags stripped
             html         TEXT,      -- original HTML, when the store has it
             body_words   INTEGER,
             html_bytes   INTEGER,
             -- 'full' when the store holds the whole message, 'preview' when it
             -- holds only Outlook's ~255-character cache of it. Most messages
             -- are preview-only: that is the format, not a parse failure.
             body_kind    TEXT,
             sent_unix    INTEGER,   -- earliest .NET tick in the record span
             sent_utc     TEXT,
             -- 1 when the subject came from another record in the same
             -- conversation, because this record stores none of its own.
             subject_inherited INTEGER
         );
         CREATE INDEX messages_sent ON messages(sent_unix);
         CREATE INDEX messages_sender ON messages(sender);
         CREATE VIRTUAL TABLE messages_fts USING fts5(
             sender, sender_name, recipients, subject, body,
             content='messages', content_rowid='id', tokenize='porter unicode61'
         );",
    )
    .expect("schema");

    let mut blocks_ok = 0usize;
    let mut best: std::collections::HashMap<String, record::Record> = Default::default();
    // `Topic` is a conversation-level field, so a record can legitimately hold
    // no subject of its own while its thread has one. These map each thread to
    // its known subject, and each message identity to its threads.
    let mut convo_subject: std::collections::HashMap<String, String> = Default::default();
    let mut convo_of: std::collections::HashMap<String, Vec<String>> = Default::default();

    for &o in &offs {
        let Some(b) = block::parse(&mm, o) else { continue };
        blocks_ok += 1;

        for loc in records(&b.data, &needle) {
            let mut r = record::parse(o, &b.data, loc.anchor);
            let m = schema::build_bounded(&b.data, loc.anchor, loc.end, loc.back);

            // The named map is authoritative for every field it covers: it
            // assigns slots by their position in the run sequence and checks
            // each against the type the protocol schema says it holds.
            // `record::parse` supplies only what is not a string run -- the
            // HTML body -- plus the send time, read here from the span.
            r.sent_unix = record::read_time(loc.span);
            // Take the map's value where it has one, but keep what
            // `record::parse` found otherwise -- the two paths locate fields
            // differently, and the shape-based path still covers records the
            // map's stricter type checks reject.
            if let Some(v) = m.get(schema::Key::SenderAddress) {
                r.sender = Some(v.to_string());
            }
            if let Some(v) = m.get(schema::Key::SenderName) {
                r.sender_name = Some(v.to_string());
            }
            if let Some(v) = m.get(schema::Key::InternetMessageId) {
                r.message_id = Some(v.to_string());
            }
            // The subject is the exception: the map is the only path that
            // requires the Topic/NormalizedSubject duplicate, and the
            // shape-based fallback supplies attachment paths instead of
            // subjects, so an empty map result must win.
            r.subject = m.get(schema::Key::NormalizedSubject).map(str::to_string);
            r.recipients = m
                .all(schema::Key::Recipient)
                .iter()
                .filter(|t| Some(**t) != r.sender.as_deref())
                .map(|t| t.to_string())
                .collect();
            if r.body.split_whitespace().count() < 3 {
                if let Some(v) = m.get(schema::Key::Preview) {
                    r.body = v.to_string();
                }
            }

            // Built from every raw record, not the deduplicated set: a revision
            // that loses the merge can still be the only one carrying the
            // thread's subject.
            let convo_ids: Vec<String> =
                m.all(schema::Key::ConversationId).iter().map(|s| s.to_string()).collect();

            // A record with neither a sender nor readable text is a stub.
            if r.sender.is_none() && r.body.split_whitespace().count() < 5 {
                continue;
            }

            // Identity is sender + send time: the only fields present on
            // essentially every record. `InternetMessageId` is deliberately
            // excluded -- the store reuses one across a conversation, so keying
            // on it merges distinct messages, and pairing it with anything else
            // splits the revisions of one. See SPEC.md 4.7.
            let key = format!("{:?}|{:?}", r.sender, r.sent_unix);
            for id in &convo_ids {
                if let Some(sub) = &r.subject {
                    convo_subject.entry(id.clone()).or_insert_with(|| sub.clone());
                }
            }
            let slot = convo_of.entry(key.clone()).or_default();
            for id in convo_ids {
                if !slot.contains(&id) {
                    slot.push(id);
                }
            }

            match best.get_mut(&key) {
                None => {
                    best.insert(key, r);
                }
                // Merge field by field rather than keeping one whole record.
                // Revisions are not uniformly complete -- one carries the
                // subject, another the full HTML body -- so choosing a single
                // "best" record discards fields recovered from a sibling.
                Some(prev) => merge(prev, r),
            }
        }
    }

    // Back-fill subjects from the conversation. Measured over the store, 90.9 %
    // of *records* lacking a subject share a thread identifier with one that
    // has it; most of those merge into messages that already recovered a
    // subject, leaving 219 messages genuinely fixed by this pass.
    let mut backfilled = 0usize;
    for (key, rec) in best.iter_mut() {
        if rec.subject.is_some() {
            continue;
        }
        let Some(ids) = convo_of.get(key) else { continue };
        if let Some(sub) = ids.iter().find_map(|i| convo_subject.get(i)) {
            rec.subject = Some(sub.clone());
            rec.subject_inherited = true;
            backfilled += 1;
        }
    }
    println!("  {backfilled} subjects recovered from conversation threads");

    // A display name equal to the subject is the subject. Extraction rejects
    // this within a record, but a merged message can take its name from one
    // revision and its subject from another, so the check runs again here.
    for r in best.values_mut() {
        if r.sender_name.is_some() && r.sender_name == r.subject {
            r.sender_name = None;
        }
    }

    let stored = best.len();
    let tx = db.transaction().expect("tx");
    {
        let mut ins = tx
            .prepare(
                "INSERT INTO messages
                   (block,sender,sender_name,recipients,subject,message_id,body,
                    html,body_words,html_bytes,body_kind,sent_unix,sent_utc,
                    subject_inherited)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,
                         datetime(?12,'unixepoch'),?13)",
            )
            .expect("prepare");

        for r in best.values() {
            ins.execute(rusqlite::params![
                r.offset as i64,
                r.sender,
                r.sender_name,
                (!r.recipients.is_empty()).then(|| r.recipients.join(", ")),
                r.subject,
                r.message_id,
                r.body,
                r.html,
                r.body.split_whitespace().count() as i64,
                r.html.as_ref().map(|h| h.len() as i64),
                if r.html.is_some() { "full" } else { "preview" },
                r.sent_unix,
                r.subject_inherited as i64,
            ])
            .expect("insert");
        }
    }
    tx.commit().expect("commit");

    db.execute_batch(
        "INSERT INTO messages_fts(rowid,sender,sender_name,recipients,subject,body)
           SELECT id,sender,sender_name,recipients,subject,body FROM messages;
         INSERT INTO messages_fts(messages_fts) VALUES('optimize');
         VACUUM;",
    )
    .expect("index");

    println!("\n{blocks_ok}/{} blocks verified, {stored} messages stored", offs.len());
    for (label, sql) in [
        ("sender     ", "sender IS NOT NULL"),
        ("date       ", "sent_unix IS NOT NULL"),
        ("sender name", "sender_name IS NOT NULL"),
        ("subject    ", "subject IS NOT NULL"),
        ("message-id ", "message_id IS NOT NULL"),
        ("body       ", "body_words > 3"),
        ("full HTML  ", "body_kind = 'full'"),
    ] {
        let n: i64 = db
            .query_row(&format!("SELECT count(*) FROM messages WHERE {sql}"), [], |r| r.get(0))
            .unwrap_or(0);
        println!("  {label} {n:>6}  {:>5.1}%", n as f64 * 100.0 / stored as f64);
    }
}

/// Combine a later revision of a message into the copy already held.
fn merge(prev: &mut record::Record, r: record::Record) {
    if prev.subject.is_none() {
        prev.subject = r.subject;
    }
    if prev.sender_name.is_none() {
        prev.sender_name = r.sender_name;
    }
    if prev.message_id.is_none() {
        prev.message_id = r.message_id;
    }
    if r.recipients.len() > prev.recipients.len() {
        prev.recipients = r.recipients;
    }
    let better_html = match (&prev.html, &r.html) {
        (None, Some(_)) => true,
        (Some(a), Some(b)) => b.len() > a.len(),
        _ => false,
    };
    if better_html {
        prev.html = r.html;
    }
    if r.body.len() > prev.body.len() {
        prev.body = r.body;
    }
}

const USAGE: &str = "\
hxprobe — parse HxStore.hxd, the New Outlook for Mac message store

usage:
  hxprobe blocks <file>              verify every block, report coverage
  hxprobe db     <file> [out.db]     build a SQLite database (default mail.db)
  hxprobe map    <file> [n]          dump the field map for n records (0 = stats)
  hxprobe find   <file> <term> [n]   show records whose text contains <term>

Work on a snapshot, not the live store: Outlook holds HxStore.lock and
rewrites the file while it runs.";

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }
    let num = |i: usize, d: usize| args.get(i).and_then(|s| s.parse().ok()).unwrap_or(d);

    match args[1].as_str() {
        "blocks" => cmd_blocks(&args[2]),
        "db" => cmd_db(&args[2], args.get(3).map(String::as_str).unwrap_or("mail.db")),
        "map" => cmd_map(&args[2], num(3, 4)),
        "find" => match args.get(3) {
            Some(term) => cmd_find(&args[2], term, num(4, 4)),
            None => {
                eprintln!("find needs a search term\n\n{USAGE}");
                std::process::exit(2);
            }
        },
        other => {
            eprintln!("unknown command {other:?}\n\n{USAGE}");
            std::process::exit(2);
        }
    }
}
