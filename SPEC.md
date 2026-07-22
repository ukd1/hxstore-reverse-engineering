# HxStore.hxd, file format specification

Format of the message store used by **New Outlook for Mac** (`Nostromo`,
version `i`). Reverse-engineered from a live profile and cross-checked against
the shipping implementation in `HxCore.framework`.

No public specification exists. Everything below is either read directly out of
the binary's own code or verified against a real store; each claim is labelled
with how it was established.

For the story of how this was worked out (including the parts I got wrong
first), see the [write-up](https://securized.dev/hxstore-reverse-engineering).

* **Verified**, checked against a live 56 MB store (13,116 blocks).
* **From binary**, read out of `HxCore.framework` (arm64) disassembly.
* **Inferred**, consistent with observation, not independently confirmed.

Reference store used for all counts:
58,720,256 bytes, Outlook 16.107.1, macOS 15, three Exchange/ActiveSync
accounts.

---

## 1. Overview

`HxStore.hxd` is a **paged, append-oriented key–value block store**. It is not
an ESE/JET database, not MAPI, and not encrypted. Message content is held in
independently compressed, CRC-protected blocks.

Two layers matter:

1. **File header**, 48+ bytes: magic, version, page size, region offsets.
2. **Blocks**, a 40-byte header (two CRCs, a magic, lengths) followed by an
   LZ4-compressed payload. Records live inside the decompressed payload.

The architecture is confirmed by the C++ symbols still present in the binary:
`Hx::Storage::KeyValueStore` with `KeyValueBlock`, `KeyDirectory`, `StoreFile`,
`Blob`, `BufferReader`/`BufferWriter`, `Transaction`, `StoreVersionMismatch`.

Location:

```
~/Library/Group Containers/UBF8T346G9.Office/Outlook/
  Outlook 15 Profiles/Main Profile/HxStore.hxd
```

The live file **mutates while Outlook runs** (observed shrinking mid-session).
`HxStore.lock` is held by the app. Always work on a snapshot copy.

---

## 2. File header

**From binary.** The header initialiser is at `0xda5804` / `0xda5910`. It
allocates a `0x4b0`-byte object, zeroes `0x3f8` bytes, then writes:

```asm
str  x8,  [x25, #0x10]        ; "Nostromo"
mov  w8,  #0x69
str  w8,  [x25, #0x18]        ; version 'i'
mov  w8,  #0x3
strb w8,  [x25, #0x40b]
memset_pattern16(x25+0xac, <deadbeef…>, 0x24)
mov  w8,  #0x2000000
str  x8,  [x25, #0x478]       ; 32 MiB cap
```

The object is persisted with its first `0x10` bytes elided, so

> **`file_offset = object_offset − 0x10`**

**Verified.** The guard pattern proves the mapping: `object+0xac` → `file+0x9c`,
and `file+0x9c` holds exactly `0x24` bytes of repeating `ef be ad de`.

### Layout

| File | Type | Reference value | Meaning |
|---|---|---|---|
| `+0x00` | char[8] | `Nostromo` | magic |
| `+0x08` | u64 | `0x69` (`'i'`) | format version |
| `+0x10` | u64 | `0x2798600` | live data size (41,518,592) |
| `+0x18` | u64 | `0x5000` | directory / region size |
| `+0x20` | u64 | `0xc5000` | start of block area |
| `+0x28` | u64 | `0x12c0` | |
| `+0x30` | u64 | `0xcb20019a` | checksum-like |
| `+0x38` | u64 | `0x1000` | **page size (4096)** |
| `+0x40` | u64 | `0x3000` | |
| `+0x48` | u64 | `0xfff1` | default (`w9 = #0xfff1` at `0xf4a514`) |
| `+0x50` | u64 | `0xdeadbeef` | guard |
| `+0x58` | u64 | `0x25000` | |
| `+0x9c` | u8[0x24] | `deadbeef` ×9 | guard pattern |
| `+0x3fb` | u8 | `3` | (object `+0x40b`) |
| `+0x468` | u64 | `0x2000000` | 32 MiB cap (object `+0x478`) |

Every size field is a clean multiple of the 4096-byte page size.

### Version bytes

A parser should treat the byte as a gate: accept what it has reasoned about,
warn on anything else, and rely on the per-block checksums (§3.2) to catch a
genuine format change. `hxprobe` accepts `'i'` and `'h'`; `'h'` is accepted on
the reasoning below but has **not** been tested against a Windows store.

`NostromoH`, `NostromoH9` and `NostromoI` all appear as literals in
`HxCore`. The Mac build under test writes `'i'` (lowercase, `0x69`); Windows
Mail samples in the literature show `'h'`. Treat the version byte as a
compatibility gate.

---

## 3. Block container

This is the layer that makes the format tractable: every block is
**self-validating**, so a parser never has to guess.

### 3.1 Header (40 bytes)

**From binary**, writer at `0xf44670`, validator at `0xf4552c`.

```
+0x00  u32  crc32(block[0x04 .. 0x20])          header checksum
+0x04  u32  crc32(block[0x08 .. 0x28 + len])    payload checksum
+0x08  u64  magic  0x5d0245643b706a05
+0x10  u32  type            observed 8 (message data) and 16
+0x14  u32  payload_len     compressed bytes, starting at +0x28
+0x18  u32  inflated_len    exact decompressed size
+0x1c  u32  4               constant in every observed block
+0x20  u64  (covered by the header CRC, purpose unresolved)
+0x28  ...  LZ4-compressed payload
```

Total block size on disk: `0x28 + payload_len`.

The magic is stored little-endian, so on disk it reads
`05 6a 70 3b 64 45 02 5d`.

### 3.2 Checksums

Standard **CRC-32 (IEEE, zlib polynomial `0xEDB88320`)**. `HxCore` calls
libz's `_crc32` (35 call sites).

Note the asymmetry, which is easy to get wrong:

* the **header** CRC covers `[0x04, 0x20)`, 28 bytes, excluding itself;
* the **payload** CRC starts at `0x08` (i.e. from the magic, *not* from the
  payload) and runs to the end of the block.

**Verified:** header CRC matches on **13,107 / 13,116** blocks (99.93 %);
payload CRC on **13,104 / 13,116** (99.91 %). The handful of failures are
stale/partially-rewritten regions, as expected in an append-oriented store.

### 3.3 Locating blocks

There is no usable directory for the `.hxd` (see §6). Blocks are found by
scanning for the 8-byte magic and subtracting 8. This is safe **because** of
the two checksums: a false positive cannot survive validation.

### 3.4 Payload codec

LZ4 block format, standard sequence layout:

```
[token] [literal-length varint] [literals] [dist_lo] [dist_hi] [match-length varint]

literal_count = token >> 4        ; 15 -> add 255-continuation varint
match_length  = (token & 0x0F) + 4 ; 15 -> add 255-continuation varint
distance      = u16 little-endian, counted back from the output end
```

Minimum match is 4. Overlapping copies are legal and common (run-length
expansion), so matches must be copied one byte at a time. The final sequence of
a block is literals only.

The `+4` minimum and the 255-continuation varints match the length decoder in
`HxCore` at x86-64 `0x136c9de`.

**Decode requirement.** `inflated_len` is authoritative: a correct decode lands
on it exactly. A decoder should treat any other outcome, short output, a
distance pointing before the window, leftover input, as a failed block rather
than returning partial output. LZ4 itself has no checksum, so a wrong start
decodes silently into plausible garbage; the container CRCs are what make this
safe.

**Verified:** **13,105 / 13,116** payloads (99.92 %) inflate to exactly the
declared length. Requiring all three checks together, header CRC, payload CRC
and exact inflated length, **13,103 / 13,116 (99.90 %)** blocks pass, yielding
**221.4 MB** of decompressed data from a 56 MB file. Full parse of the
reference store: **0.73 s, 61 MB peak RSS** (memory-mapped, never read into an
owned buffer).

---

## 4. Records

Records live inside a decompressed block payload. A single block commonly holds
several. The reference store yields **16,721 `IPM.Note` records** across
**4,873 blocks**, deduplicating to **7,193 distinct messages** (§4.7).

### 4.1 Anchor

Each record is anchored by its `ItemClass` string, stored as **UTF-16LE**:

```
IPM.Note                        mail
IPM.Schedule.Meeting.Request    meeting request
IPM.Appointment                 calendar item
```

Only `IPM.Note` has been exercised in depth.

**From binary / verified.** In raw (uncompressed) regions the anchor is
preceded by an ItemClass property header `40 58 00 08 02 00`, present before
1,084 of 1,769 raw anchors and occurring only 1,102 times in the entire file:
a 98 %-specific marker. Inside decompressed payloads the anchor is located by
searching for the UTF-16LE string.

### 4.2 Field layout

Metadata is a run of **NUL-terminated UTF-16LE strings** in a dependable order
around the anchor:

```
   -84   sender address        "no-reply@example-mailer.net"
   -44   sender display name   "Security Verification"
     0   ItemClass             "IPM.Note"              <- anchor
   +18   Message-ID            "<9e0ce892-…@example-esp.net>"
  +116   body preview          "Your Verification Code Hi Alice, …"
  +580   subject               "Your Verification Code"
  +626   subject (again)       "Your Verification Code"
```

**Verified** across thousands of records. Absolute offsets shift with field
lengths, sender addresses were observed at −64, −66, −68, −72, −74, −76, −80
and −82, so a parser must **walk the string sequence**, not index fixed
positions. The *order* is what is dependable.

Two consequences worth stating explicitly:

* **The sender pair is the last address before the anchor**, followed by the
  display name.
* **The subject is written twice**, back to back, after the body preview. That
  duplication is the most reliable way to tell a subject from a preview or a
  stray fragment. Long subjects are split across a pair of runs, so compare on
  a prefix rather than requiring an exact repeat.

### 4.3 String encoding caveats

A field run is UTF-16LE but is **not** restricted to ASCII. Breaking a run at
the first non-ASCII code unit truncates real data, `Zoé - Réseau` becomes
`é - Réseau`. Decode BMP characters (`U+00A0`–`U+D7FF`, `U+E000`–`U+FFFD`) as
part of the same run.

Conversely, HTML bodies are stored as **single-byte UTF-8 text**, not UTF-16.
Reading them as one `char` per byte and then re-joining the UTF-8 sequences
recovers the original; truncating each `char` to a byte corrupts anything
non-ASCII.

### 4.4 Body, two tiers, and a hard preview cap

**This is the single most important thing to understand about the store, and
the easiest to mistake for a decoder bug.**

`HxStore.hxd` is a *cache*, not an archive. It keeps the full body for only a
minority of messages and a short preview for the rest; the full text is fetched
from the server on demand.

Measured over all **16,721** records in the reference store:

| Tier | Count | Stored as |
|---|---|---|
| Full body | **1,877** (11 %) | single-byte UTF-8 HTML after the anchor |
| Preview only | **14,844** (89 %) | one UTF-16LE field, **capped at ~255 characters** |

The preview cap is sharp: bucketing the longest UTF-16LE field after each
anchor puts **8,773 records in the 200–250 character band**, with observed
plain-text bodies clustering at 245–252 characters and nothing beyond 292
(the outliers include a subject prefix in the same field).

So a body of ~42 words is not truncation, **that is the entire content the
file contains for that message**. Recovering more requires Graph/EWS, not a
better parser.

A preview-only record looks like this (offsets relative to the anchor):

```
   -60  support@example.com
   -30  Ari (AI agent)
    +0  IPM.Note
   +18  <28dd5a6a-9a64-458f-a3aa-64daa540b067>        internet Message-ID
   +96  <7ef249b7-…@example-esp.net>                        second ID
  +194  "Hi Alice, Yes. One workspace can …"     body preview (246 chars)
  +688  "Re: Multiple brands under one account"       subject
  +764  "Multiple brands under one account"           subject, base form
```

Note there is **no HTML anywhere** in that record, the `+194` UTF-16LE field
is the whole body. A parser that only looks for `<html`/`<div` will report an
empty body for 89 % of the store.

### 4.5 HTML bodies

The HTML part begins at the first of `<html`, `<!DOCTYPE`, `<body`, `<div` or
`<table` after the anchor.

Its end is **not** explicitly delimited. Where present, `</body>` or `</html>`
terminates it. Otherwise the text simply stops and the following field's bytes
begin, so a parser must bound the scan, or it will splice the next record into
the body.

**Bodies are stored in two shapes**, both complete:

| Shape | Count | Ends with |
|---|---|---|
| Full document | 923 / 1,108 | `</body>` or `</html>` |
| Fragment | 185 / 1,108 | an unbalanced `</div>` chain |

The fragment form is a reply/compose body stored **without** its wrapping
`<html>`/`<body>` element, so the `<div>`s are unbalanced by construction. It is
*not* truncation: **zero** fragments end inside a tag, and their text ends at
natural message boundaries (signature blocks, unsubscribe footers, legal
disclaimers). A consumer that wants well-formed markup should wrap the fragment
rather than treat it as damaged.

**Field boundary.** The byte immediately after the final `>` is the first byte
of the next field, not markup, typically the `A` of a UTF-16LE `Anonymous`
enum. A parser must strip it, or every fragment body acquires a stray trailing
character.

---

### 4.6 Timestamps, .NET ticks *(Verified)*

Message times are stored as **64-bit little-endian .NET ticks**: 100-nanosecond
units since `0001-01-01T00:00:00Z`. This is *not* Windows `FILETIME`, whose
epoch is 1601, decoding a store value as FILETIME yields a date in the 3600s,
which is why scanning for FILETIME ranges never found these fields.

The encoding was fixed by the Osa protocol logs (§6.1), which emit one field in
both raw and rendered form in the same response:

```xml
<ReceivedOrRenewTime d="c">639201014590000000</ReceivedOrRenewTime>
<LastDeliveryTime>2026-07-19T23:44:19.000Z</LastDeliveryTime>
```

`639201014590000000 / 10⁷` seconds after year 1 is exactly
`2026-07-19T23:44:19Z`, a known-plaintext pair, not an inference.

```
unix = (ticks - 621355968000000000) / 10^7
```

#### Selecting the send time

Fixed displacements do **not** work. Fields are variable length, so a byte
offset only catches records whose preceding fields happen to be the expected
size: `+255` and `+703`, the two sharpest displacements, together reach just
4,420 of 16,721 records.

Scanning the whole record span instead finds a tick in **100 %** of records.
The problem is then choosing which one, a record holds 1–12 distinct ticks
(2 and 4 are the common cases): send, delivery, last-modified and sync stamps.
Ordinal position is not stable either (no ordinal is both universal and
near-unique).

What *is* stable is ordering. A message is sent before it is delivered,
modified or synced, so the **earliest tick in the record span** is the send
time. Scored on how values distribute, a send time is near-unique per message,
a sync stamp collapses onto the few moments Outlook last ran:

| Rule | Records | Distinct | Top-value share |
|---|---|---|---|
| **min (earliest)** | 16,721 | 4,682 | **0.40 %** |
| max (latest) | 16,721 | 3,137 | 4.43 % |

The tick window (2015-01-01 … 2027-01-01) is what makes a bare 8-byte scan
safe: arbitrary binary almost never lands inside a 12-year range.

**Verified:** 100 % date coverage, no future dates, and a distribution weighted
to recent mail (4,783 in 2026, thinning to 8 in 2015).

---

### 4.7 Record identity and deduplication *(Verified)*

The store rewrites a message on every sync, so one message appears many times.
The revisions are **not uniformly complete**, one carries the subject, another
the full HTML body, which drives two rules:

* **Identity is `sender + send time`.** These are the only fields present on
  essentially every record, and they yield **7,687 distinct messages** in the
  reference store. `InternetMessageId` is deliberately *not* part of the key:
  the store reuses one across a conversation, so keying on it merges distinct
  messages, and pairing it with anything else splits the revisions of one.
* **Merge field by field, don't pick a winner.** Selecting a single "best"
  record discards fields recovered from a sibling. Merging lifted subject
  coverage from 5,065 to 6,144, exactly the measured ceiling.

### Distance bounds

Records sit back to back, so an unbounded search reads the neighbour's fields
and pairs one message's sender with another's subject. Two bounds prevent it:

| Field | Bound |
|---|---|
| Sender address | ≤ 320 bytes from the anchor |
| Display name | ≤ 200 bytes from its address |

A display name equal to the subject is the subject, and is dropped, both at
extraction and again after merging, since a merged message can take its name
from one revision and its subject from another.

---

## 5. What the format is *not*

Ruled out by direct testing, recorded so the work is not repeated:

| Hypothesis | Test | Result |
|---|---|---|
| ESE / JET Blue (Windows Mail `store.vol`) | search magic `EF CD AB 89` | **0** occurrences in 1.1 GB |
| MAPI property tags | search `0037001f`, `0e090013`, … as ASCII + LE/BE u32 | chance-level noise only |
| zlib / gzip / raw DEFLATE | 1,332 candidate offsets inflated | **0** produced text |
| LZNT1 | chunk-header scan | no match |
| Encrypted | Shannon entropy, 24 samples | **6.3–6.9** bits/byte (encryption ≈ 7.99) |
| RFC822 headers stored | count `Message-ID:`, `DKIM-Signature:` | **0** and **0** |

`HxCore` *does* import zlib (`_uncompress`, `_deflate`, `compress2`), but no
zlib stream in the store inflates, it is used elsewhere in the app. Only
`_crc32` is used against store data.

Full email headers are **not persisted**, matching Chivers' finding for Windows
Mail: *"Full email headers are not stored in either the database or in other
files."* Sender, recipients, subject and Message-ID are stored as discrete
fields; everything else is gone.

---

## 6. KeyDirectory (sidecar stores)

**From binary**, directory-walk loop at `0x98c5f4`. Entries are walked from
`dir_buffer + 0x30`:

```
+0x00  u8   type        must be 'R' (0x52)
+0x01  u8   flags       bit0 = tombstone; skipped, bumps a dead counter
+0x02  u16  key_len
+0x04  u16  val_len
+0x06  u16  extra_len
+0x08  ...  payload
```

Entry stride: `8 + key_len + val_len + extra_len`.

**Important caveat:** **no `'R'` chain exists anywhere in `HxStore.hxd`.** An
exhaustive scan found zero valid chains. That routine (`0x98c454`) is the
`KeyValueStore` opener used for the *smaller sidecar stores* (`.ctr` and
similar). The `.hxd` goes through the StorageEngine path at `0xda5804`.

This layout is documented because it is solid and useful for the sidecars, not
because it applies to the message store.

---

### 6.1 The Osa logs, Microsoft's own field list *(Verified)*

`Outlook 15 Profiles/Main Profile/Osa/OutlookServiceApiLogs_*/` holds ~41,800
gzipped XML request/response logs of the live ActiveSync/OutlookService
protocol. They are plain gzip, `gzcat` reads them directly.

Message **content** is redacted (`<Subject>pii:140D5125557024F9</Subject>`), but
the **field names, their order, their types and their enum values are in the
clear**. Because these are the objects HxStore persists, the logs act as an
authoritative schema for the record layout, the equivalent of what earlier
`store.vol` work had to derive experimentally.

```sh
gzcat 'Osa/OutlookServiceApiLogs_*/osa{*}_*_sync.GetMessage.*.res.xmlgz'
```

A `GetMessage` response opens its `MessageHeader` in this order:

```
ConversationId · ConversationIndex_Substrate · ImmConversationId · MessageId ·
ImmId · Topic · NormalizedSubject · Preview · LastDeliveryTime ·
LastModifiedTime · ReceivedOrRenewTime · SentTime · ScheduleStatus ·
SenderDisplayNamesCollection{Name,Address,Type,IsMe} · From{…} · ChangeKey ·
MessageBodyChangeKey · UnReadCount · Restricted · ItemClass_Substrate · Size ·
Importance · HasAttachment · IsRepliedMail · IsForwardedMail · ViewId ·
OutlookId · ThreadId · TailoredType · InternetMessageId · IsOnlyToMe ·
SortTime · DisplayTime · IsPinned · MailboxGuid · …
```

Two findings this settles directly:

* **`Topic` and `NormalizedSubject` are adjacent and near-identical**, sitting
  immediately before `Preview`. This is the source of the "subject stored twice,
  back to back, just before the body preview" pattern in §4.2, it is two
  distinct protocol fields, not a storage quirk.
* **Long base64 runs among the text fields are
  `AntispamSafeLinksMsgData_Substrate`** (SafeLinks scan metadata, base64 JSON,
  so always starting `eyJ`), and long unbroken hex runs are `ImmId` /
  `ImmConversationId` / `ChangeKey`. These are legitimate fields, *not* decode
  errors, but they are machine payloads and must be kept out of the subject and
  display-name columns.

The logs also supply the timestamp crib that solves §4.6, and remain the best
target list for the unmapped fields in §7 (`FocusedClassification`,
`HasAttachment`, `IsRead`, folder identity).

**Caveat:** retention is roughly 10 days, and values are hashed, the logs are
useful as a *schema* oracle only, never as a content source.

---

### 6.2 Reading a record as a named map *(Verified)*

Because §6.1 supplies the field *order*, a record can be read as a named
key → value map instead of by guessing what each string means.

What does **not** work is indexing by byte offset. Fields are NUL-terminated
and variable length, so every position depends on the length of everything
before it. Measured across 16,721 records, a sender address appears at `-74`,
`-82` and `+1174`; only two displacements are stable at all (`0` = `IPM.Note`,
`+18` = `InternetMessageId`, and only in ~60 % of records).

What does work is indexing by **position in the run sequence**. Reading the
UTF-16LE runs in order around the anchor gives a consistent layout:

```
 [-2] SenderAddress       no-reply@example-mailer.net
 [-1] SenderName          Security Verification
 [ 0] ItemClass           IPM.Note                 <- anchor
 [+1] InternetMessageId   <9e0ce892-...@example-esp.net>
 [+2] Preview             "Your Verification Code Hi Alice, ..."
 [+3] NormalizedSubject   "Your Verification Code"
 [+4] Topic               "Your Verification Code"   <- the repeat
```

Each slot is claimed by sequence *and* confirmed against the type the schema
says it holds; a slot failing its check is left empty rather than filled with
whatever sat there. Coverage over the 16,721 raw records:

| Key | Records | Share |
|---|---|---|
| `ItemClass` | 16,665 | 99.7 % |
| `Preview` | 16,279 | 97.4 % |
| `SenderAddress` | 16,313 | 97.6 % |
| `NormalizedSubject` | 14,792 | 88.5 % |
| `Recipient` | 13,051 | 78.1 % |
| `SenderName` | 11,501 | 68.8 % |
| `InternetMessageId` | 9,907 | 59.2 % |

Three rules earn their place:

* **Search both sides of the anchor.** Layout B (§4.2) puts the whole header
  *before* the anchor, so a record can have no runs after it at all.
* **Bound the distance** (§4.7). Records sit back to back; an unbounded search
  reads the neighbour's fields.
* **Reject binary at extraction.** Every second byte of a UTF-16LE ASCII string
  is zero, but arbitrary binary also yields valid BMP code units, which decode
  without error into runs like `=꼄딂aĀ`. This store's text is Latin, so a run
  with ≥20 % of its characters outside Latin/punctuation is binary and is
  dropped before it can become a field. Doing this once at the source removed
  the same check duplicated across every downstream classifier.

#### Matching the subject pair

`Topic` is the conversation subject with reply/forward prefixes stripped;
`NormalizedSubject` keeps them. The pair therefore reads
`Re: Acme: Quarterly Report` / `Acme: Quarterly Report`, near-identical but
not equal. Comparing after stripping `Re:` / `Fw:` / `Fwd:` / `Aw:` / `Tr:`
raised subject recovery from 51.1 % to 75.3 %; relaxing an over-strict prose
filter and searching both sides took it to 85.9 %.

Two further cases were found by testing the *absence* of a subject rather than
assuming it. For every record with no recovered subject, dumping every string
in its span and filtering to runs that read as subject text showed 30 % still
held an unclaimed candidate:

* **`Topic` appended to a packed run.** It is frequently concatenated onto the
  last entry of the recipient-name collection with no separator, so the record
  holds `Re: Quarterly Report` in one place and
  `Alice Turner<sep>Bob NakamuraQuarterly Report` in another. Neither an
  equality nor a whole-run comparison fires; comparing against the run's
  *suffix* does.
* **Unpaired subjects.** Some records store the subject once, with no `Topic`
  sibling. A lone run is only trusted when it sits where the schema puts the
  subject (0 … 2500 bytes after the anchor), reads as several words, and is not
  a display name. Without the position bound this fallback returns body
  previews and the neighbouring record's fields.

Together these took record-level recovery to **88.5 %** and message-level to
**85.7 %**. Re-running the same test leaves 23 records holding a candidate that
is not confidently claimable, all of them genuine non-subjects: a run beginning
mid-word, an auto-reply body, and packed quick-reply collections.

#### `Topic` is conversation-level *(Verified)*

The Osa field order places `Topic` beside `ConversationId` and `ImmThreadId`,
which is the clue to the remaining gap: the store writes the subject once per
**conversation**, not once per message. Measured over the store, **90.9 %** of
records holding no subject of their own share a thread identifier with a record
that has one.

Thread identifiers are the long hex and GUID runs (`ImmConversationId`,
`ChangeKey`) rejected as display text everywhere else, which is exactly what
makes them reliable as keys. A second pass maps each thread to its known
subject and back-fills, taking message-level coverage to **88.7 %**. Rows
filled this way are flagged `subject_inherited`, so a consumer can tell them
apart from subjects read out of the record itself.

Of the 813 messages that still have none, **809 carry no thread identifier at
all**, so there is nothing to inherit through. They hold senders, timestamps
and full bodies; the subject is simply not present anywhere in their span.

#### Packed multi-value fields

Some slots hold a list, not a scalar. The recipient display-name collection is
one run with the per-entry length prefixes left in place, decoding as
off-script characters:

```
Alice Turner ᰀ Bob Nakamura ᐀ Carol Diaz
```

Splitting on any off-script character recovers the entries in order. A run that
splits into several parts is a name list, never a subject.

---

## 7. Open questions

* **`+0x20` in the block header**, covered by the header CRC, purpose unknown.
* **Block `type`**, 8 dominates; 16 appears rarely. Semantics unconfirmed.
* **Subject ceiling.** 88.7 % of message identities yield a subject, after
  back-filling from the conversation (§6.2). Of the 813 without one, 809 carry
  no thread identifier either, so there is no route to a subject for them. The
  records concerned are a distinct variant (8, 25 KB spans holding `Anonymous`,
  a GUID, SafeLinks payloads, addresses and attachment paths). Established by
  exhaustive test rather than sampling.
* **HTML bodies**, only ~23 % of messages carry one; the rest hold Outlook's
  ~255-character `Preview` and fetch the body from the server on demand (§4.4).
* **Recipients**, recovered from addresses inside the record span; the
  authoritative recipient table has not been located, so ordering and the
  To/Cc/Bcc distinction are unavailable.
* **Folder / read state / flags**, not mapped. The Osa logs (§6.1) enumerate
  the fields Outlook syncs (`FocusedClassification`, `HasAttachment`, `IsRead`,
  `ConversationId`, …), which is the target list for further work.
* **Page-level structure**, the page size (4096) and region offsets are known,
  but how pages are allocated and reclaimed is not.

---

## 8. Minimal parser

```
1.  Verify file[0..8] == "Nostromo".
2.  Read page size at file+0x38 (4096).
3.  Scan for the 8-byte block magic 05 6a 70 3b 64 45 02 5d; block = hit - 8.
4.  For each block:
      a. crc32(block[0x04..0x20])  ==  u32 at block+0x00   else skip
      b. len      = u32 at block+0x14
         inflated = u32 at block+0x18
      c. crc32(block[0x08 .. 0x28+len]) == u32 at block+0x04  else skip
      d. LZ4-decompress block[0x28 .. 0x28+len]; require exactly `inflated`
         bytes out, else skip.
5.  In each payload, find every UTF-16LE "IPM.Note".
6.  Per anchor, walk NUL-terminated UTF-16LE runs:
      - last address before the anchor  -> sender
      - the run following it            -> display name
      - "<…@…>" after the anchor        -> Message-ID
      - the duplicated run after the
        body preview                    -> subject
      - first HTML marker after anchor  -> body (bound the scan!)
7.  Deduplicate on Message-ID; the same message is written repeatedly as it
    syncs, and copies differ in completeness, keep the fullest.
```

Steps 4a–4d are what make this a parser rather than a heuristic: a wrong offset
fails loudly instead of producing convincing nonsense.

---

## 9. Stability

The store format is tied to the Outlook build (`16.107.1` here). Microsoft ships
Outlook monthly and has no compatibility obligation to third-party readers. The
magic and version byte are the guard: refuse anything other than `Nostromo` +
`i` rather than mis-parsing a newer layout.

Because the file mutates while Outlook runs, any parse must be done on a
snapshot.
