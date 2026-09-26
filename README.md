# hxprobe

A parser for `HxStore.hxd`, the message store used by **New Outlook** (macOS,
and the Windows Mail / Outlook "Hx" engine). No public specification exists, no
documented API, and since New Outlook dropped the AppleScript data model, no
supported way to read your own mail off disk.

This turns one into a SQLite database with full-text search, in about a second.

**[Read the write-up](https://securized.dev/hxstore-reverse-engineering)** for how the format was worked out: the block
header and CRC ranges read out of `HxCore.framework`, the Osa protocol logs
that supply the field schema, and the .NET tick timestamps that took three
attempts to find.

**[SPEC.md](SPEC.md)** is the format itself: file header, block container, CRC
ranges, LZ4 framing, record layout, and the parts still unmapped.

## Results

56 MB reference store, Outlook 16.107.1, macOS 15:

| | |
|---|---|
| Blocks verified | **13,103 / 13,116 (99.90 %)** |
| Decompressed | 221 MB |
| Messages extracted | 7,193 |
| Parse time | 1.2 s, 67 MB peak RSS |

| Field | Coverage |
|---|---|
| Send time | **100 %** |
| Sender | 99.8 % |
| Body / preview | 98.5 % |
| Display name | 91.2 % |
| Subject | 88.7 % |
| Full HTML body | 23.5 % |

The last two are format limits rather than parser limits. About 11 % of
messages store no subject string and belong to no conversation that has one, and Outlook keeps only a
~255-character preview for most mail, fetching the real body from the server
when you open the message. The write-up covers
[how the subject ceiling was established](https://securized.dev/hxstore-reverse-engineering#subjects-and-testing-your-own-assumptions),
including the two attempts where I had it wrong.

## Usage

```sh
cargo build --release

hxprobe blocks <file>              # verify every block, report coverage
hxprobe db     <file> [out.db]     # build a SQLite database with FTS5
hxprobe map    <file> [n]          # dump the named field map for n records
hxprobe find   <file> <term> [n]   # show records whose text contains <term>
```

### Snapshot first

Outlook holds `HxStore.lock` and rewrites the file while it runs. I watched a
store shrink mid-session. Work on a copy:

```sh
STORE=~/"Library/Group Containers/UBF8T346G9.Office/Outlook/Outlook 15 Profiles/Main Profile/HxStore.hxd"
cp "$STORE" snapshot.hxd
hxprobe db snapshot.hxd mail.db
```

The file is memory-mapped and never read into an owned buffer, so peak memory
tracks the working set rather than file size. This matters: these stores reach
a gigabyte.

### Searching

```sh
sqlite3 mail.db "SELECT sent_utc, sender, subject
                 FROM messages
                 WHERE id IN (SELECT rowid FROM messages_fts
                              WHERE messages_fts MATCH 'invoice')
                 ORDER BY sent_unix DESC LIMIT 20;"
```

### Folders

The export includes `folders` (local folder/account keys, display name and
source block) and `message_folders` (message-to-folder links). List the catalog,
including folders with no recovered messages:

```sql
SELECT f.id, f.account_id, f.name, count(mf.message_id) AS messages
FROM folders AS f
LEFT JOIN message_folders AS mf ON mf.folder_id = f.id
GROUP BY f.id
ORDER BY messages DESC, f.name;
```

Read messages associated with a particular folder, using its ID from the list:

```sql
SELECT m.sent_utc, m.sender, m.subject, m.body
FROM messages AS m
JOIN message_folders AS mf ON mf.message_id = m.id
WHERE mf.folder_id = 12345  -- replace with the folder's local ID
ORDER BY m.sent_unix DESC;
```

Membership describes **observed cached records**, not guaranteed current server
location. Merged revisions can contribute multiple folders; unknown membership
has no link. The catalog can include virtual, calendar and internal folders, and
identically named folders have separate IDs. Zero recovered messages does not
mean the server folder is empty. Conflicting cached names produce a NULL name.
Folder extraction is currently verified against a macOS version `i` snapshot;
unsupported layouts remain unlinked. See SPEC.md §6.3 for the byte-level evidence.

## Windows stores

Untested. The macOS build writes version byte `'i'`; `HxCore` also carries
`NostromoH` / `NostromoH9` / `NostromoI` literals, and Windows Mail samples in
the literature show `'h'`, so the container should be the same.

`hxprobe` accepts `'i'` and `'h'`, and warns on any other version rather than
guessing. Because every block carries two CRC-32s, a format mismatch fails
loudly instead of producing wrong data. If you have a Windows store, I'd be
interested in the result.

## Scope and limits

* Read-only. Nothing here writes to a store.
* Verified against three Exchange/ActiveSync accounts on macOS.
* The format drifts with Outlook updates. The block container has been stable;
  record layout may not be.
* Server-side-only mail is absent. This is a local cache, not an archive.

## License

MIT. Independent interoperability research based on observation of a file
format and readable log files. Ships no Microsoft code.
