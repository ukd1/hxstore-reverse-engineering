//! Folder objects and membership in verified HxStore block payloads.
//!
//! The serialized envelopes, repeated object keys and typed references are
//! checked before accepting a link. Names in message text are never evidence
//! of membership. See SPEC.md, "Folder objects and membership".

use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug)]
pub struct Folder {
    pub id: u64,
    pub account_id: u64,
    /// Conflicting names in cached revisions are left unresolved.
    pub name: Option<String>,
    pub block: usize,
}

#[derive(Default)]
pub struct Index {
    pub folders: BTreeMap<u64, Folder>,
    owners: BTreeMap<u64, BTreeSet<u64>>,
    members: BTreeMap<u64, BTreeSet<u64>>,
}

fn u64_at(data: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        data.get(at..at.checked_add(8)?)?.try_into().ok()?,
    ))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        data.get(at..at.checked_add(4)?)?.try_into().ok()?,
    ))
}

fn signature(class: u16) -> [u8; 10] {
    let mut s = [0; 10];
    s[..2].copy_from_slice(&class.to_le_bytes());
    s
}

/// `[05 00, tag:u16, length:u32, 00 00, object...]`.
/// Length includes the ten-byte envelope, not its enclosing transaction.
fn envelopes(data: &[u8], tag: u16, class: u16) -> Vec<(usize, &[u8])> {
    let tag_bytes = tag.to_le_bytes();
    let needle = [5, 0, tag_bytes[0], tag_bytes[1]];
    memchr::memmem::find_iter(data, &needle)
        .filter_map(|at| {
            let len = u32_at(data, at + 4)? as usize;
            if len < 56 || data.get(at + 8..at + 10)? != [0, 0] {
                return None;
            }
            let start = at + 10;
            let object = data.get(start..at.checked_add(len)?)?;
            object
                .starts_with(&signature(class))
                .then_some((start, object))
        })
        .collect()
}

/// A typed local reference repeats its own key and its owning object's key.
fn reference(data: &[u8], class: u16, kinds: &[u32]) -> Option<(u64, u64)> {
    if !data.starts_with(&signature(class)) || !kinds.contains(&u32_at(data, 18)?) {
        return None;
    }
    let id = u64_at(data, 10)?;
    let owner = u64_at(data, 22)?;
    (id != 0
        && id <= i64::MAX as u64
        && owner <= i64::MAX as u64
        && Some(id) == u64_at(data, 30)
        && Some(owner) == u64_at(data, 38))
    .then_some((id, owner))
}

fn message_key(data: &[u8], class: u16) -> Option<u64> {
    if !data.starts_with(&signature(class)) {
        return None;
    }
    let id = u64_at(data, 10)?;
    (id != 0 && Some(id) == u64_at(data, 30) && Some(id) == u64_at(data, 38)).then_some(id)
}

/// Folder payloads end in the display name, following a binary sort key.
/// Decode UTF-16 (including surrogate pairs), rather than scanning ASCII runs.
fn trailing_name(data: &[u8]) -> Option<String> {
    if !data.ends_with(&[0, 0]) {
        return None;
    }
    let end = data.len().checked_sub(2)?;
    let mut start = end;
    while start >= 2 {
        let u = u16::from_le_bytes([data[start - 2], data[start - 1]]);
        if u < 32 || u == 127 {
            break;
        }
        start -= 2;
        if end - start > 1024 {
            return None;
        }
    }
    // The sort key has a single-byte NUL terminator before the UTF-16 name.
    if start == end || start == 0 || data[start - 1] != 0 {
        return None;
    }
    let units: Vec<_> = data[start..end]
        .chunks_exact(2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .collect();
    let name = String::from_utf16(&units).ok()?;
    (!name.chars().any(char::is_control)).then_some(name)
}

impl Index {
    /// First pass: gather the catalog and message/view membership references.
    pub fn observe(&mut self, block: usize, data: &[u8]) {
        for (_, object) in envelopes(data, 0x04c2, 0x004d) {
            let Some((id, account_id)) = reference(object, 0x004d, &[2, 0x02ac]) else {
                continue;
            };
            let Some(name) = trailing_name(object) else {
                continue;
            };
            let folder = self.folders.entry(id).or_insert_with(|| Folder {
                id,
                account_id,
                name: Some(name.clone()),
                block,
            });
            if folder.name.as_ref() != Some(&name) || folder.account_id != account_id {
                folder.name = None;
            }
            // Two copies of the folder's view-collection reference. Require
            // each reference's duplicated key, not an arbitrary nearby u64.
            for at in [160, 360] {
                if object.get(at..at + 10) != Some(signature(4).as_slice()) {
                    continue;
                }
                if let Some(owner) = u64_at(object, at + 10) {
                    if owner != 0 && Some(owner) == u64_at(object, at + 38) {
                        self.owners.entry(owner).or_default().insert(id);
                    }
                }
            }
        }
        for (_, object) in envelopes(data, 0x02c8, 0x00bf) {
            let Some(key) = message_key(object, 0x00bf) else {
                continue;
            };
            // This observed layout ends with a 51-byte immutable message ID
            // (00 09 00 2e 00 ...), then the local folder key. Require that
            // framing so a different metadata subtype cannot supply a link.
            let Some(tail) = object.len().checked_sub(59) else {
                continue;
            };
            if object.get(tail..tail + 5) != Some(&[0, 9, 0, 46, 0]) {
                continue;
            }
            if let Some(folder) = u64_at(object, object.len() - 8) {
                self.members.entry(key).or_default().insert(folder);
            }
        }
    }

    /// Resolve IPM.Note anchor positions to observed folders within this block.
    pub fn links(&self, data: &[u8], needle: &[u8]) -> BTreeMap<usize, BTreeSet<u64>> {
        let mut links = BTreeMap::new();
        for (start, object) in envelopes(data, 0x0430, 0x004f) {
            let Some((_, owner)) = reference(object, 0x004f, &[4]) else {
                continue;
            };
            if let Some(folders) = self.owners.get(&owner) {
                self.link_single_anchor(&mut links, start, object, needle, folders);
            }
        }
        for (start, object) in envelopes(data, 0x0740, 0x00ca) {
            let Some(key) = message_key(object, 0x00ca) else {
                continue;
            };
            if let Some(folders) = self.members.get(&key) {
                self.link_single_anchor(&mut links, start, object, needle, folders);
            }
        }
        // Expanded message objects embedded in transaction wrappers include
        // a full typed folder reference at +408. Unlike compact objects, they
        // do not have an individual length envelope. Bound the header by the
        // next message object, and only take its first ItemClass anchor.
        let starts: Vec<_> = memchr::memmem::find_iter(data, &signature(0x00ca))
            .filter(|&p| message_key(&data[p..], 0x00ca).is_some())
            .collect();
        let boundaries: BTreeSet<_> = [
            (0x04c2, 0x004d),
            (0x0430, 0x004f),
            (0x0740, 0x00ca),
            (0x02c8, 0x00bf),
        ]
        .into_iter()
        .flat_map(|(tag, class)| envelopes(data, tag, class).into_iter().map(|(p, _)| p - 10))
        .collect();
        for (i, &start) in starts.iter().enumerate() {
            let next_envelope = boundaries
                .range((std::ops::Bound::Excluded(start), std::ops::Bound::Unbounded))
                .next()
                .copied()
                .unwrap_or(data.len());
            let end = starts
                .get(i + 1)
                .copied()
                .unwrap_or(data.len())
                .min(next_envelope)
                .min(start.saturating_add(4096));
            let Some(object) = data.get(start..end) else {
                continue;
            };
            let Some(field) = object.get(408..) else {
                continue;
            };
            let Some((id, account)) = reference(field, 0x004d, &[2, 0x02ac]) else {
                continue;
            };
            if !self
                .folders
                .get(&id)
                .is_some_and(|f| f.account_id == account)
            {
                continue;
            }
            let Some(rel) = memchr::memmem::find(object, needle) else {
                continue;
            };
            if rel < 454 {
                continue;
            }
            links
                .entry(start + rel)
                .or_insert_with(BTreeSet::new)
                .insert(id);
        }
        links
    }

    fn link_single_anchor(
        &self,
        links: &mut BTreeMap<usize, BTreeSet<u64>>,
        start: usize,
        object: &[u8],
        needle: &[u8],
        folders: &BTreeSet<u64>,
    ) {
        let mut anchors = memchr::memmem::find_iter(object, needle);
        let Some(anchor) = anchors.next() else { return };
        if anchors.next().is_some() {
            return;
        }
        let known: BTreeSet<_> = folders
            .iter()
            .copied()
            .filter(|id| self.folders.contains_key(id))
            .collect();
        if !known.is_empty() {
            links.entry(start + anchor).or_default().extend(known);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put64(b: &mut [u8], p: usize, v: u64) {
        b[p..p + 8].copy_from_slice(&v.to_le_bytes());
    }
    fn object(class: u16, id: u64, kind: u32, owner: u64, size: usize) -> Vec<u8> {
        let mut b = vec![0; size];
        b[..10].copy_from_slice(&signature(class));
        put64(&mut b, 10, id);
        b[18..22].copy_from_slice(&kind.to_le_bytes());
        put64(&mut b, 22, owner);
        put64(&mut b, 30, id);
        put64(&mut b, 38, owner);
        b
    }
    fn envelope(tag: u16, b: &[u8]) -> Vec<u8> {
        let mut v = vec![5, 0];
        v.extend(tag.to_le_bytes());
        v.extend(((b.len() + 10) as u32).to_le_bytes());
        v.extend([0, 0]);
        v.extend(b);
        v
    }
    fn folder(id: u64, owner: u64, name: &str) -> Vec<u8> {
        let mut b = object(0x4d, id, 2, 7, 420);
        b[160..170].copy_from_slice(&signature(4));
        put64(&mut b, 170, owner);
        put64(&mut b, 198, owner);
        b.extend([1, 1, 1, 1, 0]);
        b.extend(name.encode_utf16().chain([0]).flat_map(u16::to_le_bytes));
        envelope(0x4c2, &b)
    }
    fn note() -> Vec<u8> {
        "IPM.Note"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    #[test]
    fn unicode_catalog_and_bounded_view_membership() {
        let mut index = Index::default();
        index.observe(123, &folder(50, 60, "Équipe 🚀"));
        assert_eq!(index.folders[&50].name.as_deref(), Some("Équipe 🚀"));
        let mut view = object(0x4f, 70, 4, 60, 100);
        view.extend(note());
        let mut data = envelope(0x430, &view);
        let end = data.len();
        data.extend(note());
        let links = index.links(&data, &note());
        assert_eq!(links.get(&110), Some(&BTreeSet::from([50])));
        assert!(!links.contains_key(&end));
    }

    #[test]
    fn reject_truncation_bad_keys_and_unknown_owners() {
        let good = folder(50, 60, "Inbox");
        for cut in 0..good.len() {
            let mut index = Index::default();
            index.observe(0, &good[..cut]);
            assert!(index.folders.is_empty());
        }
        let mut bad = good.clone();
        bad[40] ^= 1;
        let mut index = Index::default();
        index.observe(0, &bad);
        assert!(index.folders.is_empty());
        index.observe(0, &good);
        let mut view = object(0x4f, 70, 4, 999, 100);
        view.extend(note());
        assert!(index.links(&envelope(0x430, &view), &note()).is_empty());
    }

    #[test]
    fn metadata_links_preserve_moves_and_require_id_framing() {
        let mut index = Index::default();
        index.observe(0, &folder(50, 60, "Inbox"));
        index.observe(0, &folder(51, 61, "Archive"));
        for fid in [50, 51] {
            let mut metadata = object(0xbf, 70, 0, 70, 120);
            metadata[61..66].copy_from_slice(&[0, 9, 0, 46, 0]);
            put64(&mut metadata, 112, fid);
            index.observe(0, &envelope(0x2c8, &metadata));
        }
        let mut msg = object(0xca, 70, 0, 70, 100);
        msg.extend(note());
        assert_eq!(
            index.links(&envelope(0x740, &msg), &note())[&110],
            BTreeSet::from([50, 51])
        );
        let mut bad = object(0xbf, 71, 0, 71, 120);
        put64(&mut bad, 112, 50);
        index.observe(0, &envelope(0x2c8, &bad));
        assert!(!index.members.contains_key(&71));
    }

    #[test]
    fn expanded_headers_validate_account_and_do_not_cross_next_object() {
        let mut index = Index::default();
        index.observe(0, &folder(50, 60, "Inbox"));
        let mut expanded = object(0xca, 70, 0, 70, 500);
        expanded[408..454].copy_from_slice(&object(0x4d, 50, 2, 7, 46));
        let mut next = object(0xca, 71, 0, 71, 500);
        next.extend(note());
        let mut combined = expanded.clone();
        combined.extend(next);
        assert!(index.links(&combined, &note()).is_empty());
        expanded.extend(note());
        assert_eq!(index.links(&expanded, &note())[&500], BTreeSet::from([50]));
        put64(&mut expanded, 430, 99);
        put64(&mut expanded, 446, 99);
        assert!(index.links(&expanded, &note()).is_empty());
    }

    #[test]
    fn embedded_header_cannot_claim_a_neighboring_folder_view() {
        let mut index = Index::default();
        index.observe(0, &folder(50, 60, "Inbox"));
        index.observe(0, &folder(51, 61, "Archive"));
        let mut expanded = object(0xca, 70, 0, 70, 500);
        expanded[408..454].copy_from_slice(&object(0x4d, 50, 2, 7, 46));
        let mut view = object(0x4f, 71, 4, 61, 100);
        view.extend(note());
        expanded.extend(envelope(0x430, &view));
        assert_eq!(index.links(&expanded, &note())[&610], BTreeSet::from([51]));
    }

    #[test]
    fn conflicting_folder_names_are_not_silently_overwritten() {
        let mut index = Index::default();
        index.observe(0, &folder(50, 60, "Old"));
        index.observe(1, &folder(50, 60, "New"));
        assert!(index.folders[&50].name.is_none());
    }
}
