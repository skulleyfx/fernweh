//! Per-host images: `<directory>/<hostname-lowercase>.png`, written by the admin
//! tooling, read here. Only a small, well-formed PNG is ever served: the
//! signature and IHDR are checked, the size is capped, and nothing else about
//! the file is trusted. Clients re-verify before decoding.

use std::collections::HashMap;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use tracing::warn;

use crate::util::sha256;

/// Largest file accepted.
pub const MAX_BYTES: u64 = 128 * 1024;
/// Accepted edge length range (inclusive), both dimensions.
pub const MIN_EDGE: u32 = 16;
pub const MAX_EDGE: u32 = 256;

const PNG_SIGNATURE: [u8; 8] = [0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];

#[derive(Debug, PartialEq, Eq)]
pub struct Image {
    /// Lower-case hex SHA-256 of `bytes`.
    pub sha256: String,
    pub bytes: Vec<u8>,
}

/// Why a file was refused (logged once per file version).
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    TooLarge,
    NotPng,
    Dimensions(u32, u32),
}

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Refused::TooLarge => write!(f, "larger than {MAX_BYTES} bytes"),
            Refused::NotPng => write!(f, "not a PNG with a valid IHDR"),
            Refused::Dimensions(w, h) => write!(f, "{w}x{h} is outside {MIN_EDGE}..{MAX_EDGE}"),
        }
    }
}

/// Signature, IHDR chunk header and dimensions only.
pub fn validate_png(bytes: &[u8]) -> Result<(), Refused> {
    if bytes.len() as u64 > MAX_BYTES {
        return Err(Refused::TooLarge);
    }
    if bytes.len() < 24 || bytes[..8] != PNG_SIGNATURE || bytes[8..12] != [0, 0, 0, 13] || &bytes[12..16] != b"IHDR" {
        return Err(Refused::NotPng);
    }
    let w = u32::from_be_bytes(bytes[16..20].try_into().unwrap());
    let h = u32::from_be_bytes(bytes[20..24].try_into().unwrap());
    if !(MIN_EDGE..=MAX_EDGE).contains(&w) || !(MIN_EDGE..=MAX_EDGE).contains(&h) {
        return Err(Refused::Dimensions(w, h));
    }
    Ok(())
}

/// (mtime, len, inode, ctime sec, ctime nsec): a replaced or rewritten file changes at least one.
type Stamp = (SystemTime, u64, u64, i64, i64);

pub struct Thumbs {
    dir: PathBuf,
    /// host label -> stamp it was read at and the verdict (None = refused/unreadable).
    cache: Mutex<HashMap<String, (Stamp, Option<Arc<Image>>)>>,
}

impl Thumbs {
    pub fn new(dir: PathBuf) -> Thumbs {
        Thumbs { dir, cache: Mutex::new(HashMap::new()) }
    }

    /// The image of `fqdn` (first label, lower-cased), if a valid one exists.
    /// The file is opened with O_NOFOLLOW and judged by the opened handle's
    /// fstat (no lstat/open race); its contents are read again only when the
    /// stamp (mtime, length, inode, ctime) changes.
    pub fn image(&self, fqdn: &str) -> Option<Arc<Image>> {
        let label = fqdn.split('.').next().unwrap_or("").to_ascii_lowercase();
        if label.is_empty() || !label.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-') {
            return None;
        }
        let path = self.dir.join(format!("{label}.png"));
        let mut file = match std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(&path) {
            Ok(f) => f,
            Err(_) => {
                self.cache.lock().unwrap().remove(&label);
                return None;
            }
        };
        let meta = match file.metadata() {
            Ok(m) if m.file_type().is_file() => m,
            _ => {
                self.cache.lock().unwrap().remove(&label);
                return None;
            }
        };
        let stamp: Stamp =
            (meta.modified().unwrap_or(SystemTime::UNIX_EPOCH), meta.len(), meta.ino(), meta.ctime(), meta.ctime_nsec());
        if let Some((s, img)) = self.cache.lock().unwrap().get(&label) {
            if *s == stamp {
                return img.clone();
            }
        }
        let img = match Self::load(&mut file, meta.len()) {
            Ok(i) => Some(Arc::new(i)),
            Err(e) => {
                warn!("host image {label}.png ignored: {e}");
                None
            }
        };
        self.cache.lock().unwrap().insert(label, (stamp, img.clone()));
        img
    }

    fn load(file: &mut std::fs::File, len: u64) -> Result<Image, String> {
        if len > MAX_BYTES {
            return Err(Refused::TooLarge.to_string());
        }
        let mut bytes = Vec::with_capacity(len as usize);
        file.take(MAX_BYTES + 1).read_to_end(&mut bytes).map_err(|e| e.to_string())?;
        validate_png(&bytes).map_err(|e| e.to_string())?;
        Ok(Image { sha256: hex::encode(sha256(&bytes)), bytes })
    }
}

#[cfg(test)]
pub(crate) fn test_png(w: u32, h: u32, filler: u8) -> Vec<u8> {
    let mut v = PNG_SIGNATURE.to_vec();
    v.extend([0, 0, 0, 13]);
    v.extend(b"IHDR");
    v.extend(w.to_be_bytes());
    v.extend(h.to_be_bytes());
    v.extend([8, 6, 0, 0, 0]);
    v.extend([filler; 4]); // CRC is not checked here; clients decode and verify
    v.extend([0, 0, 0, 0]);
    v.extend(b"IEND");
    v.extend([0xae, 0x42, 0x60, 0x82]);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_rules() {
        assert_eq!(validate_png(&test_png(256, 256, 0)), Ok(()));
        assert_eq!(validate_png(&test_png(16, 16, 0)), Ok(()));
        assert_eq!(validate_png(&test_png(15, 64, 0)), Err(Refused::Dimensions(15, 64)));
        assert_eq!(validate_png(&test_png(64, 257, 0)), Err(Refused::Dimensions(64, 257)));
        assert_eq!(validate_png(b"GIF89a not a png at all, but long enough to read"), Err(Refused::NotPng));
        assert_eq!(validate_png(&PNG_SIGNATURE), Err(Refused::NotPng));
        let mut big = test_png(64, 64, 0);
        big.resize(MAX_BYTES as usize + 1, 0);
        assert_eq!(validate_png(&big), Err(Refused::TooLarge));
        let mut wrong_chunk = test_png(64, 64, 0);
        wrong_chunk[12..16].copy_from_slice(b"IDAT");
        assert_eq!(validate_png(&wrong_chunk), Err(Refused::NotPng));
    }

    fn tmp() -> PathBuf {
        let d = std::env::temp_dir().join(format!("fernweh-thumbs-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn cache_follows_the_file() {
        let d = tmp();
        let t = Thumbs::new(d.clone());
        assert!(t.image("ws1.example.org").is_none());
        let a = test_png(64, 64, 1);
        std::fs::write(d.join("ws1.png"), &a).unwrap();
        let first = t.image("WS1.example.org").unwrap();
        assert_eq!(first.bytes, a);
        assert_eq!(first.sha256, hex::encode(sha256(&a)));
        assert!(Arc::ptr_eq(&first, &t.image("ws1.example.org").unwrap()), "unchanged file is not re-read");
        let b = test_png(64, 64, 2);
        std::thread::sleep(std::time::Duration::from_millis(50)); // same length: only mtime tells
        std::fs::write(d.join("ws1.png"), &b).unwrap();
        let second = t.image("ws1.example.org").unwrap();
        assert_ne!(second.sha256, first.sha256);
        std::fs::write(d.join("ws1.png"), b"not a png").unwrap();
        assert!(t.image("ws1.example.org").is_none());
        std::fs::remove_file(d.join("ws1.png")).unwrap();
        assert!(t.image("ws1.example.org").is_none());
        assert!(t.image("../etc/passwd").is_none());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn a_fifo_is_ignored_without_blocking() {
        let d = tmp();
        let c = std::ffi::CString::new(d.join("ws1.png").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert!(Thumbs::new(d.clone()).image("ws1.example.org").is_none());
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn symlinks_are_not_followed() {
        let d = tmp();
        std::fs::write(d.join("real.dat"), test_png(64, 64, 3)).unwrap();
        std::os::unix::fs::symlink(d.join("real.dat"), d.join("ws1.png")).unwrap();
        assert!(Thumbs::new(d.clone()).image("ws1.example.org").is_none());
        std::fs::remove_dir_all(d).unwrap();
    }
}
