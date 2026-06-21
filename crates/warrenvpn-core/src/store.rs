//! The configuration shadow store.
//!
//! This is the highest-risk component of the daemon: the file written here is the
//! ONLY copy OpenVPN is ever launched against, and OpenVPN runs as root. The store
//! therefore:
//!
//! * classifies the configuration safe/unsafe **itself** (via `ovpn-config`),
//!   never trusting any external verdict;
//! * writes the shadow copy **atomically** and **without following symlinks**
//!   (`O_NOFOLLOW`, `O_EXCL` temp file + `rename`), with restrictive permissions;
//! * keys everything on an immutable random id (not the mutable display name), so a
//!   display name can never influence a filesystem path.
//!
//! Ownership/permissions: shadow files are created `0600`. In production the daemon
//! runs as root, so the file is root-owned and unreadable by other users. (Group
//! `warrenvpn` read access, if ever wanted, is intentionally NOT granted here.)

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use ovpn_config::Config;

use crate::util::random_id;

/// The shadow config filename inside each per-config directory.
const CONFIG_FILE: &str = "config.ovpn";
/// The metadata filename inside each per-config directory.
const META_FILE: &str = "meta";

/// The placeholder substituted for security-sensitive inline blocks.
const SANITIZED_PLACEHOLDER: &str = "[Security-related line(s) omitted]";

/// Inline blocks whose contents are stripped by [`ConfigStore::sanitized`].
const SECRET_BLOCKS: &[&str] = &[
    "key",
    "tls-auth",
    "tls-crypt",
    "tls-crypt-v2",
    "pkcs12",
    "secret",
];

/// A configuration that has been installed into the store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledConfig {
    /// Immutable random id (also the on-disk directory name).
    pub id: String,
    /// User-facing display name.
    pub name: String,
    /// Whether the daemon classified it as safe (no admin needed to connect).
    pub safe: bool,
    /// Absolute path to the shadow configuration file.
    pub path: PathBuf,
}

/// True if `id` is a well-formed config id: exactly 32 lowercase hex characters,
/// as produced by [`random_id`]. Rejecting anything else at the read boundary
/// prevents a caller-supplied id (`..`, `/`, an absolute path) from escaping the
/// store via `Path::join`.
pub fn is_valid_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// A per-user (or shared) shadow store rooted at `base`.
pub struct ConfigStore {
    base: PathBuf,
}

impl ConfigStore {
    /// Create a store rooted at `base` (e.g. `/var/lib/warrenvpn/users/<uid>`).
    pub fn new(base: impl Into<PathBuf>) -> Self {
        ConfigStore { base: base.into() }
    }

    /// Install a configuration from raw `contents`, classifying it server-side.
    pub fn install_contents(
        &self,
        contents: &str,
        display_name: &str,
    ) -> io::Result<InstalledConfig> {
        let safe = Config::parse(contents).is_safe();
        let id = random_id()?;
        let dir = self.base.join(&id);
        // 0700: only the owner (root in production) may traverse.
        fs::create_dir_all(&self.base)?;
        create_dir_secure(&dir)?;

        let config_path = dir.join(CONFIG_FILE);
        write_atomic(&config_path, contents.as_bytes(), 0o600)?;

        let meta = format!("safe={}\nname={}\n", safe, encode_meta_value(display_name));
        write_atomic(&dir.join(META_FILE), meta.as_bytes(), 0o600)?;

        Ok(InstalledConfig {
            id,
            name: display_name.to_string(),
            safe,
            path: config_path,
        })
    }

    /// Install a configuration from a file on disk.
    pub fn install_path(&self, source: &Path, display_name: &str) -> io::Result<InstalledConfig> {
        let mut contents = String::new();
        // O_NOFOLLOW on the source: refuse to read through a symlink.
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(source)?
            .read_to_string(&mut contents)?;
        self.install_contents(&contents, display_name)
    }

    /// All installed configurations, in arbitrary order.
    pub fn list(&self) -> io::Result<Vec<InstalledConfig>> {
        let mut out = Vec::new();
        let entries = match fs::read_dir(&self.base) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e),
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let id = entry.file_name().to_string_lossy().into_owned();
            if let Some(cfg) = self.get(&id)? {
                out.push(cfg);
            }
        }
        Ok(out)
    }

    /// Look up a configuration by id. Returns `Ok(None)` for a malformed id.
    pub fn get(&self, id: &str) -> io::Result<Option<InstalledConfig>> {
        if !is_valid_id(id) {
            return Ok(None);
        }
        let dir = self.base.join(id);
        let config_path = dir.join(CONFIG_FILE);
        if !config_path.exists() {
            return Ok(None);
        }
        let (safe, name) = read_meta(&dir.join(META_FILE)).unwrap_or((false, id.to_string()));
        Ok(Some(InstalledConfig {
            id: id.to_string(),
            name,
            safe,
            path: config_path,
        }))
    }

    /// Remove an installed configuration (its shadow copy + metadata). Idempotent:
    /// removing a missing config succeeds. Rejects a malformed id.
    pub fn remove(&self, id: &str) -> io::Result<()> {
        if !is_valid_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid configuration id",
            ));
        }
        match fs::remove_dir_all(self.base.join(id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// The configuration with inline secret material removed, for display/logging.
    pub fn sanitized(&self, id: &str) -> io::Result<String> {
        if !is_valid_id(id) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid configuration id",
            ));
        }
        let dir = self.base.join(id);
        let mut contents = String::new();
        File::open(dir.join(CONFIG_FILE))?.read_to_string(&mut contents)?;
        Ok(sanitize_config(&contents))
    }
}

/// Remove the contents of inline secret blocks (`<key>…</key>`, etc.), leaving the
/// tags and a placeholder so the structure is still visible.
pub fn sanitize_config(contents: &str) -> String {
    let mut out = String::with_capacity(contents.len());
    let mut skipping: Option<String> = None;

    for line in contents.lines() {
        let trimmed = line.trim();
        if let Some(close) = &skipping {
            if trimmed == close.as_str() {
                out.push_str(line);
                out.push('\n');
                skipping = None;
            }
            // else: drop the secret line.
            continue;
        }

        out.push_str(line);
        out.push('\n');

        if let Some(tag) = trimmed
            .strip_prefix('<')
            .and_then(|s| s.strip_suffix('>'))
        {
            if SECRET_BLOCKS.contains(&tag) {
                out.push_str(SANITIZED_PLACEHOLDER);
                out.push('\n');
                skipping = Some(format!("</{tag}>"));
            }
        }
    }
    out
}

/// Create a directory with mode 0700, failing if it already exists.
fn create_dir_secure(dir: &Path) -> io::Result<()> {
    fs::DirBuilder::new().mode(0o700).create(dir)
}

/// Atomically write `contents` to `path` with the given mode, without following a
/// symlink at the final path component. Writes a uniquely-named temp file in the
/// same directory (`O_CREAT|O_EXCL|O_NOFOLLOW`), fsyncs it, then renames into place.
fn write_atomic(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "path has no parent directory")
    })?;
    let suffix = random_id()?;
    let tmp = dir.join(format!(
        ".{}.tmp.{suffix}",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true) // O_CREAT | O_EXCL
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(contents)?;
    f.sync_all()?;
    drop(f);

    match fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn encode_meta_value(v: &str) -> String {
    // Keep meta single-line: strip CR/LF from the display name.
    v.replace(['\r', '\n'], " ")
}

fn read_meta(path: &Path) -> Option<(bool, String)> {
    let mut s = String::new();
    File::open(path).ok()?.read_to_string(&mut s).ok()?;
    let mut safe = false;
    let mut name = String::new();
    for line in s.lines() {
        if let Some(v) = line.strip_prefix("safe=") {
            safe = v == "true";
        } else if let Some(v) = line.strip_prefix("name=") {
            name = v.to_string();
        }
    }
    Some((safe, name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_base() -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("warrenvpn-store-test-{}", random_id().unwrap()));
        p
    }

    const SAFE_CFG: &str = "client\ndev tun\nproto udp\nremote vpn.example.com 1194\nca ca.crt\nauth-user-pass\n";
    const UNSAFE_CFG: &str = "client\ndev tun\nup /home/user/evil.sh\n";

    #[test]
    fn installs_and_classifies_safe_config() {
        let store = ConfigStore::new(tmp_base());
        let c = store.install_contents(SAFE_CFG, "Work VPN").unwrap();
        assert!(c.safe);
        assert_eq!(c.name, "Work VPN");
        assert!(c.path.exists());
        let written = fs::read_to_string(&c.path).unwrap();
        assert_eq!(written, SAFE_CFG);
    }

    #[test]
    fn installs_and_flags_unsafe_config() {
        let store = ConfigStore::new(tmp_base());
        let c = store.install_contents(UNSAFE_CFG, "Sketchy").unwrap();
        assert!(!c.safe);
    }

    #[test]
    fn shadow_file_is_not_world_or_group_readable() {
        use std::os::unix::fs::PermissionsExt;
        let store = ConfigStore::new(tmp_base());
        let c = store.install_contents(SAFE_CFG, "x").unwrap();
        let mode = fs::metadata(&c.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "shadow config must be 0600, got {mode:o}");
    }

    #[test]
    fn list_and_get_round_trip() {
        let store = ConfigStore::new(tmp_base());
        let a = store.install_contents(SAFE_CFG, "A").unwrap();
        let b = store.install_contents(UNSAFE_CFG, "B").unwrap();
        assert_ne!(a.id, b.id);

        let listed = store.list().unwrap();
        assert_eq!(listed.len(), 2);

        let got = store.get(&a.id).unwrap().unwrap();
        assert_eq!(got.name, "A");
        assert!(got.safe);
        assert!(store.get("does-not-exist").unwrap().is_none());
    }

    #[test]
    fn install_then_remove() {
        let store = ConfigStore::new(tmp_base());
        let c = store.install_contents(SAFE_CFG, "Temp").unwrap();
        assert!(store.get(&c.id).unwrap().is_some());
        store.remove(&c.id).unwrap();
        assert!(store.get(&c.id).unwrap().is_none());
        // Idempotent + id-validated.
        store.remove(&c.id).unwrap();
        assert!(store.remove("../etc").is_err());
    }

    #[test]
    fn rejects_malformed_ids() {
        assert!(is_valid_id("06960c9f4cef7a97c42e3c2e62c54c06"));
        assert!(!is_valid_id("../0/06960c9f4cef7a97c42e3c2e62c54c06"));
        assert!(!is_valid_id("/etc/passwd"));
        assert!(!is_valid_id(".."));
        assert!(!is_valid_id("06960C9F4CEF7A97C42E3C2E62C54C06")); // uppercase
        assert!(!is_valid_id("short"));
        assert!(!is_valid_id(""));

        let store = ConfigStore::new(tmp_base());
        // Path-traversal attempts never resolve to a real file.
        assert!(store.get("../../etc/passwd").unwrap().is_none());
        assert!(store.sanitized("..").is_err());
    }

    #[test]
    fn list_on_missing_base_is_empty() {
        let store = ConfigStore::new(tmp_base());
        assert!(store.list().unwrap().is_empty());
    }

    #[test]
    fn sanitize_strips_secret_blocks_but_keeps_ca() {
        let cfg = "client\n<ca>\nPUBLIC CERT\n</ca>\n<key>\nSECRET KEY DATA\n</key>\nverb 3\n";
        let s = sanitize_config(cfg);
        assert!(s.contains("PUBLIC CERT"), "ca should be kept");
        assert!(!s.contains("SECRET KEY DATA"), "key must be stripped");
        assert!(s.contains("<key>") && s.contains("</key>"));
        assert!(s.contains(SANITIZED_PLACEHOLDER));
    }

    #[test]
    fn sanitized_via_store() {
        let store = ConfigStore::new(tmp_base());
        let cfg = "client\n<tls-crypt>\nSECRET\n</tls-crypt>\n";
        let c = store.install_contents(cfg, "x").unwrap();
        let s = store.sanitized(&c.id).unwrap();
        assert!(!s.contains("SECRET"));
    }
}
