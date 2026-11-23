// SPDX-License-Identifier: MIT

//! Fixed policy location for operator-managed builds (`fixed-policy` feature).
//!
//! A build with this feature never reads [`super::POLICY_FILE_ENV`] or
//! [`super::MANAGED_POLICY_FILE_ENV`]. Every process, however it was started,
//! loads the user layer from `<home>/.config/cua-driver/policy/policy.yaml`
//! and the managed layer from `policy.rego` in the same folder. `<home>` is
//! the account's home directory from the user database, never `$HOME`.
//!
//! Each file is reached through one chain of opens: `<home>`, then `.config`,
//! `cua-driver`, `policy` and the file, each opened relative to the folder
//! before it and refused if it is a symbolic link. The file must be a regular
//! file, and both its policy and its digest come from the bytes read through
//! that one open. So a symbolic link anywhere below `<home>`, or a file or
//! folder swapped in while the driver loads, cannot point it at another file.
//!
//! With `fixed-policy-root-owned`, the account must not be able to change the
//! files either. Checked on the descriptors the chain holds: `cua-driver`,
//! `policy` and both files are owned by root, no folder in the chain is
//! writable by group or others, and the files are writable by no one.
//! `.config` alone may also be owned by the account.
//!
//! A layer whose file is missing, cannot be opened or read this way, fails
//! those checks or does not load is replaced by the built-in locked policy,
//! which allows only tools that neither act on nor read the screen. The
//! driver therefore always starts, and never starts open.

use std::path::{Path, PathBuf};

use super::{
    policy_digest, ConfiguredPolicyLayer, PolicyEngine, PolicySource, RegoPolicy, YamlPolicy,
    MANAGED_POLICY_FILE_ENV,
};

/// Policy folder, relative to the account's home directory.
pub const POLICY_DIR: &str = ".config/cua-driver/policy";
const USER_POLICY_FILE: &str = "policy.yaml";
const MANAGED_POLICY_FILE: &str = "policy.rego";

/// Name under which the built-in policy is hashed, so its digest never equals
/// a policy file's digest even when the bytes match.
const LOCKED_POLICY_NAME: &str = "built-in-locked";
const LOCKED_POLICY: &str = "\
allow:
  tools:
    - health_report
    - get_config
    - check_permissions
    - get_guide
    - list_sessions
    - get_session
    - get_session_state
";

/// Why a layer's fixed file did not load.
#[derive(Debug)]
struct LoadFailure {
    reason: String,
    /// Whether anything was found at the fixed path.
    file_present: bool,
}

impl LoadFailure {
    fn present(reason: String) -> Self {
        Self {
            reason,
            file_present: true,
        }
    }

    fn absent(reason: String) -> Self {
        Self {
            reason,
            file_present: false,
        }
    }
}

/// The layer for `env_name`'s slot: its fixed file, or the built-in locked policy.
pub(super) fn load_layer(env_name: &str) -> ConfiguredPolicyLayer {
    let (layer, file) = if env_name == MANAGED_POLICY_FILE_ENV {
        ("managed", MANAGED_POLICY_FILE)
    } else {
        ("user", USER_POLICY_FILE)
    };
    let loaded = account_home()
        .map_err(LoadFailure::absent)
        .and_then(|home| load_fixed_file(&home, file));
    match loaded {
        Ok(configured) => configured,
        Err(failure) => {
            tracing::warn!(
                "{layer} policy: serving the built-in locked policy: {}",
                failure.reason
            );
            locked_layer(failure)
        }
    }
}

fn load_fixed_file(home: &Path, file: &str) -> Result<ConfiguredPolicyLayer, LoadFailure> {
    let (path, bytes) = read_fixed_file(home, file)?;
    let invalid =
        |error: anyhow::Error| LoadFailure::present(format!("{}: {error:#}", path.display()));
    let text = String::from_utf8(bytes)
        .map_err(|_| LoadFailure::present(format!("{} is not UTF-8", path.display())))?;
    let sha256 = policy_digest([(file, text.as_bytes())]);
    let engine = if file == MANAGED_POLICY_FILE {
        PolicyEngine::Rego(Box::new(
            RegoPolicy::from_source(file, text).map_err(invalid)?,
        ))
    } else {
        PolicyEngine::Yaml(YamlPolicy::from_str(&text).map_err(invalid)?)
    };
    Ok(ConfiguredPolicyLayer {
        engine,
        sha256,
        source: PolicySource::FixedFile,
        configured: true,
    })
}

fn locked_layer(failure: LoadFailure) -> ConfiguredPolicyLayer {
    let policy = YamlPolicy::from_str(LOCKED_POLICY).expect("the built-in locked policy parses");
    ConfiguredPolicyLayer {
        engine: PolicyEngine::Yaml(policy),
        sha256: policy_digest([(LOCKED_POLICY_NAME, LOCKED_POLICY.as_bytes())]),
        source: PolicySource::BuiltInLocked {
            reason: failure.reason,
        },
        configured: failure.file_present,
    }
}

/// Read `<home>/.config/cua-driver/policy/<file>` without following a symbolic
/// link below `<home>`, returning its path (for messages) and its bytes.
#[cfg(unix)]
fn read_fixed_file(home: &Path, file: &str) -> Result<(PathBuf, Vec<u8>), LoadFailure> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut path = home.to_path_buf();
    let mut folder = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(home)
        .map_err(|error| LoadFailure::present(format!("{}: {error}", path.display())))?;
    for (depth, name) in POLICY_DIR.split('/').enumerate() {
        path.push(name);
        let next = open_at(&folder, name, libc::O_DIRECTORY)
            .map_err(|error| open_failure(&folder, name, &path, error))?;
        // `.config` is the account's own folder; the rest belong to root.
        check_owner(
            &next,
            &path,
            Entry::Folder {
                account_may_own: depth == 0,
            },
        )?;
        folder = next;
    }
    path.push(file);
    // O_NONBLOCK: opening a FIFO must not wait for a writer.
    let mut policy = open_at(&folder, file, libc::O_NONBLOCK)
        .map_err(|error| open_failure(&folder, file, &path, error))?;
    let unreadable =
        |error: std::io::Error| LoadFailure::present(format!("{}: {error}", path.display()));
    if !policy.metadata().map_err(unreadable)?.is_file() {
        return Err(LoadFailure::present(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    check_owner(&policy, &path, Entry::File)?;
    let mut bytes = Vec::new();
    policy.read_to_end(&mut bytes).map_err(unreadable)?;
    Ok((path, bytes))
}

#[cfg(not(unix))]
fn read_fixed_file(_home: &Path, _file: &str) -> Result<(PathBuf, Vec<u8>), LoadFailure> {
    Err(LoadFailure::absent(
        "a fixed policy location is supported only on Unix".to_owned(),
    ))
}

#[cfg(not(unix))]
fn account_home() -> Result<PathBuf, String> {
    Ok(PathBuf::new())
}

/// Open `name`, one path component, in `folder` for reading, never following
/// a symbolic link: `openat(2)` with `O_NOFOLLOW` plus `flags`.
#[cfg(unix)]
fn open_at(
    folder: &std::fs::File,
    name: &str,
    flags: libc::c_int,
) -> std::io::Result<std::fs::File> {
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    let name = c_name(name)?;
    let flags = flags | libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // SAFETY: `folder` is an open descriptor and `name` a NUL-terminated
    // string; both outlive the call.
    let fd = unsafe { libc::openat(folder.as_raw_fd(), name.as_ptr(), flags) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` was just opened by this call and nothing else owns it.
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}

#[cfg(unix)]
fn c_name(name: &str) -> std::io::Result<std::ffi::CString> {
    std::ffi::CString::new(name).map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))
}

/// Whether `name` in `folder` is itself a symbolic link (`fstatat(2)` with
/// `AT_SYMLINK_NOFOLLOW`).
#[cfg(unix)]
fn is_symlink_at(folder: &std::fs::File, name: &str) -> bool {
    use std::os::fd::AsRawFd as _;

    let Ok(name) = c_name(name) else {
        return false;
    };
    // SAFETY: `stat` is plain old data that fstatat fills in.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `folder` is an open descriptor, `name` a NUL-terminated string
    // and `stat` a writable buffer; all outlive the call.
    let status = unsafe {
        libc::fstatat(
            folder.as_raw_fd(),
            name.as_ptr(),
            &mut stat,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    status == 0 && stat.st_mode & libc::S_IFMT == libc::S_IFLNK
}

/// Why opening `name` in `folder` (at `path`) failed. `O_NOFOLLOW` refuses a
/// symbolic link with `ELOOP`, but a directory open refuses one with `ENOTDIR`
/// on Linux, so both are checked with `fstatat`.
#[cfg(unix)]
fn open_failure(
    folder: &std::fs::File,
    name: &str,
    path: &Path,
    error: std::io::Error,
) -> LoadFailure {
    match error.raw_os_error() {
        Some(libc::ENOENT) => LoadFailure::absent(format!("{} does not exist", path.display())),
        Some(libc::ELOOP | libc::ENOTDIR) if is_symlink_at(folder, name) => {
            LoadFailure::present(format!("{} is a symbolic link", path.display()))
        }
        _ => LoadFailure::present(format!("{}: {error}", path.display())),
    }
}

#[cfg(unix)]
#[cfg_attr(not(feature = "fixed-policy-root-owned"), allow(dead_code))]
#[derive(Clone, Copy)]
enum Entry {
    Folder { account_may_own: bool },
    File,
}

/// `fixed-policy-root-owned`: refuse an entry of the chain that the account,
/// its group or others could change. Checked with `fstat` on the open
/// descriptor, so it is the entry that is read.
#[cfg(all(unix, feature = "fixed-policy-root-owned"))]
fn check_owner(entry: &std::fs::File, path: &Path, kind: Entry) -> Result<(), LoadFailure> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = entry
        .metadata()
        .map_err(|error| LoadFailure::present(format!("{}: {error}", path.display())))?;
    let (owner, mode) = (metadata.uid(), metadata.mode() & 0o7777);
    // SAFETY: getuid has no preconditions.
    let account = unsafe { libc::getuid() };
    let (owner_ok, writable_by, rule) = match kind {
        Entry::Folder {
            account_may_own: true,
        } => (
            owner == 0 || owner == account,
            0o022,
            "owned by root or the account and not writable by group or others",
        ),
        Entry::Folder {
            account_may_own: false,
        } => (
            owner == 0,
            0o022,
            "owned by root and not writable by group or others",
        ),
        Entry::File => (owner == 0, 0o222, "owned by root and writable by no one"),
    };
    if owner_ok && mode & writable_by == 0 {
        return Ok(());
    }
    Err(LoadFailure::present(format!(
        "{} is owned by uid {owner} with mode {mode:04o}; it must be {rule}",
        path.display()
    )))
}

#[cfg(all(unix, not(feature = "fixed-policy-root-owned")))]
fn check_owner(_entry: &std::fs::File, _path: &Path, _kind: Entry) -> Result<(), LoadFailure> {
    Ok(())
}

#[cfg(unix)]
fn account_home() -> Result<PathBuf, String> {
    account_home_with(16 * 1024)
}

/// The account's home directory from the user database, starting with a
/// `buffer_len`-byte buffer for `getpwuid_r` and doubling it up to 1 MiB
/// while the entry does not fit.
#[cfg(unix)]
fn account_home_with(mut buffer_len: usize) -> Result<PathBuf, String> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt as _;

    const MAX_BUFFER_LEN: usize = 1024 * 1024;
    loop {
        let mut buffer = vec![0 as libc::c_char; buffer_len];
        // SAFETY: `passwd` is plain old data; getpwuid_r fills it in.
        let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: every pointer is valid for the call, and `buffer.len()` is
        // the size of the buffer getpwuid_r may write the entry's strings into.
        let status = unsafe {
            libc::getpwuid_r(
                libc::getuid(),
                &mut entry,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };
        if status == libc::ERANGE && buffer_len < MAX_BUFFER_LEN {
            buffer_len = (buffer_len * 2).clamp(1, MAX_BUFFER_LEN);
            continue;
        }
        if status != 0 {
            return Err(format!(
                "the account's user database entry could not be read: {}",
                std::io::Error::from_raw_os_error(status)
            ));
        }
        if found.is_null() || entry.pw_dir.is_null() {
            return Err("the account's home directory is not in the user database".to_owned());
        }
        // SAFETY: on success `pw_dir` points at a NUL-terminated string inside
        // `buffer`, which outlives this borrow.
        let home = unsafe { CStr::from_ptr(entry.pw_dir) };
        let home = Path::new(OsStr::from_bytes(home.to_bytes()));
        if !home.is_absolute() {
            return Err(format!(
                "the account's home directory is not absolute: {}",
                home.display()
            ));
        }
        return Ok(home.to_path_buf());
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    const YAML: &str = "allow:\n  tools: [get_config]\n";

    /// A home with `.config/cua-driver` in it, owned by the test's account.
    fn home() -> tempfile::TempDir {
        let home = tempfile::tempdir().expect("temporary home");
        std::fs::create_dir_all(home.path().join(".config/cua-driver")).expect("config folders");
        home
    }

    fn write_policy(folder: &Path) {
        std::fs::create_dir_all(folder).expect("policy folder");
        std::fs::write(folder.join(USER_POLICY_FILE), YAML).expect("policy file");
    }

    fn failure(home: &Path) -> LoadFailure {
        load_fixed_file(home, USER_POLICY_FILE).expect_err("the layer must not load")
    }

    // A root-owned build refuses the account-owned folders first.
    #[cfg(not(feature = "fixed-policy-root-owned"))]
    #[test]
    fn a_symlinked_policy_folder_is_reported_as_a_symbolic_link() {
        let home = home();
        let elsewhere = home.path().join("elsewhere");
        write_policy(&elsewhere);
        let folder = home.path().join(POLICY_DIR);
        std::os::unix::fs::symlink(&elsewhere, &folder).expect("link the policy folder");

        let failure = failure(home.path());
        assert_eq!(
            failure.reason,
            format!("{} is a symbolic link", folder.display())
        );
        assert!(failure.file_present);
    }

    // A root-owned build refuses the account-owned folders first.
    #[cfg(not(feature = "fixed-policy-root-owned"))]
    #[test]
    fn a_symlinked_policy_file_is_reported_as_a_symbolic_link() {
        let home = home();
        let folder = home.path().join(POLICY_DIR);
        write_policy(&home.path().join("elsewhere"));
        std::fs::create_dir(&folder).expect("policy folder");
        let file = folder.join(USER_POLICY_FILE);
        std::os::unix::fs::symlink(home.path().join("elsewhere").join(USER_POLICY_FILE), &file)
            .expect("link the policy file");

        assert_eq!(
            failure(home.path()).reason,
            format!("{} is a symbolic link", file.display())
        );
    }

    // A root-owned build refuses the account-owned folders first.
    #[cfg(not(feature = "fixed-policy-root-owned"))]
    #[test]
    fn a_missing_policy_file_is_absent() {
        let home = home();
        let failure = failure(home.path());
        assert!(!failure.file_present);
        assert!(
            failure.reason.ends_with("does not exist"),
            "{}",
            failure.reason
        );
    }

    #[test]
    fn the_account_home_resolves_from_a_one_byte_buffer() {
        assert_eq!(account_home_with(1), account_home());
        assert!(account_home().is_ok());
    }

    #[cfg(not(feature = "fixed-policy-root-owned"))]
    #[test]
    fn a_policy_file_the_account_owns_loads() {
        let home = home();
        write_policy(&home.path().join(POLICY_DIR));
        let layer = load_fixed_file(home.path(), USER_POLICY_FILE).expect("the layer loads");
        assert_eq!(layer.source, PolicySource::FixedFile);
        assert_eq!(
            layer.sha256,
            policy_digest([(USER_POLICY_FILE, YAML.as_bytes())])
        );
    }

    #[cfg(feature = "fixed-policy-root-owned")]
    #[test]
    fn a_policy_folder_the_account_owns_is_refused_with_its_owner_and_mode() {
        // SAFETY: getuid has no preconditions.
        let account = unsafe { libc::getuid() };
        if account == 0 {
            eprintln!("skipped: running as root, which owns everything it creates");
            return;
        }
        use std::os::unix::fs::PermissionsExt as _;
        let home = home();
        let config = home.path().join(".config");
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o755))
            .expect("chmod .config");
        write_policy(&home.path().join(POLICY_DIR));
        let driver = home.path().join(".config/cua-driver");
        std::fs::set_permissions(&driver, std::fs::Permissions::from_mode(0o755))
            .expect("chmod cua-driver");

        let failure = failure(home.path());
        assert_eq!(
            failure.reason,
            format!(
                "{} is owned by uid {account} with mode 0755; it must be owned by root and \
                 not writable by group or others",
                driver.display()
            )
        );
        assert!(failure.file_present);
    }

    #[cfg(feature = "fixed-policy-root-owned")]
    #[test]
    fn a_config_folder_writable_by_others_is_refused() {
        use std::os::unix::fs::PermissionsExt as _;
        let home = home();
        let config = home.path().join(".config");
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o777))
            .expect("chmod .config");

        let failure = failure(home.path());
        assert!(
            failure.reason.starts_with(&format!(
                "{} is owned by uid {} with mode 0777;",
                config.display(),
                // SAFETY: getuid has no preconditions.
                unsafe { libc::getuid() }
            )),
            "{}",
            failure.reason
        );
    }
}
