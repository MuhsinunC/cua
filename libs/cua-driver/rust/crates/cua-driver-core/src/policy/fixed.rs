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
//! A layer whose file is missing, cannot be opened or read this way, or does
//! not load is replaced by the built-in locked policy, which allows only tools
//! that neither act on nor read the screen. The driver therefore always
//! starts, and never starts open.

use std::path::PathBuf;

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
}

/// The layer for `env_name`'s slot: its fixed file, or the built-in locked policy.
pub(super) fn load_layer(env_name: &str) -> ConfiguredPolicyLayer {
    let (layer, file) = if env_name == MANAGED_POLICY_FILE_ENV {
        ("managed", MANAGED_POLICY_FILE)
    } else {
        ("user", USER_POLICY_FILE)
    };
    match load_fixed_file(file) {
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

fn load_fixed_file(file: &str) -> Result<ConfiguredPolicyLayer, LoadFailure> {
    let (path, bytes) = read_fixed_file(file)?;
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
    })
}

fn locked_layer(failure: LoadFailure) -> ConfiguredPolicyLayer {
    let policy = YamlPolicy::from_str(LOCKED_POLICY).expect("the built-in locked policy parses");
    ConfiguredPolicyLayer {
        engine: PolicyEngine::Yaml(policy),
        sha256: policy_digest([(LOCKED_POLICY_NAME, LOCKED_POLICY.as_bytes())]),
        source: PolicySource::BuiltInLocked {
            reason: failure.reason,
            file_present: failure.file_present,
        },
    }
}

/// Read `<home>/.config/cua-driver/policy/<file>` without following a symbolic
/// link below `<home>`, returning its path (for messages) and its bytes.
#[cfg(unix)]
fn read_fixed_file(file: &str) -> Result<(PathBuf, Vec<u8>), LoadFailure> {
    use std::io::Read as _;
    use std::os::unix::fs::OpenOptionsExt as _;

    let home = account_home().map_err(|reason| LoadFailure {
        reason,
        file_present: false,
    })?;
    let mut path = home.clone();
    let mut folder = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY)
        .open(&home)
        .map_err(|error| open_failure(&path, error))?;
    for name in POLICY_DIR.split('/') {
        path.push(name);
        folder = open_at(&folder, name, libc::O_DIRECTORY)
            .map_err(|error| open_failure(&path, error))?;
    }
    path.push(file);
    // O_NONBLOCK: opening a FIFO must not wait for a writer.
    let mut policy =
        open_at(&folder, file, libc::O_NONBLOCK).map_err(|error| open_failure(&path, error))?;
    let unreadable =
        |error: std::io::Error| LoadFailure::present(format!("{}: {error}", path.display()));
    if !policy.metadata().map_err(unreadable)?.is_file() {
        return Err(LoadFailure::present(format!(
            "{} is not a regular file",
            path.display()
        )));
    }
    let mut bytes = Vec::new();
    policy.read_to_end(&mut bytes).map_err(unreadable)?;
    Ok((path, bytes))
}

#[cfg(not(unix))]
fn read_fixed_file(_file: &str) -> Result<(PathBuf, Vec<u8>), LoadFailure> {
    Err(LoadFailure {
        reason: "a fixed policy location is supported only on Unix".to_owned(),
        file_present: false,
    })
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

    let name = std::ffi::CString::new(name)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
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
fn open_failure(path: &std::path::Path, error: std::io::Error) -> LoadFailure {
    match error.raw_os_error() {
        Some(libc::ENOENT) => LoadFailure {
            reason: format!("{} does not exist", path.display()),
            file_present: false,
        },
        Some(libc::ELOOP) => LoadFailure::present(format!("{} is a symbolic link", path.display())),
        _ => LoadFailure::present(format!("{}: {error}", path.display())),
    }
}

#[cfg(unix)]
fn account_home() -> Result<PathBuf, String> {
    use std::ffi::{CStr, OsStr};
    use std::os::unix::ffi::OsStrExt as _;
    use std::path::Path;

    let mut buffer = vec![0 as libc::c_char; 16 * 1024];
    // SAFETY: `passwd` is plain old data; getpwuid_r fills it in.
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call, and `buffer.len()` is the
    // size of the buffer getpwuid_r may write the entry's strings into.
    let status = unsafe {
        libc::getpwuid_r(
            libc::getuid(),
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        )
    };
    if status != 0 || found.is_null() || entry.pw_dir.is_null() {
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
    Ok(home.to_path_buf())
}
