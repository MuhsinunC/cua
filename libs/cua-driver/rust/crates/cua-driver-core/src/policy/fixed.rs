// SPDX-License-Identifier: MIT

//! Fixed policy location for operator-managed builds (`fixed-policy` feature).
//!
//! A build with this feature never reads [`super::POLICY_FILE_ENV`] or
//! [`super::MANAGED_POLICY_FILE_ENV`]. Every process, however it was started,
//! loads the user layer from `<home>/.config/cua-driver/policy/policy.yaml`
//! and the managed layer from `policy.rego` in the same folder. `<home>` is
//! the account's home directory from the user database, never `$HOME`, so a
//! launcher cannot point the driver at another folder.
//!
//! A layer whose file is missing, is not a regular file (a symbolic link
//! counts), cannot be read or does not load is replaced by the built-in
//! locked policy, which allows only tools that neither act on nor read the
//! screen. The driver therefore always starts, and never starts open.

use std::path::PathBuf;

use sha2::{Digest, Sha256};

use super::{
    hash_policy_file, load_policy_path, ConfiguredPolicyLayer, PolicyEngine, PolicySource,
    YamlPolicy, MANAGED_POLICY_FILE_ENV,
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

/// The layer for `env_name`'s slot: its fixed file, or the built-in locked policy.
pub(super) fn load_layer(env_name: &str) -> ConfiguredPolicyLayer {
    let (layer, file) = if env_name == MANAGED_POLICY_FILE_ENV {
        ("managed", MANAGED_POLICY_FILE)
    } else {
        ("user", USER_POLICY_FILE)
    };
    match load_fixed_file(file) {
        Ok(configured) => configured,
        Err(reason) => {
            tracing::warn!("{layer} policy: serving the built-in locked policy: {reason}");
            locked_layer(reason)
        }
    }
}

fn load_fixed_file(file: &str) -> Result<ConfiguredPolicyLayer, String> {
    let path = account_home()?.join(POLICY_DIR).join(file);
    let metadata =
        std::fs::symlink_metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    load_policy_path(&path, PolicySource::FixedFile)?
        .ok_or_else(|| format!("{}: policy support is not enabled", path.display()))
}

fn locked_layer(reason: String) -> ConfiguredPolicyLayer {
    let policy = YamlPolicy::from_str(LOCKED_POLICY).expect("the built-in locked policy parses");
    let mut digest = Sha256::new();
    digest.update(b"cua-driver-policy-v1\0");
    hash_policy_file(&mut digest, LOCKED_POLICY_NAME, LOCKED_POLICY.as_bytes());
    ConfiguredPolicyLayer {
        engine: PolicyEngine::Yaml(policy),
        sha256: format!("{:x}", digest.finalize()),
        source: PolicySource::BuiltInLocked { reason },
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

#[cfg(not(unix))]
fn account_home() -> Result<PathBuf, String> {
    Err("a fixed policy location is supported only on Unix".to_owned())
}
