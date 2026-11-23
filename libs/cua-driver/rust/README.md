# cua-driver Rust workspace

This directory is the standalone Cargo workspace for the driver daemon, platform
implementations, testkit, and helper crates.

## Crates

| Crate | Purpose |
| --- | --- |
| `cua-driver` | Main CLI/MCP daemon and hermetic integration tests |
| `cua-driver-e2e` | Desktop E2E suites that the canonical OS runners select; never shipped |
| `cua-driver-core` | Shared protocol, tool models, config, and CDP helpers |
| `platform-macos` | macOS AX, capture, input, browser, and daemon support |
| `platform-windows` | Windows UIA, capture, input, overlay, and diagnostics |
| `platform-linux` | Linux AT-SPI, X11/Wayland, capture, and input support |
| `cua-driver-testkit` | Test-only helpers for spawning the daemon and parsing responses |
| `cua-driver-uia` | Windows UIAccess worker |
| `cursor-overlay` | Cross-platform semantic cursor renderer and bounded compiled-theme loader |
| `cursor-theme-cli` | Short-lived dotLottie validation, compilation, preview, and installation sidecar |
| `pip-preview` | Packaging preview helper |

Platform crates are selected with `cfg(target_os)` from the main driver crate.
Keep platform-specific behavior inside the matching `platform-<os>` crate.

## Build

```bash
cargo build -p cua-driver
cargo build -p cua-driver --release
```

The Python wrapper and install scripts expect the built binary at
`target/<profile>/cua-driver` (or `cua-driver.exe` on Windows), unless
`CUA_DRIVER_BINARY` is set.

## Formatting

The supported Rust toolchain and `rustfmt` component are pinned in
`rust-toolchain.toml`. Install [rustup](https://rustup.rs/) and run the
canonical formatting check from this directory:

```bash
cargo fmt --all -- --check
```

To apply formatting, omit `--check`:

```bash
cargo fmt --all
```

## Tests

Default tests should be headless and safe for CI:

```bash
cargo test -p cua-driver-core
cargo test -p cua-driver --test protocol_schema_test
```

GUI and VM-backed tests live in `cua-driver-e2e`, are marked `#[ignore]`, and
require a built driver, harness apps from `../tests/fixtures/build/`, and a
real interactive desktop session:

```bash
cargo build -p cua-driver
cargo test -p cua-driver-e2e --test harness_appkit_test -- --ignored --nocapture
cargo test -p cua-driver-e2e --test harness_wpf_test -- --ignored --nocapture
```

See `crates/cua-driver-e2e/tests/README.md` for the desktop E2E suites and
`crates/cua-driver/tests/README.md` for the hermetic driver tests.

Testkit-owned daemons use a temporary `CUA_DRIVER_RS_HOME` on every platform.
A nonempty override also places Computer History data and its `admission.json`
under `<CUA_DRIVER_RS_HOME>/computer-history`. Without an override (or with an
empty value), History keeps its platform-specific default location. Existing
data is not migrated, and installed-product admission checks still apply.
On Windows this isolates driver state without redirecting `LOCALAPPDATA`,
`APPDATA`, or `USERPROFILE`, which Windows app discovery needs. Explicit caller
environment values take precedence; `SHARE_HOST_STATE` opts a testkit spawn out
of isolation. Use separate roots for independent driver instances. This isolates
files, not the operating system's credential store.

## Generated Outputs

- `target/`: Cargo output, ignored.
- `test-apps/harness-*/`: staged harness apps, ignored.
- `test-apps/README.md`: explains how staged harness outputs are produced.

## Permission Policies

Set `CUA_DRIVER_POLICY_FILE` on the daemon to enforce a deny-by-default policy
on all tool calls from MCP and CLI clients. If the variable is unset, or points to a path that does
not exist, the driver keeps its backward-compatible behavior with no policy
enforcement. Supported paths are:

- `.yaml` / `.yml`: a single YAML policy file.
- `.rego`: a single Rego policy file.
- A directory: all top-level `.rego` files are loaded in sorted order.

YAML policies allow unconstrained tools through `allow.tools`, constrained
calls through `allow.rules`, and explicit overrides through `deny.tools`:

```yaml
allow:
  tools: [get_window_state, get_desktop_state, scroll, wait]
  rules:
    - tool: click
      constraints:
        x: { min: 0, max: 1920 }
        y: { min: 0, max: 1080 }
    - tool: type_text
      constraints:
        text: { max_length: 1000, pattern: "^[a-zA-Z0-9\\s]+$" }
    - tool: launch_app
      constraints:
        app:
          allowed: [Calculator, TextEdit, Safari]
deny:
  tools: [shell_execute, file_delete]
```

Rego policies must expose a boolean rule at `data.cua.policy.allow`. The input
shape is `{ "server": "cua-driver", "tool": <name>, "arguments": <object> }`.
Regorus evaluates policies inside the daemon; no OPA service is required.

### Fixed policy builds

An operator who must guarantee that their copy of the driver never serves
without their policy can build it with `--features cua-driver/fixed-policy`
(off by default). Such a build ignores `CUA_DRIVER_POLICY_FILE` and
`CUA_DRIVER_MANAGED_POLICY_FILE`, however the driver is started (`serve`,
`mcp` and the daemon it launches, `open -a ... --args serve`), and always loads
the user layer from `~/.config/cua-driver/policy/policy.yaml` and the managed
layer from `policy.rego` in the same folder. `~` is the account's home
directory from the user database, not `$HOME`.

The guarantee covers the `cua-driver` binary and `CuaDriver.app` built with
the feature. `cua-driver-sdk` does not enable it, so a driver embedded through
the SDK keeps the environment variables.

Each file is opened one folder at a time from `~`: `.config`, `cua-driver`,
`policy`, then the file, each relative to the folder before it and never
through a symbolic link. The file must be a regular file, and the policy and
its digest are built from the bytes read through that open. A layer whose file
is missing, is or sits under a symbolic link below `~`, cannot be read or
fails to load is replaced by a built-in locked policy that allows only
`health_report`, `get_config`, `check_permissions`, `get_guide`,
`list_sessions`, `get_session` and `get_session_state`.

The driver still starts, so `status` can say why. For such a layer it reports
`valid=false` (and `configured=false` when no file is there), the source
`built_in_locked` and the reason; a layer loaded from its file reports the
source `fixed_file`. The status JSON carries them as `*_policy_valid`,
`*_policy_configured`, `*_policy_source` and `*_policy_locked_reason`. In
default builds the source is `environment` for a layer loaded from its
variable and `null` otherwise. The fixed folder is supported on Unix;
elsewhere both layers are always locked.

A fixed-policy build never updates itself: its operator builds and installs
it, and a release installed over it would not enforce their policy. `update`
(with or without `--apply`), `check-update`, the `check_for_update` tool and the
release channel commands refuse with "This build is managed by its operator;
updates come from them", and the startup update notice is never shown.

`doctor` reports the app's bundle id (`bundle id`), which the driver reads
from the Info.plist of the app it runs in, so a fixed-policy app given its own
bundle id names that id in `permissions grant`, in doctor's checks and in the
Computer History identity check.

#### Root-owned policy files

By default the account that runs the driver owns its policy folder, so any
program running as that account can rewrite the files. To take that away,
build with `--features cua-driver/fixed-policy-root-owned` (it includes
`fixed-policy`). Checked on the folders and files the driver opened:

- `~/.config/cua-driver`, `~/.config/cua-driver/policy` and both files are
  owned by root;
- no folder in the chain is writable by group or others, and the files are
  writable by no one;
- `~/.config` may also be owned by the account, but is not writable by group
  or others.

Anything else serves the built-in locked policy, with a reason that names the
path, its owner and its mode. After writing the files, one administrator step
puts the folder in that state (`wheel` is `root` on Linux):

```sh
sudo sh -c 'd="$1/.config/cua-driver"; chown -R root:wheel "$d" && chmod 755 "$d" "$d/policy" && chmod 444 "$d/policy/policy.yaml" "$d/policy/policy.rego" && chmod go-w "$1/.config"' sh "$HOME"
```

To change the policy later, the administrator replaces the files the same way.
