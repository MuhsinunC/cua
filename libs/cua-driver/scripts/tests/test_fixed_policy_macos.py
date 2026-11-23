"""End-to-end checks of a `fixed-policy` build of CuaDriver.app on macOS.

They drive the built app the way clients start it: a bare `cua-driver mcp`
(which launches its own daemon through LaunchServices) and
`open -n -g <app> --args serve`. No privacy grants are needed: the policy is
evaluated before any action runs, so a policy refusal shows without them.

The app must be installed at /Applications/CuaDriver.app, where `mcp` launches
it from. The tests write the fixed policy folder in the account's home, set
launchd's environment for the daemons LaunchServices starts (no first-launch
permission panel, no telemetry) and restart the daemon for each case, so they
run one at a time on a disposable macOS machine. Set CUA_FIXED_POLICY_E2E=1 to
run them.

Set CUA_FIXED_POLICY_ROOT_OWNED=1 when the app was built with
`fixed-policy-root-owned`: the tests then write the fixed folder and files as
root with `sudo -n` (passwordless sudo is required) and check that a policy
the account owns is refused. CUA_FIXED_POLICY_E2E_BUNDLE_ID is the app's
bundle id (default com.trycua.driver.fixedpolicy).
"""

import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import tempfile
import time

import pytest

pwd = pytest.importorskip("pwd")


pytestmark = pytest.mark.skipif(
    os.environ.get("CUA_FIXED_POLICY_E2E") != "1",
    reason="set CUA_FIXED_POLICY_E2E=1 on a disposable macOS machine",
)

ROOT_OWNED = os.environ.get("CUA_FIXED_POLICY_ROOT_OWNED") == "1"
BUNDLE_ID = os.environ.get("CUA_FIXED_POLICY_E2E_BUNDLE_ID", "com.trycua.driver.fixedpolicy")
APP = Path("/Applications/CuaDriver.app")
BIN = APP / "Contents/MacOS/cua-driver"
# Driver output (daemons started with `open`, `mcp` clients), kept for CI.
LOG_DIR = Path(os.environ.get("CUA_FIXED_POLICY_E2E_LOGS", tempfile.gettempdir()))
HOME = Path(pwd.getpwuid(os.getuid()).pw_dir)
DRIVER_DIR = HOME / ".config/cua-driver"
POLICY_DIR = DRIVER_DIR / "policy"
LOCKED_TOOLS = {
    "health_report",
    "get_config",
    "check_permissions",
    "get_guide",
    "list_sessions",
    "get_session",
    "get_session_state",
}
POLICY_ENV = ("CUA_DRIVER_POLICY_FILE", "CUA_DRIVER_MANAGED_POLICY_FILE")
# What the driver runs with, here and in launchd for the daemons
# LaunchServices starts: no first-launch permission panel, no telemetry.
DRIVER_ENV = {"CUA_DRIVER_RS_PERMISSIONS_GATE": "0", "CUA_TELEMETRY": "0", "DO_NOT_TRACK": "1"}
UPDATE_REFUSAL = "managed by its operator; updates come from them"
POLICY_DENIAL = re.compile(r"Permission denied: (user|managed) policy: ")
# An allow-list of click, get_window_state and the locked tools: the two
# actions the locked policy refuses are allowed. Every other tool is denied.
PERMISSIVE_YAML = "allow:\n  tools: [click, get_window_state, {}]\n".format(
    ", ".join(sorted(LOCKED_TOOLS))
)
PERMISSIVE_REGO = "package cua.policy\n\ndefault allow := true\n"
CLICK = {"pid": 1, "x": 10, "y": 10}
WINDOW_STATE = {"pid": 1, "window_id": 1}


def driver(*args, env=None, timeout=60):
    return subprocess.run(
        [str(BIN), *args],
        capture_output=True,
        text=True,
        env=env or clean_env(),
        timeout=timeout,
    )


def clean_env(**extra):
    env = {k: v for k, v in os.environ.items() if k not in POLICY_ENV}
    env.update(DRIVER_ENV)
    env.update(extra)
    return env


def write_policy(directory, yaml=PERMISSIVE_YAML, rego=PERMISSIVE_REGO):
    """Policy files the account owns, anywhere."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "policy.yaml").write_text(yaml)
    (directory / "policy.rego").write_text(rego)


def sudo(*args):
    subprocess.run(["/usr/bin/sudo", "-n", *args], check=True, timeout=60)


def write_fixed_policy(yaml=PERMISSIVE_YAML, rego=PERMISSIVE_REGO):
    """The fixed policy folder, owned the way the build requires: by the
    account, or (root-owned builds) by root with the files read-only."""
    if not ROOT_OWNED:
        write_policy(POLICY_DIR, yaml, rego)
        return
    secure_config()
    sudo("/usr/bin/install", "-d", "-o", "root", "-g", "wheel", "-m", "0755",
         str(DRIVER_DIR), str(POLICY_DIR))
    for name, content in (("policy.yaml", yaml), ("policy.rego", rego)):
        place_fixed_file(name, content)


def secure_config():
    """~/.config, which the account may own, not writable by group or others."""
    config = DRIVER_DIR.parent
    config.mkdir(exist_ok=True)
    config.chmod(stat.S_IMODE(config.stat().st_mode) & 0o755)


def place_fixed_file(name, content):
    """Replace one fixed policy file, as root in root-owned builds."""
    if not ROOT_OWNED:
        (POLICY_DIR / name).write_text(content)
        return
    with tempfile.NamedTemporaryFile("w", suffix=name) as staged:
        staged.write(content)
        staged.flush()
        sudo("/usr/bin/install", "-o", "root", "-g", "wheel", "-m", "0444",
             staged.name, str(POLICY_DIR / name))


def link_fixed_file(name, target):
    """Replace one fixed policy file with a symbolic link to `target`."""
    if ROOT_OWNED:
        sudo("/bin/ln", "-sfn", str(target), str(POLICY_DIR / name))
    else:
        (POLICY_DIR / name).unlink()
        (POLICY_DIR / name).symlink_to(target)


def policy_digest(name, data):
    """The digest `status` reports for one policy file."""
    digest = hashlib.sha256(b"cua-driver-policy-v1\0")
    for part in (name.encode(), data):
        digest.update(len(part).to_bytes(8, "big"))
        digest.update(part)
    return digest.hexdigest()


def wait_for(predicate, timeout=60, what="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.5)
    raise AssertionError(f"timed out waiting for {what}")


def socket_listening(socket):
    return driver("--socket", socket, "status", timeout=15).returncode == 0


def stop(socket=None):
    args = ["--socket", socket] if socket else []
    driver(*args, "stop", timeout=30)
    wait_for(
        lambda: driver(*args, "status", timeout=15).returncode != 0,
        what="the daemon to stop",
    )


def log_path(kind):
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    test = os.environ.get("PYTEST_CURRENT_TEST", "test").split(" ")[0]
    return LOG_DIR / (re.sub(r"[^A-Za-z0-9_.-]+", "_", test) + f".{kind}.log")


def serve_with_open(socket, env=None):
    """Start the app through LaunchServices, as Cua itself launches its daemon."""
    env_args = [arg for name, value in (env or {}).items() for arg in ("--env", f"{name}={value}")]
    output = ["--stdout", str(log_path("serve-out")), "--stderr", str(log_path("serve-err"))]
    subprocess.run(
        ["/usr/bin/open", "-n", "-g", *output, *env_args, str(APP),
         "--args", "--socket", socket, "serve"],
        check=True,
        timeout=60,
    )
    wait_for(lambda: socket_listening(socket), what=f"a daemon on {socket}")


def status_text(socket=None):
    args = ["--socket", socket] if socket else []
    result = driver(*args, "status", timeout=30)
    assert result.returncode == 0, result.stderr
    return result.stdout


def assert_layer(text, layer, source, configured, valid):
    """`status` reports `layer` with this source, configured and valid state."""
    state = f"configured={str(configured).lower()}, active=true, valid={str(valid).lower()}"
    assert f"{layer} policy: {state}" in text, text
    assert f"{layer} policy source: {source}" in text, text


def assert_locked(text, configured=False):
    for layer in ("user", "managed"):
        assert_layer(text, layer, "built_in_locked", configured=configured, valid=False)


class Mcp:
    """Minimal MCP stdio client: newline-delimited JSON-RPC over stdin/stdout.

    The pipes are unbuffered and lines are split here, so data already read
    from the pipe is never left waiting in a buffer `select` cannot see.
    """

    def __init__(self, env, *args):
        self.stderr = log_path("mcp-err").open("a")
        self.process = subprocess.Popen(
            [str(BIN), "mcp", *args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.stderr,
            bufsize=0,
            env=env,
        )
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        self.pending = b""
        self.next_id = 0

    def send(self, message):
        data = (json.dumps(message) + "\n").encode()
        while data:
            data = data[os.write(self.process.stdin.fileno(), data):]

    def read_line(self, deadline):
        """The next line the driver writes, or None if none comes by `deadline`."""
        while b"\n" not in self.pending:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(timeout=remaining):
                return None
            chunk = os.read(self.process.stdout.fileno(), 65536)
            if not chunk:
                raise AssertionError("mcp closed its output")
            self.pending += chunk
        line, _, self.pending = self.pending.partition(b"\n")
        return line

    def request(self, method, params=None, timeout=120):
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)
        deadline = time.monotonic() + timeout
        while (line := self.read_line(deadline)) is not None:
            if not line.strip():
                continue
            reply = json.loads(line)
            if reply.get("id") == self.next_id:
                return reply
        raise AssertionError(f"no answer to {method} within {timeout}s")

    def initialize(self):
        reply = self.request(
            "initialize",
            {
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "fixed-policy-e2e", "version": "0"},
            },
        )
        assert "result" in reply, reply
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})

    def call_text(self, tool, arguments):
        reply = self.request("tools/call", {"name": tool, "arguments": arguments})
        result = reply.get("result", {})
        return result.get("isError"), " ".join(
            item.get("text", "") for item in result.get("content", [])
        ) or json.dumps(reply)

    def close(self):
        self.process.stdin.close()
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        finally:
            self.stderr.close()


def remove(path):
    """Remove a file, a folder tree or a symbolic link (never its target)."""
    if ROOT_OWNED and (path.exists() or path.is_symlink()):
        # No trailing slash: a symbolic link is removed, not its target.
        sudo("/bin/rm", "-rf", str(path))
    elif path.is_symlink() or path.is_file():
        path.unlink()
    elif path.exists():
        shutil.rmtree(path)


def launchctl_getenv(name):
    result = subprocess.run(
        ["/bin/launchctl", "getenv", name], capture_output=True, text=True, check=False
    )
    return result.stdout.rstrip("\n") or None


@pytest.fixture(autouse=True, scope="module")
def launchd_env():
    """DRIVER_ENV in launchd's environment for the module, then the old values."""
    previous = {name: launchctl_getenv(name) for name in DRIVER_ENV}
    for name, value in DRIVER_ENV.items():
        subprocess.run(["/bin/launchctl", "setenv", name, value], check=True)
    try:
        yield
    finally:
        for name, value in previous.items():
            if value is None:
                subprocess.run(["/bin/launchctl", "unsetenv", name], check=False)
            else:
                subprocess.run(["/bin/launchctl", "setenv", name, value], check=False)


@pytest.fixture(autouse=True)
def fresh_state(launchd_env):
    """No daemon, no driver config folder and no LaunchServices policy env per case."""
    assert BIN.is_file(), f"install the fixed-policy build at {APP}"
    if DRIVER_DIR.exists() or DRIVER_DIR.is_symlink():
        pytest.fail(f"{DRIVER_DIR} exists; run only on a disposable machine")
    stop()
    try:
        yield
    finally:
        try:
            for name in POLICY_ENV:
                subprocess.run(["/bin/launchctl", "unsetenv", name], check=False)
            stop()
        finally:
            remove(DRIVER_DIR)


@pytest.fixture
def socket():
    """A daemon socket path short enough for a Unix socket address."""
    directory = Path(tempfile.mkdtemp(prefix="fp", dir="/tmp"))
    path = str(directory / "d.sock")
    try:
        yield path
    finally:
        try:
            stop(path)
        finally:
            shutil.rmtree(directory, ignore_errors=True)


def assert_locked_mcp(env, *args, socket=None):
    client = Mcp(env, *args)
    try:
        client.initialize()
        listed = client.request("tools/list")
        names = {tool["name"] for tool in listed["result"]["tools"]}
        assert names, listed
        assert names <= LOCKED_TOOLS, sorted(names - LOCKED_TOOLS)
        for tool, arguments in (("click", CLICK), ("get_window_state", WINDOW_STATE)):
            is_error, text = client.call_text(tool, arguments)
            assert is_error, text
            assert POLICY_DENIAL.search(text), text
        assert_locked(status_text(socket))
    finally:
        client.close()


def assert_policy_refuses_call(socket):
    result = driver("--socket", socket, "call", "get_window_state", json.dumps(WINDOW_STATE))
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert POLICY_DENIAL.search(output), output


def permissive_env(tmp_path):
    permissive = tmp_path / "permissive"
    write_policy(permissive)
    return dict(zip(POLICY_ENV, (str(permissive / "policy.yaml"), str(permissive / "policy.rego"))))


def test_a_bare_mcp_without_policy_files_is_locked():
    # No daemon runs, so `mcp` launches one through LaunchServices.
    assert_locked_mcp(clean_env())


def test_b_policy_environment_is_ignored(tmp_path):
    env = permissive_env(tmp_path)
    # The daemon `mcp` launches gets LaunchServices' environment, so set the
    # variables there too, not only in the client's own environment.
    for name, value in env.items():
        subprocess.run(["/bin/launchctl", "setenv", name, value], check=True)
    assert_locked_mcp(clean_env(**env))


def test_b2_home_override_is_ignored(tmp_path, socket):
    fake_home = tmp_path / "home"
    write_policy(fake_home / ".config/cua-driver/policy")
    serve_with_open(socket, {"HOME": str(fake_home)})
    assert_policy_refuses_call(socket)
    assert_locked_mcp(clean_env(HOME=str(fake_home)), "--socket", socket, socket=socket)


def test_c_open_with_policy_env_is_refused_by_policy(tmp_path, socket):
    serve_with_open(socket, permissive_env(tmp_path))
    assert_policy_refuses_call(socket)
    assert_locked(status_text(socket))


def test_d_fixed_files_are_loaded(socket):
    write_fixed_policy()
    serve_with_open(socket)
    result = driver("--socket", socket, "call", "get_window_state", json.dumps(WINDOW_STATE))
    output = result.stdout + result.stderr
    # Past the policy the call may still fail (no such window, no privacy
    # grant); only a policy refusal fails this case.
    assert not POLICY_DENIAL.search(output), output
    assert "Policy loading error" not in output, output
    text = status_text(socket)
    for layer, name, source in (
        ("user", "policy.yaml", PERMISSIVE_YAML),
        ("managed", "policy.rego", PERMISSIVE_REGO),
    ):
        assert_layer(text, layer, "fixed_file", configured=True, valid=True)
        # The digest of exactly the bytes the driver read, hashed as a default
        # build hashes the same file.
        assert f"{layer} policy sha256: {policy_digest(name, source.encode())}" in text, text


@pytest.mark.parametrize("damage", ["symlink", "malformed"])
def test_e_unusable_fixed_file_gives_the_locked_policy(tmp_path, socket, damage):
    write_fixed_policy()
    if damage == "symlink":
        target = tmp_path / "elsewhere.yaml"
        target.write_text(PERMISSIVE_YAML)
        link_fixed_file("policy.yaml", target)
    else:
        place_fixed_file("policy.yaml", "allow: [click\n")
    serve_with_open(socket)
    assert_policy_refuses_call(socket)
    text = status_text(socket)
    assert_layer(text, "user", "built_in_locked", configured=True, valid=False)
    assert_layer(text, "managed", "fixed_file", configured=True, valid=True)


def test_f_symlinked_policy_folder_gives_the_locked_policy(tmp_path, socket):
    target = tmp_path / "policy"
    write_policy(target)
    DRIVER_DIR.mkdir(parents=True)
    POLICY_DIR.symlink_to(target, target_is_directory=True)
    serve_with_open(socket)
    assert_policy_refuses_call(socket)
    assert_locked(status_text(socket), configured=True)


def test_g_symlinked_driver_config_folder_gives_the_locked_policy(tmp_path, socket):
    target = tmp_path / "cua-driver"
    write_policy(target / "policy")
    DRIVER_DIR.parent.mkdir(parents=True, exist_ok=True)
    DRIVER_DIR.symlink_to(target, target_is_directory=True)
    serve_with_open(socket)
    assert_policy_refuses_call(socket)
    assert_locked(status_text(socket), configured=True)


@pytest.mark.skipif(not ROOT_OWNED, reason="a root-owned build refuses this layout")
def test_root_owned_build_refuses_a_policy_the_account_owns(socket):
    secure_config()
    write_policy(POLICY_DIR)
    serve_with_open(socket)
    assert_policy_refuses_call(socket)
    text = status_text(socket)
    assert_locked(text, configured=True)
    # The first folder of the chain the account owns is named, with its owner
    # and mode.
    reason = f"{DRIVER_DIR} is owned by uid {os.getuid()} with mode "
    assert f"user policy source: built_in_locked ({reason}" in text, text
    assert f"managed policy source: built_in_locked ({reason}" in text, text


def test_doctor_names_the_apps_own_bundle_id():
    result = driver("doctor", "--json", timeout=120)
    report = json.loads(result.stdout)
    probes = {probe["label"]: probe for probe in report["probes"]}
    assert probes["bundle id"]["message"] == BUNDLE_ID, probes.get("bundle id")


def test_history_admission_checks_the_apps_own_bundle_id(socket):
    # An ad hoc signature is never admitted to Computer History, which needs a
    # certificate-backed signature. The identity check before that must pass:
    # it compares the signature's identifier with the app's own bundle id.
    result = driver("--socket", socket, "serve", "--experimental-history", timeout=60)
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert "Computer History admission error" in output, output
    assert "signing identifier does not match" not in output, output
    assert "signature is not certificate-backed" in output, output


def sha256_of(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize("command", [("update", "--apply"), ("check-update",)])
def test_updates_are_left_to_the_operator(command):
    before = sha256_of(BIN)
    result = driver(*command, timeout=120)
    output = result.stdout + result.stderr
    assert result.returncode != 0, output
    assert UPDATE_REFUSAL in output, output
    assert sha256_of(BIN) == before
