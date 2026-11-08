import base64
import json
import os
from pathlib import Path
import signal
import socket
import stat
import struct
from types import SimpleNamespace

import pytest

from services.agent import daemon_guard as guard


IMAGE = "sha256:" + "c" * 64
CID = "a" * 64
FOREIGN = "b" * 64
SOURCE = "# trusted verifier\n".encode()
ARTIFACT = b"invoice bytes\x00\xff"


def request(artifact=ARTIFACT):
    return json.dumps({
        "artifact_b64": base64.b64encode(artifact).decode(),
        "artifact_sha256": guard.digest(artifact),
    }).encode()


class Docker:
    def __init__(self):
        self.calls = []
        self.create_reply = CID.encode() + b"\n"
        self.mutate = None
        self.fail_create = False
        self.fail_start = False
        self.fail_inventory = False
        self.fail_remove = False
        self.final_exit = 0
        self.result = {
            "status": "passed",
            "artifact_sha256": guard.digest(ARTIFACT),
            "verifier_sha256": guard.digest(SOURCE),
            "input_sha256": guard.INPUT_SHA256,
        }
        self.exists = False
        self.started = False
        self.name = None
        self.guard = guard.InvoiceGuard(IMAGE, SOURCE, command=self)

    def inspect(self, container_id):
        args = self.guard.verifier_args.copy()
        record = {
            "Id": container_id, "Name": f"/{self.name}", "Image": IMAGE,
            "Path": guard.PYTHON, "Args": args, "Mounts": [],
            "Config": {
                "Labels": {guard.LABEL: self.name}, "Entrypoint": [guard.PYTHON],
                "Cmd": args.copy(), "User": "65534:65534", "OpenStdin": True, "Tty": False,
                "WorkingDir": "/", "Healthcheck": {"Test": ["NONE"]},
            },
            "HostConfig": {
                "NetworkMode": "none", "IpcMode": "none", "CgroupnsMode": "private",
                "Runtime": "runc", "Privileged": False, "ReadonlyRootfs": True,
                "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges=true"],
                "AutoRemove": False, "PublishAllPorts": False, "Memory": guard.MEMORY,
                "MemorySwap": guard.MEMORY, "NanoCpus": guard.CPU, "PidsLimit": guard.PIDS,
                "RestartPolicy": {"Name": "no"}, "LogConfig": {"Type": "none"},
            },
            "State": {
                "Status": "exited" if self.started else "created", "Running": False,
                "Pid": 0, "ExitCode": self.final_exit,
            },
        }
        if container_id == FOREIGN:
            record["Name"] = "/foreign-container"
            record["Config"]["Labels"] = {}
        if self.mutate is not None and not self.started:
            self.mutate(record)
        return json.dumps([record]).encode()

    def __call__(self, args, data=None):
        self.calls.append((args, data))
        verb = args[0]
        if verb == "create":
            self.name = args[args.index("--name") + 1]
            self.exists = True
            self.started = False
            if self.fail_create:
                raise guard.GuardError("docker_command_failed")
            return self.create_reply
        if verb == "inspect":
            return self.inspect(args[-1])
        if verb == "start":
            self.started = True
            if self.fail_start:
                raise guard.GuardError("docker_command_failed")
            return self.result if isinstance(self.result, bytes) else json.dumps(self.result).encode()
        if verb == "rm":
            assert args == ["rm", "--force", CID]
            if self.fail_remove:
                raise guard.GuardError("docker_command_failed")
            self.exists = False
            return CID.encode()
        if verb == "ls":
            assert args[:5] == ["ls", "--all", "--no-trunc", "--quiet", "--filter"]
            if self.fail_inventory:
                raise guard.GuardError("docker_command_failed")
            return (CID + "\n").encode() if self.exists and args[-1] != f"id={FOREIGN}" else b""
        raise AssertionError(args)

    @property
    def verbs(self):
        return [args[0] for args, _ in self.calls]

    def verify(self):
        return self.guard.verify(ARTIFACT, guard.digest(ARTIFACT))


@pytest.mark.parametrize("outcome", ["passed", "rejected"])
def test_verifies_fixed_profile_then_checks_absence(outcome):
    docker = Docker()
    docker.result["status"] = outcome
    result = docker.verify()
    assert result == {**docker.result, "container_id": CID, "cleanup_confirmed": True}
    assert docker.verbs == ["create", "inspect", "start", "inspect", "rm", "ls", "ls"]
    create = docker.calls[0][0]
    assert "--pull=never" in create and "--read-only" in create and "--network=none" in create
    assert create[create.index(IMAGE) + 1:] == ["-I", "-S", "-c", guard.BOOTSTRAP, SOURCE.decode()]
    assert docker.calls[2] == (["start", "-a", "-i", CID], ARTIFACT)
    assert docker.calls[-2][0][-1] == f"label={guard.LABEL}={docker.name}"
    assert docker.calls[-1][0][-1] == f"id={CID}"
    assert not docker.exists and not docker.guard.poisoned


@pytest.mark.parametrize(("block", "key", "value"), [
    (None, "Image", "sha256:" + FOREIGN),
    (None, "Args", ["-c", "other code"]),
    (None, "Mounts", [{"Source": "/var/run/docker.sock"}]),
    ("Config", "User", "0:0"),
    ("Config", "Volumes", {"/tmp": {}}),
    ("Config", "Healthcheck", {"Test": ["CMD", "x"]}),
    ("HostConfig", "Binds", ["/:/host"]),
    ("HostConfig", "Devices", [{"PathOnHost": "/dev/kmsg"}]),
    ("HostConfig", "DeviceRequests", [{"Count": 1}]),
    ("HostConfig", "Privileged", True),
    ("HostConfig", "CapDrop", []),
    ("HostConfig", "CapAdd", ["SYS_ADMIN"]),
    ("HostConfig", "SecurityOpt", ["no-new-privileges=true", "seccomp=unconfined"]),
    ("HostConfig", "NetworkMode", "host"),
    ("HostConfig", "PidMode", "host"),
    ("HostConfig", "Runtime", "external"),
    ("HostConfig", "ReadonlyRootfs", False),
    ("HostConfig", "PidsLimit", 0),
    ("HostConfig", "Memory", 0),
    ("HostConfig", "MemorySwap", -1),
    ("HostConfig", "NanoCpus", 0),
    ("State", "Status", "running"),
])
def test_rejects_effective_profile_before_start(block, key, value):
    docker = Docker()
    docker.mutate = lambda record: (record if block is None else record[block]).update({key: value})
    with pytest.raises(guard.GuardError, match="^profile_mismatch$"):
        docker.verify()
    assert docker.verbs == ["create", "inspect", "rm", "ls", "ls"]
    assert not docker.exists and not docker.guard.poisoned


@pytest.mark.parametrize("field", ["artifact_sha256", "verifier_sha256", "input_sha256", "status", "extra"])
def test_rejects_untrusted_verifier_result(field):
    docker = Docker()
    docker.result[field] = "b" * 64
    with pytest.raises(guard.GuardError, match="^invalid_verifier_response$"):
        docker.verify()
    assert "start" in docker.verbs and "rm" in docker.verbs
    assert not docker.exists


@pytest.mark.parametrize("which", ["start", "exit"])
def test_start_failure_or_exit_nonzero_still_cleans_up(which):
    docker = Docker()
    docker.fail_start = which == "start"
    docker.final_exit = 1 if which == "exit" else 0
    with pytest.raises(guard.GuardError, match="^verifier_failed$"):
        docker.verify()
    assert not docker.exists and not docker.guard.poisoned


@pytest.mark.parametrize("rm_fails", [False, True])
def test_poisoned_if_absence_is_indeterminate_or_container_remains(rm_fails):
    docker = Docker()
    docker.fail_remove = rm_fails
    docker.fail_inventory = not rm_fails
    with pytest.raises(guard.GuardError, match="^cleanup_unconfirmed$"):
        docker.verify()
    before = docker.calls.copy()
    with pytest.raises(guard.GuardError, match="^guard_unavailable$"):
        docker.verify()
    assert docker.calls == before


@pytest.mark.parametrize("create_raises", [False, True])
def test_uncertain_create_cleans_owned_label_without_retry_or_unlock(create_raises):
    docker = Docker()
    docker.create_reply = b"malformed ID"
    docker.fail_create = create_raises
    with pytest.raises(guard.GuardError, match="^create_uncertain$"):
        docker.verify()
    assert docker.verbs == ["create", "ls", "inspect", "rm", "ls"]
    assert not docker.exists and docker.guard.poisoned


def test_ambiguous_label_never_removes_foreign_container():
    docker = Docker()
    docker.create_reply = b"malformed ID"
    docker.mutate = lambda record: record.update({"Name": "/other"})
    with pytest.raises(guard.GuardError, match="^cleanup_unconfirmed$"):
        docker.verify()
    assert docker.verbs == ["create", "ls", "inspect"]
    assert docker.exists and docker.guard.poisoned


def test_foreign_create_reply_never_starts_or_removes_foreign_id():
    docker = Docker()
    docker.create_reply = FOREIGN.encode()
    with pytest.raises(guard.GuardError, match="^profile_mismatch$"):
        docker.verify()
    assert "start" not in docker.verbs
    assert [args[-1] for args, _ in docker.calls if args[0] == "rm"] == [CID]


def test_interrupt_during_start_runs_cleanup():
    docker = Docker()

    def command(args, data=None):
        if args[0] == "start":
            raise KeyboardInterrupt
        return docker(args, data)

    docker.guard.command = command
    with pytest.raises(KeyboardInterrupt):
        docker.verify()
    assert not docker.exists and not docker.guard.poisoned
    assert docker.verbs[-3:] == ["rm", "ls", "ls"]


def test_repeated_sigterm_does_not_interrupt_active_cleanup():
    docker = Docker()

    def command(args, data=None):
        if args[0] in ("start", "rm", "ls"):
            docker.guard.request_stop(signal.SIGTERM, None)
        return docker(args, data)

    docker.guard.command = command
    assert docker.verify()["cleanup_confirmed"]
    assert docker.verbs[-3:] == ["rm", "ls", "ls"]
    assert not docker.exists and not docker.guard.poisoned
    with pytest.raises(guard.GuardError, match="^guard_stopping$"):
        docker.verify()


def test_sigterm_before_start_cleans_created_container_without_starting():
    docker = Docker()

    def command(args, data=None):
        if args[0] == "inspect":
            docker.guard.request_stop(signal.SIGTERM, None)
        return docker(args, data)

    docker.guard.command = command
    with pytest.raises(guard.GuardError, match="^guard_stopping$"):
        docker.verify()
    assert docker.verbs == ["create", "inspect", "rm", "ls", "ls"]
    assert not docker.exists and not docker.guard.poisoned


@pytest.mark.parametrize("raw", [
    b'{"artifact_b64":"","artifact_b64":"","artifact_sha256":"' + b"b" * 64 + b'"}',
    b'{"artifact_b64":NaN,"artifact_sha256":"' + b"b" * 64 + b'"}',
    b'{"artifact_b64":"","artifact_sha256":"' + b"b" * 64 + b'","command":"exec"}',
    b'{"artifact_b64":"!","artifact_sha256":"' + b"b" * 64 + b'"}',
    b'{"artifact_b64":"YR==","artifact_sha256":"' + guard.digest(b"a").encode() + b'"}',
    b"[]", b"\xff", request() + b"{}", request(b"x" * 4097), b" " * (guard.FRAME_MAX + 1),
])
def test_request_rejects_bad_shape_encoding_and_bounds(raw):
    with pytest.raises(guard.GuardError, match="^invalid_request$"):
        guard.parse_request(raw)


def test_request_accepts_exact_limits():
    artifact = b"x" * guard.ARTIFACT_MAX
    frame = request(artifact).ljust(guard.FRAME_MAX)
    assert guard.parse_request(frame) == (artifact, guard.digest(artifact))


class Peer:
    def __init__(self, uid, data):
        self.uid = uid
        self.data = data
        self.reads = 0
        self.sent = []

    def getsockopt(self, level, kind, size):
        assert (level, kind, size) == (socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
        return struct.pack("=iII", 123, self.uid, 55)

    def settimeout(self, seconds):
        assert 0 < seconds <= guard.READ_SECONDS

    def recv(self, count):
        self.reads += 1
        if self.data is None:
            raise TimeoutError
        chunk, self.data = self.data[:count], self.data[count:]
        return chunk

    def sendall(self, raw):
        self.sent.append(raw)


@pytest.mark.parametrize(("uid", "frame", "status", "reason"), [
    (123, request(), "passed", None),
    (999, request(), "error", "unauthorized"),
    (123, None, "error", "invalid_request"),
    (123, b" " * (guard.FRAME_MAX + 1), "error", "invalid_request"),
])
def test_peer_credentials_eof_and_one_json_line(monkeypatch, uid, frame, status, reason):
    monkeypatch.setattr(socket, "SO_PEERCRED", 17, raising=False)
    docker = Docker()
    peer = Peer(uid, frame)
    guard.serve_peer(peer, docker.guard, 123)
    assert len(peer.sent) == 1 and peer.sent[0].count(b"\n") == 1
    response = json.loads(peer.sent[0])
    assert response["status"] == status
    if reason:
        assert response == {"status": "error", "reason": reason}
        assert docker.calls == []
    if uid != 123:
        assert peer.reads == 0


@pytest.mark.skipif(os.name != "posix", reason="Linux path contract")
@pytest.mark.parametrize(("directory_mode", "occupied", "reason"), [
    (stat.S_IFDIR | 0o750, False, None),
    (stat.S_IFDIR | 0o770, False, "invalid_socket_path"),
    (stat.S_IFLNK | 0o750, False, "invalid_socket_path"),
    (stat.S_IFDIR | 0o750, True, "socket_path_occupied"),
])
def test_socket_path_checks_every_ancestor_before_bind(monkeypatch, directory_mode, occupied, reason):
    path = Path("/run/private/guard.sock")
    monkeypatch.setattr(Path, "lstat", lambda p: SimpleNamespace(
        st_uid=123 if p == path.parent else 0,
        st_mode=directory_mode if p == path.parent else stat.S_IFDIR | 0o755,
    ))
    monkeypatch.setattr(os.path, "lexists", lambda p: occupied)
    if reason:
        with pytest.raises(guard.GuardError, match=f"^{reason}$"):
            guard._trusted_socket_path(str(path), 123)
    else:
        assert guard._trusted_socket_path(str(path), 123) == path
