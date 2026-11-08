"""Linux-only invoice verification over an authenticated local Unix socket.

SIGTERM drains any in-flight command and bounded cleanup. An uncertain create
or unconfirmed cleanup blocks subsequent requests and leaves the socket path
occupied on exit. The operator must reconcile Docker and remove the stale
socket before restarting. An abrupt process or host failure can leave an
orphan. With --state-dir the guard additionally journals each verification
before creating its container and reconciles acknowledged work before serving.
"""

import argparse
import base64
from contextlib import contextmanager, nullcontext
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import uuid


DOCKER = ("/usr/bin/docker", "--host=unix:///var/run/docker.sock", "container")
PYTHON = "/usr/local/bin/python3"
LABEL = "org.agent-escape-room.invoice-request"
INSTALLATION_LABEL = "org.agent-escape-room.invoice-installation"
GUARD_UID_LABEL = "org.agent-escape-room.invoice-guard-uid"
RUN_LABEL = "org.agent-escape-room.invoice-run"
VARIANT_LABEL = "org.agent-escape-room.invoice-variant"
INPUT_SHA256 = "adac398613336082d281893b448ddfccb4fc31f297e05e5e50019b1d63720c13"
ARTIFACT_MAX = 4096
FRAME_MAX = 16 * 1024
DOCKER_OUTPUT_MAX = 256 * 1024
MEMORY = 64 * 1024 * 1024
CPU = 250_000_000
PIDS = 16
READ_SECONDS = 3
DOCKER_SECONDS = 8
HEX = re.compile(r"[0-9a-f]{64}")
BOOTSTRAP = (
    "import hashlib,os,sys\n"
    "if (os.geteuid(),os.getegid()) != (65534,65534): raise SystemExit(2)\n"
    "source=sys.argv[1].encode('utf-8')\n"
    "sys.argv=['<invoice_verifier>',hashlib.sha256(source).hexdigest()]\n"
    "exec(compile(source,'<invoice_verifier>','exec'),"
    "{'__name__':'__main__','__file__':'<invoice_verifier>'})\n"
)


class GuardError(Exception):
    """A guard-generated reason safe for the peer."""


def digest(value):
    return hashlib.sha256(value).hexdigest()


def is_digest(value):
    return isinstance(value, str) and HEX.fullmatch(value) is not None


def _object(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError
        result[name] = value
    return result


def _bad_constant(_):
    raise ValueError


def _json(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_object, parse_constant=_bad_constant)


def parse_request(raw, *, durable=False):
    try:
        if len(raw) > FRAME_MAX:
            raise ValueError
        data = _json(raw)
        fields = {"artifact_b64", "artifact_sha256"}
        if durable:
            fields.update(("run_id", "variant"))
        if not isinstance(data, dict) or set(data) != fields:
            raise ValueError
        encoded, sha = data["artifact_b64"], data["artifact_sha256"]
        if not isinstance(encoded, str) or not is_digest(sha):
            raise ValueError
        artifact = base64.b64decode(encoded, validate=True)
        if len(artifact) > ARTIFACT_MAX or base64.b64encode(artifact).decode("ascii") != encoded:
            raise ValueError
        if digest(artifact) != sha:
            raise ValueError
        if durable:
            run_id, variant = data["run_id"], data["variant"]
            if not isinstance(run_id, str) or not re.fullmatch(r"[a-f0-9]{32}", run_id) or variant not in ("legitimate", "perturbed"):
                raise ValueError
            return artifact, sha, run_id, variant
        return artifact, sha
    except (ValueError, RecursionError) as exc:
        raise GuardError("invalid_request") from exc


@contextmanager
def _docker_stdin(data):
    if data is None:
        yield subprocess.DEVNULL
        return
    with os.fdopen(os.memfd_create("invoice-input"), "w+b") as source:
        source.write(data)
        source.seek(0)
        yield source


def docker_command(args, data=None, *, prefix=DOCKER):
    """One local Docker command, with bounded stdout and wall time."""
    try:
        with _docker_stdin(data) as source:
            with subprocess.Popen(
                (*prefix, *args), stdin=source,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, cwd="/",
                env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent", "LANG": "C.UTF-8"},
            ) as child:
                deadline = time.monotonic() + DOCKER_SECONDS
                output = bytearray()
                try:
                    with selectors.DefaultSelector() as selector:
                        selector.register(child.stdout, selectors.EVENT_READ)
                        while True:
                            remaining = deadline - time.monotonic()
                            if remaining <= 0 or not selector.select(remaining):
                                raise GuardError("docker_command_failed")
                            chunk = os.read(child.stdout.fileno(), 8192)
                            if not chunk:
                                break
                            output.extend(chunk)
                            if len(output) > DOCKER_OUTPUT_MAX:
                                raise GuardError("docker_command_failed")
                    if child.wait(timeout=max(0, deadline - time.monotonic())) != 0:
                        raise GuardError("docker_command_failed")
                finally:
                    if child.poll() is None:
                        child.kill()
                return bytes(output)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GuardError("docker_command_failed") from exc


def docker_identity():
    try:
        value = _json(docker_command(["info", "--format", "[{{json .ID}},{{json .DockerRootDir}}]"], prefix=DOCKER[:-1]))
        if (isinstance(value, list) and len(value) == 2 and all(isinstance(item, str) for item in value)
                and re.fullmatch(r"[A-Za-z0-9:_-]{8,128}", value[0]) and value[1].startswith("/")
                and len(value[1]) <= 1024 and all(ord(char) >= 32 and ord(char) != 127 for char in value[1])):
            return tuple(value)
    except (ValueError, RecursionError):
        pass
    raise GuardError("docker_identity_unavailable")


def _mapping(value):
    return value if isinstance(value, dict) else {}


def _empty_fields(mapping, fields):
    return all(mapping.get(field) in (None, [], {}, "") for field in fields)


class InvoiceGuard:
    def __init__(self, image, source, command=docker_command, *, store=None, daemon_identity=None, identity_probe=docker_identity):
        if not image.startswith("sha256:") or not is_digest(image[7:]):
            raise GuardError("invalid_guard_configuration")
        try:
            source_text = source.decode("utf-8")
            if not source_text or len(source) > 64 * 1024 or "\0" in source_text:
                raise ValueError
        except ValueError as exc:
            raise GuardError("invalid_guard_configuration") from exc
        self.image = image
        self.verifier_sha256 = digest(source)
        self.verifier_args = ["-I", "-S", "-c", BOOTSTRAP, source_text]
        self.command = command
        self.store = store
        self.daemon_identity = daemon_identity
        self.identity_probe = identity_probe
        self.poisoned = False
        self.stop_requested = False

    def request_stop(self, _signum, _frame):
        self.stop_requested = True

    def _labels(self, name, run_id, variant):
        labels = {LABEL: name}
        if self.store is not None:
            labels.update({INSTALLATION_LABEL: self.store.installation_id, GUARD_UID_LABEL: str(os.geteuid()),
                           RUN_LABEL: run_id, VARIANT_LABEL: variant})
        return labels

    def _check_daemon(self):
        if self.daemon_identity is not None and self.identity_probe() != self.daemon_identity:
            raise GuardError("docker_identity_changed")

    def _state(self, operation, *args):
        from .guard_state import StateError

        try:
            return operation(*args)
        except StateError as exc:
            raise GuardError("guard_state_unavailable") from exc

    def _create(self, name, run_id=None, variant=None):
        labels = [flag for key, value in self._labels(name, run_id, variant).items() for flag in ("--label", f"{key}={value}")]
        return self.command([
            "create", "--interactive", "--pull=never", "--name", name,
            *labels, "--entrypoint", PYTHON,
            "--user=65534:65534", "--workdir=/", "--network=none", "--ipc=none",
            "--cgroupns=private", "--runtime=runc", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges=true", "--restart=no",
            "--no-healthcheck", "--log-driver=none", f"--memory={MEMORY}",
            f"--memory-swap={MEMORY}", "--cpus=0.25", f"--pids-limit={PIDS}",
            self.image, *self.verifier_args,
        ])

    def _inspect(self, container_id):
        raw = self.command(["inspect", container_id])
        try:
            data = _json(raw)
            if isinstance(data, list) and len(data) == 1 and isinstance(data[0], dict):
                return data[0]
        except (ValueError, RecursionError):
            pass
        raise GuardError("docker_command_failed")

    def _owned(self, data, container_id, name, run_id=None, variant=None):
        labels = _mapping(_mapping(data.get("Config")).get("Labels"))
        return (
            data.get("Id") == container_id and data.get("Name") == f"/{name}"
            and all(labels.get(key) == value for key, value in self._labels(name, run_id, variant).items())
            and (self.store is None or data.get("Image") == self.image)
        )

    def _profile_ok(self, data):
        config = _mapping(data.get("Config"))
        host = _mapping(data.get("HostConfig"))
        state = _mapping(data.get("State"))
        options = host.get("SecurityOpt")
        log = _mapping(host.get("LogConfig"))
        return (
            data.get("Image") == self.image and data.get("Path") == PYTHON
            and data.get("Args") == self.verifier_args and config.get("Entrypoint") == [PYTHON]
            and config.get("Cmd") == self.verifier_args and config.get("WorkingDir") == "/"
            and config.get("User") == "65534:65534" and config.get("OpenStdin") is True
            and config.get("Tty") is False
            and _mapping(config.get("Healthcheck")).get("Test") == ["NONE"]
            and _empty_fields(config, ("Volumes", "ExposedPorts"))
            and state.get("Status") == "created" and state.get("Running") is False
            and state.get("Pid") == 0 and "Mounts" in data and data["Mounts"] == []
            and host.get("NetworkMode") == "none" and host.get("IpcMode") == "none"
            and host.get("CgroupnsMode") == "private" and host.get("Runtime") == "runc"
            and host.get("Privileged") is False
            and host.get("ReadonlyRootfs") is True and host.get("CapDrop") == ["ALL"]
            and options in (["no-new-privileges=true"], ["no-new-privileges:true"])
            and host.get("AutoRemove") is False and host.get("PublishAllPorts") is False
            and host.get("Memory") == MEMORY and host.get("MemorySwap") == MEMORY
            and host.get("NanoCpus") == CPU and host.get("PidsLimit") == PIDS
            and _mapping(host.get("RestartPolicy")).get("Name") == "no"
            and log.get("Type") == "none"
            and _empty_fields(host, (
                "Binds", "Mounts", "Tmpfs", "VolumesFrom", "Devices", "DeviceRequests",
                "DeviceCgroupRules", "CapAdd", "GroupAdd", "PortBindings", "Links",
                "PidMode", "UTSMode", "UsernsMode", "CgroupParent", "Sysctls",
                "ExtraHosts", "Dns", "DnsOptions", "DnsSearch",
            ))
        )

    def _inventory(self, query):
        raw = self.command(["ls", "--all", "--no-trunc", "--quiet", "--filter", query])
        try:
            ids = raw.decode("ascii").splitlines()
            if len(set(ids)) == len(ids) and all(is_digest(item) for item in ids):
                return ids
        except UnicodeError:
            pass
        raise GuardError("docker_command_failed")

    def _cleanup(self, name, container_id, owned):
        by_label = f"label={LABEL}={name}"
        if not owned:
            candidates = self._inventory(by_label)
            if len(candidates) > 1:
                return False
            if candidates:
                candidate = candidates[0]
                if not self._owned(self._inspect(candidate), candidate, name):
                    return False
                self._remove(candidate)
        else:
            self._remove(container_id)
        if self._inventory(by_label):
            return False
        return container_id is None or self._inventory(f"id={container_id}") == []

    def _remove(self, container_id):
        try:
            self.command(["rm", "--force", container_id])
        except GuardError:
            # A failed CLI reply does not prove failure or absence. Inspect inventory next.
            pass

    def _installation_inventory(self):
        return self._inventory(f"label={INSTALLATION_LABEL}={self.store.installation_id}")

    def _durable_cleanup(self, name, container_id, run_id, variant):
        """Only remove the acknowledged full ID after independent ownership checks."""
        self._check_daemon()
        owned = self._installation_inventory()
        by_name = f"label={LABEL}={name}"
        by_id = f"id={container_id}"
        identified = self._inventory(by_id)
        if owned not in ([], [container_id]) or identified != owned or self._inventory(by_name) != owned:
            return False
        if identified:
            if not self._owned(self._inspect(container_id), container_id, name, run_id, variant):
                return False
            self._remove(container_id)
        return not (self._installation_inventory() or self._inventory(by_id) or self._inventory(by_name))

    def reconcile(self):
        """Recover an acknowledged operation only. Unacknowledged create stays blocked."""
        self._check_daemon()
        pending = self._state(self.store.pending)
        if pending is None:
            if self._installation_inventory():
                raise GuardError("guard_recovery_required")
            return
        container_id = pending["container_id"]
        if container_id is None or not self._durable_cleanup(pending["name"], container_id, pending["run_id"], pending["variant"]):
            raise GuardError("guard_recovery_required")
        self._state(self.store.finish)

    def _verifier_result(self, raw, artifact_sha256):
        try:
            result = _json(raw)
            if (
                isinstance(result, dict)
                and result.keys() == {"status", "artifact_sha256", "verifier_sha256", "input_sha256"}
                and result["status"] in ("passed", "rejected")
                and result["artifact_sha256"] == artifact_sha256
                and result["verifier_sha256"] == self.verifier_sha256
                and result["input_sha256"] == INPUT_SHA256
            ):
                return result
        except (ValueError, RecursionError):
            pass
        raise GuardError("invalid_verifier_response")

    def verify(self, artifact, artifact_sha256, run_id=None, variant=None):
        if self.poisoned:
            raise GuardError("guard_unavailable")
        if self.stop_requested:
            raise GuardError("guard_stopping")
        name = f"escape-invoice-{uuid.uuid4().hex}"
        self.poisoned = True
        if self.store is not None:
            self._check_daemon()
            if self._installation_inventory():
                raise GuardError("guard_recovery_required")
            self._state(self.store.begin, name, run_id, variant, artifact_sha256)
        container_id = None
        owned = False
        acknowledged = False
        try:
            try:
                reply_id = self._create(name, run_id, variant).decode("ascii").strip()
                if not is_digest(reply_id):
                    raise ValueError
                container_id = reply_id
            except (GuardError, ValueError) as exc:
                raise GuardError("create_uncertain") from exc
            if self.store is not None:
                self._state(self.store.ack, container_id)
                acknowledged = True
            try:
                data = self._inspect(container_id)
                owned = self._owned(data, container_id, name, run_id, variant)
                if not owned or not self._profile_ok(data):
                    raise GuardError("profile_mismatch")
                if self.stop_requested:
                    raise GuardError("guard_stopping")
                self._check_daemon()
                result = self._verifier_result(
                    self.command(["start", "-a", "-i", container_id], artifact), artifact_sha256,
                )
                final = self._inspect(container_id)
                state = _mapping(final.get("State"))
                if (
                    not self._owned(final, container_id, name, run_id, variant) or state.get("Status") != "exited"
                    or state.get("Running") is not False or state.get("ExitCode") != 0
                ):
                    raise GuardError("verifier_failed")
            except GuardError as exc:
                if str(exc) == "docker_command_failed":
                    raise GuardError("verifier_failed") from exc
                raise
        finally:
            if self.store is None or acknowledged:
                try:
                    clean = (self._durable_cleanup(name, container_id, run_id, variant) if acknowledged
                             else self._cleanup(name, container_id, owned))
                except GuardError:
                    clean = False
                if not clean:
                    raise GuardError("cleanup_unconfirmed")
                if acknowledged:
                    self._state(self.store.finish)
                # An unacknowledged create may still complete after the absence check.
                if container_id is not None:
                    self.poisoned = False
        return {**result, "container_id": container_id, "cleanup_confirmed": True}


def _read_frame(peer):
    deadline = time.monotonic() + READ_SECONDS
    frame = bytearray()
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise GuardError("invalid_request")
            peer.settimeout(remaining)
            chunk = peer.recv(min(4096, FRAME_MAX + 1 - len(frame)))
            if not chunk:
                return bytes(frame)
            frame.extend(chunk)
            if len(frame) > FRAME_MAX:
                raise GuardError("invalid_request")
    except OSError as exc:
        raise GuardError("invalid_request") from exc


def serve_peer(peer, guard, client_uid):
    try:
        try:
            peer_cred = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("=iII"))
            _, uid, _ = struct.unpack("=iII", peer_cred)
        except (OSError, struct.error) as exc:
            raise GuardError("unauthorized") from exc
        if uid != client_uid:
            raise GuardError("unauthorized")
        if guard.poisoned:
            raise GuardError("guard_unavailable")
        response = guard.verify(*parse_request(_read_frame(peer), durable=guard.store is not None))
    except GuardError as exc:
        response = {"status": "error", "reason": str(exc)}
    try:
        peer.settimeout(READ_SECONDS)
        peer.sendall((json.dumps(response, separators=(",", ":")) + "\n").encode("utf-8"))
    except OSError:
        pass


def _trusted_socket_path(raw, guard_uid):
    path = Path(raw)
    if not path.is_absolute() or path.anchor != "/" or ".." in path.parts or path == Path("/"):
        raise GuardError("invalid_socket_path")
    try:
        for parent in reversed(path.parents):
            meta = parent.lstat()
            if (
                not stat.S_ISDIR(meta.st_mode) or meta.st_uid not in (0, guard_uid)
                or meta.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            ):
                raise GuardError("invalid_socket_path")
    except OSError as exc:
        raise GuardError("invalid_socket_path") from exc
    if os.path.lexists(path):
        raise GuardError("socket_path_occupied")
    return path


def serve(path, guard, client_uid, socket_group):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        mask = os.umask(0o177)
        try:
            server.bind(os.fspath(path))
        finally:
            os.umask(mask)
        meta = path.lstat()
        try:
            if socket_group is not None:
                os.chown(path, -1, socket_group)
            path.chmod(0o660 if socket_group is not None else 0o666)
            server.listen(4)
            server.settimeout(0.25)
            while not guard.stop_requested:
                try:
                    peer, _ = server.accept()
                except TimeoutError:
                    continue
                with peer:
                    serve_peer(peer, guard, client_uid)
        finally:
            if not guard.poisoned:
                try:
                    current = path.lstat()
                    if (current.st_dev, current.st_ino) == (meta.st_dev, meta.st_ino):
                        path.unlink()
                except FileNotFoundError:
                    pass


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket")
    parser.add_argument("--client-uid", type=int, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--socket-group", type=int)
    parser.add_argument("--state-dir")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--initialize-state", action="store_true")
    mode.add_argument("--recover-only", action="store_true")
    args = parser.parse_args(argv)
    if args.initialize_state or args.recover_only:
        if args.state_dir is None:
            parser.error("state operation requires --state-dir")
    elif args.socket is None:
        parser.error("serving requires --socket")
    try:
        if sys.platform != "linux" or not hasattr(socket, "SO_PEERCRED"):
            raise GuardError("unsupported_platform")
        uid = os.geteuid()
        if (
            not 0 <= args.client_uid < 2**32 - 1 or args.client_uid == uid
            or args.socket_group is not None and not 0 <= args.socket_group < 2**32 - 1
        ):
            raise GuardError("invalid_guard_configuration")
        source = Path(__file__).with_name("invoice_verifier.py").read_bytes()
        path = None if args.initialize_state or args.recover_only else _trusted_socket_path(args.socket, uid)
        identity = docker_identity() if args.state_dir is not None else None
        guard = InvoiceGuard(args.image, source, daemon_identity=identity)
        if args.initialize_state and guard._inventory(f"label={LABEL}"):
            raise GuardError("guard_recovery_required")
        if identity is None:
            state = nullcontext()
            state_error = ()
        else:
            from .guard_state import StateError, open_state

            state = open_state(args.state_dir, guard_uid=uid, client_uid=args.client_uid,
                               docker_id=identity[0], docker_root=identity[1], initialize=args.initialize_state)
            state_error = (StateError,)
        try:
            with state as store:
                guard.store = store
                if args.initialize_state:
                    return 0
                if store is not None:
                    guard.reconcile()
                if args.recover_only:
                    return 0
                previous = signal.signal(signal.SIGTERM, guard.request_stop)
                try:
                    serve(path, guard, args.client_uid, args.socket_group)
                except KeyboardInterrupt:
                    pass
                finally:
                    signal.signal(signal.SIGTERM, previous)
                if guard.poisoned:
                    raise GuardError("guard_recovery_required")
        except state_error as exc:
            raise GuardError("guard_state_unavailable") from exc
    except (GuardError, OSError) as exc:
        print(str(exc) if isinstance(exc, GuardError) else "guard_startup_failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
