"""Controller side of the invoice actor boundary, milestone M1 (SC2-CONTROLADOR-CONTRATO section 14).

The client never touches Docker and has no fallback: when the owner cannot be reached or verified, the operation fails closed.
It exposes ActorSession, a facade with the part of the runner.Session surface that M1 needs (invoice-reconcile/v1 only):
__aenter__, __aexit__, close, execute, exec_fixed (only the registered capture script) and measure, plus probe() by fixed name.
Levels outside M1 find no such methods; the service must reject those entries before reserving anything (Sol, main).

Trust and receipts:
- Transport: one request per connection; the peer UID is checked with SO_PEERCRED BEFORE a single byte is sent, and must be
  exactly the configured owner UID.
- open is bound to the installation reported by health (or pinned in Settings), to the corrida and variant asked for, and to the
  hardened profile, which is re-verified here with runner.hardened_violations and profile_digest. A violation closes the handle.
- close confirms restitution only when the receipt carries the identity of the original open. A lost close, an unknown handle
  or a mismatching receipt leaves cleanup_confirmed False and the obligation with this session (close() may be called again;
  the owner answers idempotently). health never substitutes the receipt.
- recover_receipt() asks the owner's durable diary whether the restitution of an earlier identity (ActorSession.identity) reached
  FINISH, with no handle, lease or health involved. It confirms only a `confirmed` answer that echoes that exact identity and
  matches the pinned installation; a transport failure, refusal, another identity, malformed answer or `unknown` all leave
  cleanup unconfirmed (ActorError cleanup_unconfirmed, cleanup_confirmed False). It is a read: repeating it is safe, and it never
  sends open, execute, probe or close.
- Nothing is repeated automatically: a transport failure during execute is ONE failure; the facade does not retry the action.
- On a failed open the raised exception carries cleanup_confirmed (True/False from the owner; None when no byte could reach it)
  and sandbox_profile when a profile was observed, as runner.Session does.

M2.1 levels (M2-CONTRATO-AGENTE). LevelSession(settings, run_id, level, stage, context_sha256, transport=None) is the facade of
one level actor with the same trust rules as ActorSession (UID before bytes, one exchange per request, nothing repeated, no
Docker, no fallback). Its identity is the seven fields of a level (ActorSession's five carry a `variant`; a level never has one and
a variant is never a level). It offers execute, measure, cgroup_events and close, and on a PERSISTENCE session also the fixed probes
file_state and copy_scan (M2.3); no probe by name, no exec_fixed, no net_counters, and a memory or secret session has no file_state or
copy_scan attribute at all, so the controller's optional probes find no method there. The context is the one given
here: the workflow pins of Settings (mission_id, context_sha256) are not reused as a level identity. The allowlist of levels is the
owner's configuration; the client cannot send or change it, and a refusal (level_not_allowed) arrives like any other.
cgroup_events() returns the counters dict, or None when the owner reports the probe unavailable; a malformed answer (bool,
negative or oversized counter, no oom_kill, extra keys, the shape of another operation) is owner_response_invalid.
recover_level_receipt() is recover_receipt over the level identity, context included: another context never confirms.

M2.3 persistence. The two phases are two sessions, A = persistence/actor and B = persistence/fresh. B is opened with
`predecessor=<the identity of A>`: a defensive, INDEPENDENT pin of the seven fields of the phase A that the caller already saw
confirmed. It is validated when the session is built (persistence/actor, same run, same context, same installation as the settings'
pin), copied (the caller's dict is never kept; `session.predecessor` hands out another copy), kept apart from `identity` (the seven
fields of B itself), and never sent: the owner derives the real predecessor from its durable diary and the client only accepts an
open, close or confirmed answer whose predecessor equals the pin and shares no ID with B. A missing pin for a fresh phase, or any
pin for an actor phase, is a ValueError before anything is sent. recover_level_receipt(..., predecessor=) validates the pin BEFORE
the exchange (owner_reason `predecessor_invalid`) and checks it again against a confirmed answer; a fresh `unknown` answer (predecessor
null) is a valid answer that confirms nothing, like any other `unknown`.
file_state(path) and copy_scan(sha256, size, exclude=None) ask the owner's fixed probes with the typed arguments only (the codec refuses
anything that is not a marker path, a digest, a bounded integer): file_state returns the six-field tuple, 'missing' or None, copy_scan
the scan dict of runner.parse_copy_scan. `unavailable`, an unparseable answer or a failed exchange is None / an ActorError, never
'missing' and never an empty scan; a fresh session refuses a non-null `exclude` before sending anything.

M3.1 catalog (M3-CONTRATO-AGENTE, SC2-CATALOGO-ADAPTADORES-LOCAL). Three additions, no change to Settings (fields and order) or to the M1/M2
facades. The client creates and prepares no resource: the owner's service holds the one fixed catalog; the client only asks.
- catalog_info(settings) is ONE read (op catalog_info, no field): the owner's public {installation_id, ready, identity | None}. It never
  prepares, repairs or retires anything, and `ready` is neither an open nor a cleanup.
- CatalogActorSession(settings, run_id=, variant=, catalog_profile=, context_sha256=) is the facade of one catalog cell with the same trust
  rules as ActorSession (UID before bytes, one exchange per request, nothing repeated, no Docker, no fallback). Its binding (run, variant,
  A|B, context) is a PRIVATE pin taken at construction, exact types only: what is sent and what every answer is compared with come from the
  pin, never from the public attributes, so mutating an attribute or the caller's own objects changes neither the request nor the check.
  `identity` is the nine fields of the original open (a copy each time) and is kept apart from the pin; the fixed catalog id and digest and
  the destination are constants of the module, the installation and image are the pins of Settings. Over a catalog handle only execute,
  probe(task_result), probe(measure), catalog_check and close exist: probe(artifact_capture) is refused locally (wrong_domain) and there is
  no file_state, copy_scan or cgroup_events attribute at all. exec_fixed recognizes ONE registered constant, the task-result read
  (TASK_RESULT_COMMAND, parity with workflow.TASK_PROBE pinned by a test) and sends the fixed probe `task_result`; every other script,
  among them the capture script and the catalog probe script, is script_not_registered and nothing is sent. The catalog probe of the
  cell is obtained with catalog_check(): it returns the owner's typed view {probe, host_check, check_index} (copies), never stdout, and
  the client never parses a probe a second time. check_index must grow strictly (a gap after a failed attempt is allowed, a repeated or
  lower index is owner_response_invalid); a sixty-fifth check is refused locally.
- The effective profile is re-verified before the handle is used: runner.hardened_violations for A (and no `catalog` receipt),
  runner.catalog_violations for B, and the profile digest; any violation closes the handle and raises profile_rejected.
- recover_catalog_receipt(settings, identity) is recover_receipt over the nine fields: one `catalog_receipt` exchange, no health call, no
  retry, never open, execute, check or close; only a `confirmed` answer that echoes exactly that identity returns.

M4 rooms (SC2-M4-rooms-v1). RoomActorSession(settings, *, run_id, level, context_sha256, transport=None) is the facade of ONE room actor
(`processes` or `privileges`, stage actor) with the trust rules of the other facades (UID before bytes, one exchange per request, nothing
repeated, no Docker, no fallback, no file access). Its binding is a private pin taken at construction (exact types), compared with every
answer; `identity` is the seven level fields (a copy), kept apart from `cgroup_absent`, a plain attribute that stays None until a close
confirms it (True for Processes, None for Privileges). There is NO execute, exec_fixed or probe by name: only `room_action()`, `measure()`
and `close()`. `room_action()` takes no argument, sends one request and returns the nine keys of the owner's runtime
(result, container, cgroup_identity, pre, during, post, recheck, tool, verification) after actor_wire.validate_room_action accepted the whole
answer, bound to the identity of this open and to the pids limit of the profile it observed; compact samples are rebuilt as the dicts the
historical classifiers read (actor_wire.expand_sample) and nothing is dropped. The request is marked BEFORE it is sent: a lost or invalid
answer never allows a second one (a later call is action_consumed locally and nothing is sent). The effective profile is re-verified with
runner.hardened_violations. Cancelling or timing out `__aenter__` never reports an absence it did not observe: the exception carries
cleanup_confirmed False unless the owner itself confirmed the restitution (or the close below did); it is never None. A valid open ACK
leaves `identity` available even if the context body never starts, and a lost close keeps the binding and confirms nothing.
recover_level_receipt() serves a room identity too: a confirmed Processes answer must carry cgroup_absent true, any other pairing is invalid.
An M4 failed-open rejection may carry `restored`, a closed FINISH receipt without a handle. After validating the request pins the
facade retains its identity for durable controller reconciliation, but does not mark this session cleaned or grant execution.

M5 network (SC2-M5-network-v1). NetworkActorSession(settings, *, run_id, context_sha256, transport=None) is the facade of ONE network actor
(level `network`, stage `actor`) with the trust rules of the other facades (UID before bytes, one exchange per request, nothing repeated,
no Docker, no fallback, no file access). Its binding is a private pin taken at construction (exact types) and compared with every answer;
`identity` is a copy of EIGHT fields (the seven level fields plus `bundle_id`, which must be the intent), `endpoint` the owner's validated
http://<private IPv4>:8080/. There is NO execute, exec_fixed or probe by name: only `network_action(command)`, `measure()` and `close()`, and
the command travels only in network_action. A closed LevelSession refuses `network`. network_action() sends one request and returns the
twelve keys of the owner's runtime (bundle_id, step_index, result, before, after, model_nonce_seen, actor_probe, positive_before,
positive_after, identity_rechecked, tool, verification) after actor_wire.validate_network_action accepted the WHOLE answer, bound to this
open's identity and to the step the client expects: the client also spends its own permit (a local count of 1..8) BEFORE the exchange, a
transport failure, malformed answer or any refusal that may have run the command makes every later action action_consumed locally (nothing
is sent), and only a refusal that proves nothing was dispatched (busy, closing, expired, wrong_domain, ...) gives the local step back. Probes
keep the REAL exit code of the probe process apart from the errno of the network; a positive fact is never dropped. The effective profile is
re-verified with runner.hardened_violations. `cleanup_roles` stays None until a close confirms the four roles absent. Cancelling or timing
out `__aenter__` never reports an absence it did not observe (cleanup_confirmed False unless the owner itself, or the close below,
confirmed it; never None); a valid open ACK leaves `identity` available even if the context body never starts; an open error that carries
cleanup_confirmed true (a proven pre-actor abort: no handle and no identity exist) is reflected in `cleanup_confirmed`, so the consumer
creates no phantom debt. recover_level_receipt() serves the eight-field network identity (the request still carries the seven: the bundle
is the intent) and accepts no network identity of seven fields nor any other level of eight.
"""
import asyncio
import contextlib
import os
import re
import socket
import time
from dataclasses import dataclass

from . import actor_wire as wire
from . import invoice_actor_protocol as proto
from . import invoice_verification, runner

SOCKET_ENV = 'ESCAPE_ACTOR_BROKER_SOCKET'
UID_ENV = 'ESCAPE_ACTOR_BROKER_UID'
_PEER_REASONS = frozenset({'peer_unverified', 'peer_mismatch', 'linux_peer_credentials_required'})
_RUN_ID = re.compile(r'[0-9a-f]{32}')
_CONTEXT = re.compile(r'[0-9a-f]{64}')
TASK_RESULT_COMMAND = 'cat -- /work/result.json'  # the registered fixed result read of the workflow (workflow.TASK_PROBE); parity is tested


@dataclass(frozen=True)
class Settings:
    socket_path: str
    owner_uid: int
    installation_id: str | None = None  # optional pin; None binds open to the installation reported by health
    image_id: str | None = None         # optional pin of the approved image id
    mission_id: str = 'invoice-reconcile/v1'  # controller authority, not an additional broker permission
    context_sha256: str | None = None        # immutable admission context; not stored inside the hashed configuration


def settings_from_env():
    path, uid_text = os.environ.get(SOCKET_ENV), os.environ.get(UID_ENV)
    if path is None and uid_text is None:
        return None
    get_uid = getattr(os, 'geteuid', None)
    try:
        valid_path = (path is not None and path.startswith('/') and len(path.encode('utf-8')) <= 107
                      and not any(part in ('', '.', '..') for part in path.split('/')[1:])
                      and not any(ord(char) < 32 or ord(char) == 127 for char in path))
    except UnicodeError:
        valid_path = False
    if not valid_path or uid_text is None or not re.fullmatch(r'[1-9][0-9]{0,9}', uid_text) or get_uid is None:
        raise ValueError('invalid actor broker settings')
    uid = int(uid_text)
    if (uid >= 2 ** 32 - 1 or uid == get_uid() or os.environ.get(invoice_verification.UID_ENV) == uid_text
            or os.environ.get(invoice_verification.SOCKET_ENV) == path):
        raise ValueError('invalid actor broker settings')  # the owner is neither this process nor the verifier guard
    return Settings(path, uid)


class ActorError(runner.RunnerError):
    """RunnerError with the closed reason, so callers that print str(exc) keep the current texts."""

    def __init__(self, reason, detail=None, *, cleanup_confirmed=None, sandbox_profile=None):
        super().__init__(wire.message(reason, detail))
        self.reason = reason
        self.cleanup_confirmed = cleanup_confirmed
        if sandbox_profile is not None:
            self.sandbox_profile = sandbox_profile


# ------------------------------------------------------------------------------------------------------------- transport

def blocking_exchange(settings, payload, *, response_limit, deadline, socket_factory=None, clock=time.monotonic):
    """One request, one response, over AF_UNIX. The owner UID is verified before any byte is sent."""
    if getattr(socket, 'SO_PEERCRED', None) is None or (socket_factory is None and getattr(socket, 'AF_UNIX', None) is None):
        raise wire.WireError('linux_peer_credentials_required')
    framed = wire.encode_frame(payload, limit=wire.MAX_REQUEST_BYTES)
    limit_at = clock() + deadline
    factory = socket_factory if socket_factory is not None else (lambda: socket.socket(socket.AF_UNIX, socket.SOCK_STREAM))
    with contextlib.closing(factory()) as peer:
        peer.settimeout(deadline)
        peer.connect(settings.socket_path)
        if wire.peer_uid(peer) != settings.owner_uid:
            raise wire.WireError('peer_mismatch')
        remaining = limit_at - clock()
        if remaining <= 0:
            raise wire.WireError('timeout')
        peer.settimeout(remaining)
        peer.sendall(framed)
        peer.shutdown(socket.SHUT_WR)

        def recv(count, timeout):
            peer.settimeout(timeout)
            return peer.recv(count)

        return wire.read_frame(recv, limit=response_limit, deadline=limit_at, clock=clock)


async def socket_transport(settings, payload, *, response_limit, deadline):
    return await asyncio.to_thread(blocking_exchange, settings, payload, response_limit=response_limit, deadline=deadline)


def _transport_reason(reason):
    if reason in _PEER_REASONS:
        return 'owner_peer_unverified'
    if reason == 'timeout':
        return 'owner_unavailable'
    return 'owner_response_invalid'


async def _request(settings, transport, op, **fields):
    """One exchange. Returns the decoded success object; raises wire.RemoteError for a refusal and ActorError otherwise."""
    try:
        payload = wire.encode_request(op, **fields)
    except proto.ProtocolError as exc:
        raise ActorError(exc.reason) from None
    try:
        raw = await (transport or socket_transport)(settings, payload, response_limit=wire.RESPONSE_LIMITS[op],
                                                    deadline=wire.CLIENT_DEADLINES[op])
    except wire.WireError as exc:
        raise ActorError(_transport_reason(exc.reason)) from None
    except (OSError, TimeoutError):
        raise ActorError('owner_unavailable') from None
    try:
        return wire.decode_response(raw, op=op)
    except wire.WireError:
        raise ActorError('owner_response_invalid') from None


async def health(settings, *, transport=None):
    """Availability of the owner. Separate from close: it never confirms a restitution."""
    try:
        value = await _request(settings, transport, 'health')
    except wire.RemoteError as exc:
        raise ActorError(exc.reason) from None
    try:
        return wire.validate_health(value)
    except wire.WireError:
        raise ActorError('owner_response_invalid') from None


def _receipt_unconfirmed(detail):
    """Closed failure of recover_receipt. `owner_reason` names the cause: a refusal or ActorError reason of the owner, or one of
    identity_invalid, installation_mismatch, owner_response_invalid and receipt_unknown."""
    error = ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
    error.owner_reason = detail
    return error


async def recover_receipt(settings, identity, *, transport=None):
    """Durable receipt of an earlier restitution, e.g. after a lost close response or an owner restart.

    `identity` is ActorSession.identity (the five fields of the original open). Returns the validated answer
    (ok, op, the identity, status 'confirmed', cleanup_confirmed True) and only for that. Everything else raises ActorError
    cleanup_unconfirmed with cleanup_confirmed False, so a caller cannot read a missing answer as a restitution. One exchange per
    call, no health call, no retry; the owner's UID is verified before any byte is sent.
    """
    if not isinstance(identity, dict) or set(identity) != set(wire.IDENTITY_FIELDS):
        raise _receipt_unconfirmed('identity_invalid')
    identity = dict(identity)  # one snapshot: the caller cannot change it between the checks and the comparison
    try:
        wire.encode_request('receipt', **identity)  # the owner's own decoder judges every field before anything is sent
    except proto.ProtocolError:
        raise _receipt_unconfirmed('identity_invalid') from None
    if settings.installation_id is not None and settings.installation_id != identity['installation_id']:
        raise _receipt_unconfirmed('installation_mismatch')
    try:
        value = await _request(settings, transport, 'receipt', **identity)
    except wire.RemoteError as exc:
        raise _receipt_unconfirmed(exc.reason) from None
    except ActorError as exc:
        raise _receipt_unconfirmed(exc.reason) from None
    try:
        receipt = wire.validate_receipt(value, identity=identity)
    except wire.WireError:
        raise _receipt_unconfirmed('owner_response_invalid') from None
    if receipt['status'] != 'confirmed' or receipt['cleanup_confirmed'] is not True:
        error = _receipt_unconfirmed('receipt_unknown')
        error.receipt_status = receipt['status']
        raise error
    return receipt


def _snapshot(value):
    """A one-time copy of a caller's dict that cannot be influenced by a subclass overriding its accessors; None for anything else."""
    return dict(dict.items(value)) if isinstance(value, dict) else None


def _pin(predecessor, *, stage, run_id, context_sha256, installation_id=None):
    """Defensive copy of the caller's pin of phase A for a phase B that is about to be opened (ValueError otherwise).

    A fresh phase needs it and an actor phase refuses it. The copy must be a faithful persistence/actor identity of the same run and
    context and, when the settings pin an installation, of that installation; the IDs of B are only known later and are checked
    against every answer. The result is a new dict and never the caller's."""
    if stage != 'fresh':
        if predecessor is not None:
            raise ValueError('an actor level takes no predecessor')
        return None
    snapshot = _snapshot(predecessor)
    if snapshot is None:
        raise ValueError('a fresh level needs the pin of its actor phase')
    checks = {'run_id': run_id, 'context_sha256': context_sha256}
    if installation_id is not None:
        checks['installation_id'] = installation_id
    try:
        return wire.predecessor_identity(snapshot, **checks)
    except wire.WireError:
        raise ValueError('invalid level predecessor pin') from None


async def recover_level_receipt(settings, identity, *, predecessor=None, transport=None):
    """Durable receipt of an earlier level restitution (LevelSession.identity: the seven fields, context included).

    Same contract as recover_receipt: one `level_receipt` exchange, no health call, no retry, and never open, execute, level_probe
    or close; the owner's UID is verified before any byte is sent. Only a `confirmed` answer that echoes exactly that identity
    returns; everything else (another context, another identity, `unknown`, refusal, malformed answer, transport failure, an M1
    identity with `variant`) raises ActorError cleanup_unconfirmed with cleanup_confirmed False and `owner_reason`.

    For a persistence/fresh identity `predecessor` is REQUIRED: the caller's independent pin of the phase A (its seven identity fields).
    It is validated BEFORE the exchange (a faithful persistence/actor identity of the same installation, run and context, sharing no ID
    with the fresh phase; owner_reason `predecessor_invalid`, nothing sent), is never transmitted, and a `confirmed` answer must carry
    exactly that predecessor. For any other identity it must be None. A fresh `unknown` (predecessor null) is receipt_unknown.
    """
    network = isinstance(identity, dict) and set(identity) == set(wire.NETWORK_IDENTITY_FIELDS)  # M5: eight fields, the bundle among them
    if not isinstance(identity, dict) or set(identity) != set(wire.NETWORK_IDENTITY_FIELDS if network else wire.LEVEL_IDENTITY_FIELDS):
        raise _receipt_unconfirmed('identity_invalid')
    identity = dict(identity)  # one snapshot: the caller cannot change it between the checks and the comparison
    if network != (identity.get('level') == proto.NETWORK_LEVEL) or (network and identity['bundle_id'] != identity['intent_id']):
        raise _receipt_unconfirmed('identity_invalid')  # a network identity has eight fields and the bundle is its intent; no other has
    asked = {key: identity[key] for key in wire.LEVEL_IDENTITY_FIELDS}  # the request never carries the bundle: the owner derives it
    try:
        wire.encode_request('level_receipt', **asked)  # the owner's own decoder judges every field before anything is sent
    except proto.ProtocolError:
        raise _receipt_unconfirmed('identity_invalid') from None
    if settings.installation_id is not None and settings.installation_id != identity['installation_id']:
        raise _receipt_unconfirmed('installation_mismatch')
    pin = None
    if identity['stage'] == 'fresh':
        snapshot = _snapshot(predecessor)
        try:
            if snapshot is None:
                raise ValueError('pin required')
            pin = wire.predecessor_identity(snapshot, run_id=identity['run_id'], context_sha256=identity['context_sha256'],
                                            installation_id=identity['installation_id'], successor=identity)
        except (ValueError, wire.WireError):
            raise _receipt_unconfirmed('predecessor_invalid') from None
    elif predecessor is not None:
        raise _receipt_unconfirmed('predecessor_invalid')  # an actor phase has no predecessor to pin
    try:
        value = await _request(settings, transport, 'level_receipt', **asked)
    except wire.RemoteError as exc:
        raise _receipt_unconfirmed(exc.reason) from None
    except ActorError as exc:
        raise _receipt_unconfirmed(exc.reason) from None
    try:
        receipt = wire.validate_level_receipt(value, identity=identity, predecessor=pin)
    except wire.WireError:
        raise _receipt_unconfirmed('owner_response_invalid') from None
    if receipt['status'] != 'confirmed' or receipt['cleanup_confirmed'] is not True:
        error = _receipt_unconfirmed('receipt_unknown')
        error.receipt_status = receipt['status']
        raise error
    return receipt


# --------------------------------------------------------------------------------------------------------------- facade

class ActorSession:
    def __init__(self, settings, *, run_id, variant, transport=None):
        if not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id) or variant not in proto.VARIANTS:
            raise ValueError('invalid actor session binding')
        self._settings, self._transport = settings, transport
        self.run_id, self.variant = run_id, variant
        self.name = None
        self.created = False
        self.oom_killed = None
        self.cleanup_confirmed = False
        self.measurement = runner.unavailable_measurement()
        self.profile = {'available': False, 'reason': 'not captured'}
        self.profile_captured = False
        self.cgroup_absent = None
        self._handle = None
        self._receipt = None

    def __repr__(self):  # the handle never appears in logs
        return 'ActorSession(variant=%s, open=%s)' % (self.variant, self._handle is not None)

    @property
    def obligation(self):
        """True while a granted handle has no confirmed restitution."""
        return self._handle is not None

    @property
    def identity(self):
        return dict(self._receipt) if self._receipt is not None else None

    async def __aenter__(self):
        task = asyncio.ensure_future(self._open())
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as cancelled:
            # Let the exchange finish so a handle already granted can be restored; then the cancellation proceeds.
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await task
            if self._handle is not None:
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await asyncio.shield(self.close())
            cancelled.cleanup_confirmed = self.cleanup_confirmed if self.created or self._receipt is not None else None
            if self.profile_captured:
                cancelled.sandbox_profile = self.profile
            raise
        return self

    async def _open(self):
        info = await health(self._settings, transport=self._transport)  # ActorError: nothing was asked to open
        if info['ready'] is not True:
            raise ActorError('owner_not_ready')
        if info['blocked'] is not False:
            raise ActorError('owner_blocked')
        installation = self._settings.installation_id or info['installation_id']
        image = self._settings.image_id or info['image_id']
        if info['installation_id'] != installation:
            raise ActorError('owner_response_invalid')
        if image is None or info['image_id'] != image:
            raise ActorError('image_mismatch')
        try:
            value = await _request(self._settings, self._transport, 'open', run_id=self.run_id, variant=self.variant)
        except wire.RemoteError as exc:
            raise ActorError(exc.reason, exc.violations or None, cleanup_confirmed=exc.cleanup_confirmed) from None
        except ActorError as exc:
            exc.cleanup_confirmed = None if exc.reason == 'owner_peer_unverified' else False  # state of the owner unknown
            raise
        try:
            value = wire.validate_open(value, run_id=self.run_id, variant=self.variant, installation_id=installation,
                                       image_id=image)
        except wire.WireError:
            raise ActorError('owner_response_invalid', cleanup_confirmed=False) from None
        self._handle = value['handle']
        self._receipt = {key: value[key] for key in wire.IDENTITY_FIELDS}
        self.name, self.created, self.cleanup_confirmed = value['name'], True, False
        profile = value['profile']
        self.profile, self.profile_captured = profile, True
        violations = list(runner.hardened_violations(profile))
        if not violations and runner.profile_digest(profile) != value['profile_sha256']:
            violations = ['profile_digest']
        if violations:
            error = ActorError('profile_rejected', violations, sandbox_profile=profile)
            try:
                await asyncio.shield(self.close())
            except ActorError as cleanup:  # an unconfirmed cleanup outranks the original error
                cleanup.cleanup_confirmed, cleanup.sandbox_profile = False, profile
                raise cleanup from None
            error.cleanup_confirmed = self.cleanup_confirmed
            raise error

    async def _call(self, op, validator, **fields):
        if self._handle is None:
            raise ActorError('unknown_handle')
        try:
            value = await _request(self._settings, self._transport, op, handle=self._handle, **fields)
        except wire.RemoteError as exc:
            raise ActorError(exc.reason) from None
        try:
            return validator(value)
        except wire.WireError:
            raise ActorError('owner_response_invalid') from None

    def _note(self, measurement):
        if measurement['memory_measurement']['available'] is True:
            self.measurement = {key: measurement[key] for key in wire.MEASUREMENT_FIELDS}

    async def execute(self, command, timeout=10):
        # `timeout` is accepted for runner.Session compatibility; the owner enforces its own bound for the call.
        result = await self._call('execute', lambda value: wire.validate_result(value, op='execute'), command=command)
        self._note(result)
        return result

    async def probe(self, name):
        """One of the three fixed probes by name. The text of a probe never travels from here."""
        if name not in proto.PROBE_NAMES:
            raise ActorError('invalid_name')
        result = await self._call('probe', lambda value: wire.validate_result(value, op='probe', name=name), name=name)
        self._note(result)
        return result

    async def measure(self):
        await self.probe('measure')
        return self.measurement

    async def exec_fixed(self, script, timeout=10, *, output_limit=None):
        """Only the registered capture script is accepted; it is translated to the fixed probe `artifact_capture`."""
        if (script != invoice_verification.ARTIFACT_CAPTURE_SCRIPT
                or output_limit not in (None, invoice_verification.CAPTURE_OUTPUT_LIMIT)):
            raise ActorError('script_not_registered')
        return await self.probe('artifact_capture')

    async def close(self):
        """Restitute through the owner. Confirmed only by a receipt with the original identity; otherwise the obligation stays."""
        if self._handle is None:
            return
        try:
            value = await _request(self._settings, self._transport, 'close', handle=self._handle)
            receipt = wire.validate_close(value, receipt=self._receipt)
        except wire.RemoteError as exc:
            self.cleanup_confirmed = False
            error = ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
            error.owner_reason = exc.reason
            raise error from None
        except wire.WireError:
            self.cleanup_confirmed = False
            raise ActorError('cleanup_unconfirmed', cleanup_confirmed=False) from None
        except ActorError as exc:
            self.cleanup_confirmed = False
            error = ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
            error.owner_reason = exc.reason
            raise error from None
        self.oom_killed = receipt['oom_killed']
        self._note(receipt)
        self.cleanup_confirmed, self.created, self._handle = True, False, None

    async def __aexit__(self, exc_type, exc, tb):
        await asyncio.shield(self.close())


class LevelSession:
    """Facade of one level actor (M2.1): execute, measure, cgroup_events and close over a handle bound to its level identity.

    Same lifecycle and failure semantics as ActorSession (see the module docstring); only the identity, the open/close shapes and
    the probes differ. It deliberately has no `probe`, `exec_fixed` or `net_counters`, and `file_state` / `copy_scan` exist only on a
    persistence session (on any other level the attribute is absent, so `getattr(session, 'copy_scan', None)` is None).

    `predecessor` is the defensive pin of phase A that a persistence/fresh session requires and an actor session refuses (ValueError
    either way); see the module docstring. `identity` stays the seven fields of THIS phase; `predecessor` is a separate copy.
    """

    def __init__(self, settings, *, run_id, level, stage, context_sha256, predecessor=None, transport=None):
        if (not isinstance(run_id, str) or not _RUN_ID.fullmatch(run_id)
                or not isinstance(level, str) or level not in proto.LEVELS or level == proto.NETWORK_LEVEL  # M5: NetworkActorSession's
                or not isinstance(stage, str) or stage not in proto.STAGES or not proto.level_stage_valid(level, stage)
                or not isinstance(context_sha256, str) or not _CONTEXT.fullmatch(context_sha256)):
            raise ValueError('invalid level session binding')
        self._settings, self._transport = settings, transport
        self.run_id, self.level, self.stage, self.context_sha256 = run_id, level, stage, context_sha256
        self._predecessor = _pin(predecessor, stage=stage, run_id=run_id, context_sha256=context_sha256,
                                 installation_id=getattr(settings, 'installation_id', None))
        self.name = None
        self.created = False
        self.oom_killed = None
        self.cleanup_confirmed = False
        self.measurement = runner.unavailable_measurement()
        self.profile = {'available': False, 'reason': 'not captured'}
        self.profile_captured = False
        self._handle = None
        self._receipt = None

    def __repr__(self):  # neither the handle nor the context appear in logs
        return 'LevelSession(level=%s, stage=%s, open=%s)' % (self.level, self.stage, self._handle is not None)

    @property
    def obligation(self):
        """True while a granted handle has no confirmed restitution."""
        return self._handle is not None

    @property
    def identity(self):
        """The seven fields of the original open, for recover_level_receipt; None before a handle was granted."""
        return dict(self._receipt) if self._receipt is not None else None

    @property
    def predecessor(self):
        """A copy of the defensive pin of phase A (the seven identity fields) of a persistence/fresh session; None for any actor
        session. It is independent of `identity` (this phase's own), and changing the returned dict changes nothing."""
        return dict(self._predecessor) if self._predecessor is not None else None

    async def __aenter__(self):
        task = asyncio.ensure_future(self._open())
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as cancelled:
            # Let the exchange finish so a handle already granted can be restored; then the cancellation proceeds.
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await task
            if self._handle is not None:
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await asyncio.shield(self.close())
            cancelled.cleanup_confirmed = self.cleanup_confirmed if self.created or self._receipt is not None else None
            if self.profile_captured:
                cancelled.sandbox_profile = self.profile
            raise
        return self

    async def _open(self):
        info = await health(self._settings, transport=self._transport)  # ActorError: nothing was asked to open
        if info['ready'] is not True:
            raise ActorError('owner_not_ready')
        if info['blocked'] is not False:
            raise ActorError('owner_blocked')
        installation = self._settings.installation_id or info['installation_id']
        image = self._settings.image_id or info['image_id']
        if info['installation_id'] != installation:
            raise ActorError('owner_response_invalid')
        if image is None or info['image_id'] != image:
            raise ActorError('image_mismatch')
        if self._predecessor is not None and self._predecessor['installation_id'] != installation:
            raise ActorError('installation_mismatch')  # the pinned phase A belongs to another installation: nothing is asked
        try:
            value = await _request(self._settings, self._transport, 'open_level', run_id=self.run_id, level=self.level,
                                   stage=self.stage, context_sha256=self.context_sha256)
        except wire.RemoteError as exc:
            raise ActorError(exc.reason, exc.violations or None, cleanup_confirmed=exc.cleanup_confirmed) from None
        except ActorError as exc:
            exc.cleanup_confirmed = None if exc.reason == 'owner_peer_unverified' else False  # state of the owner unknown
            raise
        try:
            value = wire.validate_level_open(value, run_id=self.run_id, level=self.level, stage=self.stage,
                                             context_sha256=self.context_sha256, installation_id=installation, image_id=image,
                                             predecessor=self._predecessor)
        except wire.WireError:
            raise ActorError('owner_response_invalid', cleanup_confirmed=False) from None
        self._handle = value['handle']
        self._receipt = {key: value[key] for key in wire.LEVEL_IDENTITY_FIELDS}
        self.name, self.created, self.cleanup_confirmed = value['name'], True, False
        profile = value['profile']
        self.profile, self.profile_captured = profile, True
        violations = list(runner.hardened_violations(profile))
        if not violations and runner.profile_digest(profile) != value['profile_sha256']:
            violations = ['profile_digest']
        if violations:
            error = ActorError('profile_rejected', violations, sandbox_profile=profile)
            try:
                await asyncio.shield(self.close())
            except ActorError as cleanup:  # an unconfirmed cleanup outranks the original error
                cleanup.cleanup_confirmed, cleanup.sandbox_profile = False, profile
                raise cleanup from None
            error.cleanup_confirmed = self.cleanup_confirmed
            raise error

    async def _call(self, op, validator, **fields):
        if self._handle is None:
            raise ActorError('unknown_handle')
        try:
            value = await _request(self._settings, self._transport, op, handle=self._handle, **fields)
        except wire.RemoteError as exc:
            raise ActorError(exc.reason) from None
        try:
            return validator(value)
        except wire.WireError:
            raise ActorError('owner_response_invalid') from None

    def _note(self, measurement):
        if measurement['memory_measurement']['available'] is True:
            self.measurement = {key: measurement[key] for key in wire.MEASUREMENT_FIELDS}

    async def execute(self, command, timeout=10):
        # `timeout` is accepted for runner.Session compatibility; the owner enforces its own bound for the call.
        result = await self._call('execute', lambda value: wire.validate_result(value, op='execute'), command=command)
        self._note(result)
        return result

    async def measure(self):
        result = await self._call('probe', lambda value: wire.validate_result(value, op='probe', name='measure'),
                                  name='measure')
        self._note(result)
        return self.measurement

    async def cgroup_events(self):
        """Counters of memory.events read by the owner's fixed probe: a dict, or None when the owner reports it unavailable.

        Only a Memory session asks (anything else is refused here, nothing sent). The request has no script, path or argument.
        A transport failure or refusal is an ActorError, like execute: it is never turned into None or into zeros."""
        if self.level != 'memory':
            raise ActorError('wrong_domain')
        result = await self._call('level_probe', wire.validate_level_probe, name='cgroup_events')
        return dict(result['counters']) if result['status'] == 'available' else None

    @property
    def file_state(self):
        """The fixed file_state probe, only on a persistence session; on any other level this attribute does not exist."""
        if self.level != 'persistence':
            raise AttributeError('file_state')
        return self._file_state

    @property
    def copy_scan(self):
        """The fixed copy_scan probe, only on a persistence session; on any other level this attribute does not exist."""
        if self.level != 'persistence':
            raise AttributeError('copy_scan')
        return self._copy_scan

    async def _file_state(self, path):
        """(inode, size, mtime, ctime, links, sha256) of the marker file, 'missing' when the owner saw it absent, or None when the
        owner could not observe it (`unavailable`). `path` must be /work/marker- plus 24 lowercase hex: anything else is refused
        locally with the codec's reason and nothing is sent. A transport failure, refusal or malformed answer is an ActorError,
        never 'missing'."""
        result = await self._call('level_probe', lambda value: wire.validate_level_probe(value, name='file_state'),
                                  name='file_state', path=path)
        return runner.file_state_value(result)

    async def _copy_scan(self, sha256, size, exclude=None):
        """The scan dict of the owner's fixed exact-copy probe for (sha256, size): `exclude` is None or the marker path of the original
        (a fresh session refuses a non-null one, since there the original path counts). Digest, size and path are validated by the
        codec before anything is sent. An incomplete scan is a valid answer that establishes no absence; a transport failure,
        refusal or malformed answer is an ActorError, never an empty scan."""
        if self.stage == 'fresh' and exclude is not None:
            raise ActorError('invalid_exclude')
        return await self._call('level_probe', lambda value: wire.validate_level_probe(value, name='copy_scan', size=size),
                                name='copy_scan', sha256=sha256, size=size, exclude=exclude)

    async def close(self):
        """Restitute through the owner. Confirmed only by a level receipt with the original identity; otherwise the obligation stays."""
        if self._handle is None:
            return
        try:
            value = await _request(self._settings, self._transport, 'close', handle=self._handle)
            receipt = wire.validate_level_close(value, receipt=self._receipt, predecessor=self._predecessor)
        except wire.RemoteError as exc:
            self.cleanup_confirmed = False
            error = ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
            error.owner_reason = exc.reason
            raise error from None
        except wire.WireError:
            self.cleanup_confirmed = False
            raise ActorError('cleanup_unconfirmed', cleanup_confirmed=False) from None
        except ActorError as exc:
            self.cleanup_confirmed = False
            error = ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
            error.owner_reason = exc.reason
            raise error from None
        self.oom_killed = receipt['oom_killed']
        self._note(receipt)
        self.cleanup_confirmed, self.created, self._handle = True, False, None

    async def __aexit__(self, exc_type, exc, tb):
        await asyncio.shield(self.close())


# ----------------------------------------------------------------------------------------------------- M3.1 · catalog

class RoomActorSession:
    """Facade of one room actor (M4): `room_action`, `measure` and `close` over a handle bound to its seven-field level identity.

    Same lifecycle and failure semantics as the other facades (see the module docstring). It deliberately has no execute, exec_fixed,
    probe by name, cgroup_events, file_state, copy_scan or net_counters: a room has no shell and no free probe, and the caller never
    names a script, an argument or an action. The binding is a private pin (exact types: a str subclass or a bool is a ValueError before
    anything is sent); `run_id`, `level`, `stage` and `context_sha256` are read-only views of it."""

    def __init__(self, settings, *, run_id, level, context_sha256, transport=None, allow_shell=False):
        if type(allow_shell) is not bool: raise ValueError('invalid shell mode')
        self._allow_shell = allow_shell
        if (type(run_id) is not str or not _RUN_ID.fullmatch(run_id) or type(level) is not str or level not in proto.ROOM_LEVELS
                or type(context_sha256) is not str or not _CONTEXT.fullmatch(context_sha256)):
            raise ValueError('invalid room session binding')
        self._settings, self._transport = settings, transport
        self._pin = (run_id, level, context_sha256)
        self._installation_pin = getattr(settings, 'installation_id', None)
        self._image_pin = getattr(settings, 'image_id', None)
        self.name = None
        self.created = False
        self.oom_killed = None
        self.cleanup_confirmed = False
        self.measurement = runner.unavailable_measurement()
        self.profile = {'available': False, 'reason': 'not captured'}
        self.profile_captured = False
        self.cgroup_absent = None  # True only after a confirmed Processes close; None for Privileges and before any close
        self._handle = None
        self._receipt = None
        self._pids_limit = None
        self._action_requested = False  # set BEFORE the request leaves: a lost answer never allows a second one
        self._owner_cleaned = False     # the owner itself said it restituted a failed open

    def __repr__(self):  # neither the handle nor the context appear in logs
        return 'RoomActorSession(level=%s, open=%s)' % (self._pin[1], self._handle is not None)

    run_id = property(lambda self: self._pin[0])
    level = property(lambda self: self._pin[1])
    stage = property(lambda self: 'actor')
    context_sha256 = property(lambda self: self._pin[2])

    @property
    def obligation(self):
        """True while a granted handle has no confirmed restitution."""
        return self._handle is not None

    @property
    def identity(self):
        """Seven fields for recover_level_receipt: from a valid open ACK or an exact restored-open rejection, otherwise None.
        A rejection conveys no handle. The copy stays available after close or when the context body never started."""
        return dict(self._receipt) if self._receipt is not None else None

    async def __aenter__(self):
        task = asyncio.ensure_future(self._open())
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as cancelled:
            # Let the exchange finish so a handle already granted can be restored; then the cancellation proceeds. Whether the open
            # succeeded, failed or never answered, an absence is not established here: the debt is False unless the owner (or the
            # close just below) confirmed the restitution. Never None.
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await task
            if self._handle is not None:
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await asyncio.shield(self.close())
            cancelled.cleanup_confirmed = bool(self.cleanup_confirmed or self._owner_cleaned)
            if self.profile_captured:
                cancelled.sandbox_profile = self.profile
            raise
        return self

    async def _open(self):
        run_id, level, context = self._pin
        info = await health(self._settings, transport=self._transport)  # ActorError: nothing was asked to open
        if info['ready'] is not True:
            raise ActorError('owner_not_ready')
        if info['blocked'] is not False:
            raise ActorError('owner_blocked')
        installation = self._installation_pin or info['installation_id']
        image = self._image_pin or info['image_id']
        if info['installation_id'] != installation:
            raise ActorError('owner_response_invalid')
        if image is None or info['image_id'] != image:
            raise ActorError('image_mismatch')
        try:
            value = await _request(self._settings, self._transport, 'open_level', run_id=run_id, level=level, stage='actor',
                                   context_sha256=context)
        except wire.RemoteError as exc:
            self._owner_cleaned = exc.cleanup_confirmed is True
            if exc.restored is not None:
                restored = exc.restored  # codec accepted the complete closed room receipt
                pins = {'installation_id': installation, 'run_id': run_id, 'level': level,
                        'stage': 'actor', 'context_sha256': context}
                if any(restored[key] != value for key, value in pins.items()):
                    self._owner_cleaned = False
                    raise ActorError('owner_response_invalid', cleanup_confirmed=False) from None
                self._receipt = {key: restored[key] for key in wire.LEVEL_IDENTITY_FIELDS}
                # No handle and no admission release. levels records identity on failure; the
                # controller's existing reconciliation must obtain the exact durable FINISH.
            raise ActorError(exc.reason, exc.violations or None, cleanup_confirmed=exc.cleanup_confirmed) from None
        except ActorError as exc:
            exc.cleanup_confirmed = None if exc.reason == 'owner_peer_unverified' else False  # state of the owner unknown
            raise
        try:
            value = wire.validate_level_open(value, run_id=run_id, level=level, stage='actor', context_sha256=context,
                                             installation_id=installation, image_id=image)
        except wire.WireError:
            raise ActorError('owner_response_invalid', cleanup_confirmed=False) from None
        self._handle = value['handle']
        self._receipt = {key: value[key] for key in wire.LEVEL_IDENTITY_FIELDS}
        self.name, self.created, self.cleanup_confirmed = value['name'], True, False
        profile = value['profile']
        self.profile, self.profile_captured = profile, True
        violations = list(runner.hardened_violations(profile))
        if not violations and runner.profile_digest(profile) != value['profile_sha256']:
            violations = ['profile_digest']
        if violations:
            error = ActorError('profile_rejected', violations, sandbox_profile=profile)
            try:
                await asyncio.shield(self.close())
            except ActorError as cleanup:  # an unconfirmed cleanup outranks the original error
                cleanup.cleanup_confirmed, cleanup.sandbox_profile = False, profile
                raise cleanup from None
            error.cleanup_confirmed = self.cleanup_confirmed
            raise error
        limit = profile.get('pids_limit')
        self._pids_limit = limit if type(limit) is int else None

    async def _call(self, op, validator, **fields):
        if self._handle is None:
            raise ActorError('unknown_handle')
        try:
            value = await _request(self._settings, self._transport, op, handle=self._handle, **fields)
        except wire.RemoteError as exc:
            raise ActorError(exc.reason) from None
        try:
            return validator(value)
        except wire.WireError:
            raise ActorError('owner_response_invalid') from None

    def _note(self, measurement):
        if measurement['memory_measurement']['available'] is True:
            self.measurement = {key: measurement[key] for key in wire.MEASUREMENT_FIELDS}

    async def execute(self, command, timeout=10):
        if not self._allow_shell: raise ActorError('wrong_domain')
        result = await self._call('execute', lambda value: wire.validate_result(value, op='execute'), command=command)
        self._note(result)
        return result

    async def room_action(self):
        """The owner's ONE fixed action of this room. No argument: the script, limits and sampling belong to the owner.

        Returns {result, container, cgroup_identity, pre, during, post, recheck, tool, verification}: `result` is the execute-shaped dict
        (stdout, stderr, exit_code and the three measurement fields) or None (a Processes room that dispatched nothing, with an unknown
        identity and no sample); `pre`/`during`/`post` are the historical sample dicts ({ok, pids_max, pids_current, events_max, peak, at}
        with `at` relative seconds, or {ok: False, reason}); times are seconds or None. A transport failure, refusal, oversized,
        incomplete or self-contradictory answer is an ActorError, never a result, and the request is never repeated: the permit is spent
        locally before sending, so a second call raises action_consumed without a byte leaving."""
        if self._handle is None:
            raise ActorError('unknown_handle')
        if self._action_requested:
            raise ActorError('action_consumed')
        self._action_requested = True
        identity, limit = dict(self._receipt), self._pids_limit
        view = await self._call('room_action', lambda value: wire.validate_room_action(value, identity=identity, pids_limit=limit))
        if view['result'] is not None:
            self._note(view['result'])
        return {'result': view['result'], 'container': view['container'], 'cgroup_identity': view['cgroup_identity'],
                'pre': wire.expand_sample(view['pre']), 'during': [wire.expand_sample(item) for item in view['during']],
                'post': wire.expand_sample(view['post']), 'recheck': view['recheck'], 'tool': view['tool'],
                'verification': view['verification']}

    async def measure(self):
        result = await self._call('probe', lambda value: wire.validate_result(value, op='probe', name='measure'), name='measure')
        self._note(result)
        return self.measurement

    async def close(self):
        """Restitute through the owner. Confirmed only by a room receipt with the original identity (and, for Processes, cgroup_absent
        true); otherwise the obligation and the binding stay, and nothing is confirmed."""
        if self._handle is None:
            return
        try:
            value = await _request(self._settings, self._transport, 'close', handle=self._handle)
            receipt = wire.validate_level_close(value, receipt=self._receipt)
        except wire.RemoteError as exc:
            self.cleanup_confirmed = False
            error = ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
            error.owner_reason = exc.reason
            raise error from None
        except wire.WireError:
            self.cleanup_confirmed = False
            raise ActorError('cleanup_unconfirmed', cleanup_confirmed=False) from None
        except ActorError as exc:
            self.cleanup_confirmed = False
            error = ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
            error.owner_reason = exc.reason
            raise error from None
        self.oom_killed = receipt['oom_killed']
        self.cgroup_absent = receipt['cgroup_absent']
        self._note(receipt)
        self.cleanup_confirmed, self.created, self._handle = True, False, None

    async def __aexit__(self, exc_type, exc, tb):
        await asyncio.shield(self.close())


class NetworkActorSession:
    """Facade of one network actor (M5): `network_action`, `measure` and `close` over a handle bound to its eight-field identity.

    Same lifecycle and failure semantics as the other facades (see the module docstring). It deliberately has no execute, exec_fixed,
    probe by name, room_action, cgroup_events, file_state, copy_scan or net_counters: the command of the model travels only in
    network_action, and the caller never names a destination, a probe, a resource or an option. The binding is a private pin (exact types:
    a str subclass or a bool is a ValueError before anything is sent); `run_id`, `level`, `stage` and `context_sha256` are read-only
    views of it."""

    # Refusals that PROVE the owner dispatched nothing (it decides them before spending the permit, or before reading the request): the
    # local step is given back. Any other failure of an action leaves it spent and every later action refused locally.
    _NOT_DISPATCHED = proto.DECODE_REASONS | frozenset({'busy', 'closing', 'expired', 'unknown_handle', 'foreign_owner', 'wrong_domain',
                                                        'action_unavailable', 'framing', 'owner_peer_unverified'})

    def __init__(self, settings, *, run_id, context_sha256, transport=None):
        if (type(run_id) is not str or not _RUN_ID.fullmatch(run_id) or type(context_sha256) is not str
                or not _CONTEXT.fullmatch(context_sha256)):
            raise ValueError('invalid network session binding')
        self._settings, self._transport = settings, transport
        self._pin = (run_id, context_sha256)
        self._installation_pin = getattr(settings, 'installation_id', None)
        self._image_pin = getattr(settings, 'image_id', None)
        self.name = None
        self.created = False
        self.oom_killed = None
        self.cleanup_confirmed = False
        self.measurement = runner.unavailable_measurement()
        self.profile = {'available': False, 'reason': 'not captured'}
        self.profile_captured = False
        self.cleanup_roles = None   # None until a close confirms the four roles absent; then a copy of the four
        self._handle = None
        self._receipt = None
        self._endpoint = None
        self._steps = 0             # the local permit count: spent BEFORE the exchange
        self._uncertain = False     # an action whose outcome we cannot know: no later action is ever sent
        self._acting = False        # one action at a time, as the owner does
        self._owner_cleaned = False  # the owner itself said it restituted a failed open

    def __repr__(self):  # neither the handle nor the context appear in logs
        return 'NetworkActorSession(open=%s)' % (self._handle is not None,)

    run_id = property(lambda self: self._pin[0])
    level = property(lambda self: proto.NETWORK_LEVEL)
    stage = property(lambda self: 'actor')
    context_sha256 = property(lambda self: self._pin[1])

    @property
    def obligation(self):
        """True while a granted handle has no confirmed restitution."""
        return self._handle is not None

    @property
    def identity(self):
        """The eight fields of the original open (a new copy each time), for recover_level_receipt; None before a handle was granted.
        It stays available after a close, and when the context body never started."""
        return dict(self._receipt) if self._receipt is not None else None

    @property
    def bundle_id(self):
        return self._receipt['bundle_id'] if self._receipt is not None else None

    @property
    def endpoint(self):
        """The owner's published http://<private IPv4>:8080/ (validated), or None before a handle was granted."""
        return self._endpoint

    async def __aenter__(self):
        task = asyncio.ensure_future(self._open())
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as cancelled:
            # Let the exchange finish so a handle already granted can be restored; then the cancellation proceeds. Whether the open
            # succeeded, failed or never answered, an absence is not established here: the debt is False unless the owner (or the
            # close just below) confirmed the restitution. Never None.
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await task
            if self._handle is not None:
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await asyncio.shield(self.close())
            cancelled.cleanup_confirmed = bool(self.cleanup_confirmed or self._owner_cleaned)
            if self.profile_captured:
                cancelled.sandbox_profile = self.profile
            raise
        return self

    async def _open(self):
        run_id, context = self._pin
        info = await health(self._settings, transport=self._transport)  # ActorError: nothing was asked to open
        if info['ready'] is not True:
            raise ActorError('owner_not_ready')
        if info['blocked'] is not False:
            raise ActorError('owner_blocked')
        installation = self._installation_pin or info['installation_id']
        image = self._image_pin or info['image_id']
        if info['installation_id'] != installation:
            raise ActorError('owner_response_invalid')
        if image is None or info['image_id'] != image:
            raise ActorError('image_mismatch')
        try:
            value = await _request(self._settings, self._transport, 'open_level', run_id=run_id, level=proto.NETWORK_LEVEL,
                                   stage='actor', context_sha256=context)
        except wire.RemoteError as exc:
            if exc.cleanup_confirmed is True:  # a proven pre-actor abort: no handle, no identity and no debt exist
                self._owner_cleaned = True
                self.cleanup_confirmed = True
            raise ActorError(exc.reason, exc.violations or None, cleanup_confirmed=exc.cleanup_confirmed) from None
        except ActorError as exc:
            exc.cleanup_confirmed = None if exc.reason == 'owner_peer_unverified' else False  # state of the owner unknown
            raise
        try:
            value = wire.validate_level_open(value, run_id=run_id, level=proto.NETWORK_LEVEL, stage='actor', context_sha256=context,
                                             installation_id=installation, image_id=image)
        except wire.WireError:
            raise ActorError('owner_response_invalid', cleanup_confirmed=False) from None
        self._handle = value['handle']
        self._receipt = {key: value[key] for key in wire.NETWORK_IDENTITY_FIELDS}
        self._endpoint = value['endpoint']
        self.name, self.created, self.cleanup_confirmed = value['name'], True, False
        profile = value['profile']
        self.profile, self.profile_captured = profile, True
        violations = list(runner.hardened_violations(profile))  # the actor keeps the ordinary profile, network_mode none included
        if not violations and runner.profile_digest(profile) != value['profile_sha256']:
            violations = ['profile_digest']
        if violations:
            error = ActorError('profile_rejected', violations, sandbox_profile=profile)
            try:
                await asyncio.shield(self.close())
            except ActorError as cleanup:  # an unconfirmed cleanup outranks the original error
                cleanup.cleanup_confirmed, cleanup.sandbox_profile = False, profile
                raise cleanup from None
            error.cleanup_confirmed = self.cleanup_confirmed
            raise error

    async def _call(self, op, validator, **fields):
        if self._handle is None:
            raise ActorError('unknown_handle')
        try:
            value = await _request(self._settings, self._transport, op, handle=self._handle, **fields)
        except wire.RemoteError as exc:
            raise ActorError(exc.reason) from None
        try:
            return validator(value)
        except wire.WireError:
            raise ActorError('owner_response_invalid') from None

    def _note(self, measurement):
        if measurement['memory_measurement']['available'] is True:
            self.measurement = {key: measurement[key] for key in wire.MEASUREMENT_FIELDS}

    async def network_action(self, command):
        """One command of the model inside the network actor, and the owner's typed observation of it.

        Returns the twelve keys of runtime.network_action (bundle_id, step_index, result, before, after, model_nonce_seen, actor_probe,
        positive_before, positive_after, identity_rechecked, tool, verification) as new objects, after the WHOLE answer was validated
        against this open's identity and the step this client expects. The command is judged locally by the owner's own decoder before
        a permit is spent. The permit is spent before the exchange; a transport failure, malformed answer or a refusal that may have run
        the command is ONE failure: it is never repeated and every later call raises action_consumed without sending a byte (close()
        still restitutes). Nothing is decided here: no outcome, attribution or verdict, and a positive fact stays in the view."""
        if self._handle is None:
            raise ActorError('unknown_handle')
        if self._acting:
            raise ActorError('busy')  # one action at a time, as the owner: nothing is sent and no permit is spent
        if self._uncertain or self._steps >= wire.NETWORK_MAX_STEPS:
            raise ActorError('action_consumed')
        try:
            wire.encode_request('network_action', handle=self._handle, command=command)
        except proto.ProtocolError as exc:
            raise ActorError(exc.reason) from None  # refused before any permit: it never left this process
        self._acting = True
        self._steps += 1
        expected, identity = self._steps, dict(self._receipt)
        try:
            view = await self._call('network_action',
                                    lambda value: wire.validate_network_action(value, identity=identity, step_index=expected),
                                    command=command)
        except ActorError as exc:
            if exc.reason == 'action_consumed':
                self._steps = wire.NETWORK_MAX_STEPS  # the owner says every permit is spent: so is ours
            elif exc.reason in self._NOT_DISPATCHED:
                self._steps -= 1
            else:
                self._uncertain = True
            raise
        except asyncio.CancelledError:
            self._uncertain = True
            raise
        finally:
            self._acting = False
        self._note(view['result'])
        return view

    async def measure(self):
        result = await self._call('probe', lambda value: wire.validate_result(value, op='probe', name='measure'), name='measure')
        self._note(result)
        return self.measurement

    async def close(self):
        """Restitute through the owner. Confirmed only by a network receipt with the original eight fields and the four roles absent;
        otherwise the obligation and the binding stay, and nothing is confirmed."""
        if self._handle is None:
            return
        try:
            value = await _request(self._settings, self._transport, 'close', handle=self._handle)
            receipt = wire.validate_level_close(value, receipt=self._receipt)
        except wire.RemoteError as exc:
            self.cleanup_confirmed = False
            error = ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
            error.owner_reason = exc.reason
            raise error from None
        except wire.WireError:
            self.cleanup_confirmed = False
            raise ActorError('cleanup_unconfirmed', cleanup_confirmed=False) from None
        except ActorError as exc:
            self.cleanup_confirmed = False
            error = ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
            error.owner_reason = exc.reason
            raise error from None
        self.oom_killed = receipt['oom_killed']
        self.cleanup_roles = dict(receipt['cleanup_roles'])
        self._note(receipt)
        self.cleanup_confirmed, self.created, self._handle = True, False, None

    async def __aexit__(self, exc_type, exc, tb):
        await asyncio.shield(self.close())


async def catalog_info(settings, *, transport=None):
    """The owner's public view of its catalog resource: {installation_id, ready, identity | None}, validated; a copy.

    One exchange, no retry, no health call. It prepares, repairs, mounts and retires nothing (the owner's service owns the resource) and
    `ready` is neither an open nor a cleanup. A refusal (catalog_not_allowed among them), a transport failure, a malformed or
    contradictory answer (ready without identity, another catalog, another installation than the pinned one) is an ActorError: it never
    activates the domain. The pin of Settings.installation_id, when set, must equal the answered installation."""
    try:
        value = await _request(settings, transport, 'catalog_info')
    except wire.RemoteError as exc:
        raise ActorError(exc.reason) from None
    try:
        return wire.validate_catalog_info(value, installation_id=getattr(settings, 'installation_id', None))
    except wire.WireError:
        raise ActorError('owner_response_invalid') from None


async def recover_catalog_receipt(settings, identity, *, transport=None):
    """Durable receipt of an earlier catalog restitution (CatalogActorSession.identity: the nine fields).

    Same contract as recover_receipt: one `catalog_receipt` exchange, no health call, no retry, and never open, execute, check or
    close; the owner's UID is verified before any byte is sent. Only a `confirmed` answer that echoes exactly that identity returns;
    everything else (another profile, context, catalog pin, instance or container; `unknown`; refusal; malformed answer; transport
    failure; a workflow or level identity) raises ActorError cleanup_unconfirmed with cleanup_confirmed False and `owner_reason`. The
    identity is snapshotted once and judged by the owner's own decoder before anything is sent."""
    snapshot = _snapshot(identity)
    if snapshot is None or set(snapshot) != set(wire.CATALOG_IDENTITY_FIELDS):
        raise _receipt_unconfirmed('identity_invalid')
    identity = snapshot  # one snapshot: the caller cannot change it between the checks and the comparison
    try:
        wire.encode_request('catalog_receipt', **identity)
    except proto.ProtocolError:
        raise _receipt_unconfirmed('identity_invalid') from None
    pinned = getattr(settings, 'installation_id', None)
    if pinned is not None and pinned != identity['installation_id']:
        raise _receipt_unconfirmed('installation_mismatch')
    try:
        value = await _request(settings, transport, 'catalog_receipt', **identity)
    except wire.RemoteError as exc:
        raise _receipt_unconfirmed(exc.reason) from None
    except ActorError as exc:
        raise _receipt_unconfirmed(exc.reason) from None
    try:
        receipt = wire.validate_catalog_receipt(value, identity=identity)
    except wire.WireError:
        raise _receipt_unconfirmed('owner_response_invalid') from None
    if receipt['status'] != 'confirmed' or receipt['cleanup_confirmed'] is not True:
        error = _receipt_unconfirmed('receipt_unknown')
        error.receipt_status = receipt['status']
        raise error
    return receipt


class CatalogActorSession:
    """Facade of one catalog cell (M3.1): execute, probe(task_result|measure), measure, catalog_check and close over a handle bound to
    its nine-field identity. Same lifecycle and failure semantics as ActorSession (see the module docstring); only the binding, the
    open/close shapes, the profile rule and the probes differ. It deliberately has no file_state, copy_scan, cgroup_events or
    net_counters, and it refuses the capture probe locally.

    The binding is a private pin (exact types: a str subclass or a bool is a ValueError before anything is sent). `run_id`, `variant`,
    `catalog_profile` and `context_sha256` are read-only views of it."""

    def __init__(self, settings, *, run_id, variant, catalog_profile, context_sha256, transport=None):
        if (type(run_id) is not str or not _RUN_ID.fullmatch(run_id) or type(variant) is not str or variant not in proto.VARIANTS
                or type(catalog_profile) is not str or catalog_profile not in proto.CATALOG_PROFILES
                or type(context_sha256) is not str or not _CONTEXT.fullmatch(context_sha256)):
            raise ValueError('invalid catalog session binding')
        self._settings, self._transport = settings, transport
        self._pin = (run_id, variant, catalog_profile, context_sha256)
        self._installation_pin = getattr(settings, 'installation_id', None)
        self._image_pin = getattr(settings, 'image_id', None)
        self.name = None
        self.created = False
        self.oom_killed = None
        self.cleanup_confirmed = False
        self.measurement = runner.unavailable_measurement()
        self.profile = {'available': False, 'reason': 'not captured'}
        self.profile_captured = False
        self._handle = None
        self._receipt = None
        self._check_index = 0

    def __repr__(self):  # neither the handle nor the context appear in logs
        return 'CatalogActorSession(profile=%s, variant=%s, open=%s)' % (self._pin[2], self._pin[1], self._handle is not None)

    run_id = property(lambda self: self._pin[0])
    variant = property(lambda self: self._pin[1])
    catalog_profile = property(lambda self: self._pin[2])
    context_sha256 = property(lambda self: self._pin[3])

    @property
    def obligation(self):
        """True while a granted handle has no confirmed restitution."""
        return self._handle is not None

    @property
    def identity(self):
        """The nine fields of the original open, for recover_catalog_receipt; a new copy each time; None before a handle was granted."""
        return dict(self._receipt) if self._receipt is not None else None

    async def __aenter__(self):
        task = asyncio.ensure_future(self._open())
        try:
            await asyncio.shield(task)
        except asyncio.CancelledError as cancelled:
            # Let the exchange finish so a handle already granted can be restored; then the cancellation proceeds.
            with contextlib.suppress(Exception, asyncio.CancelledError):
                await task
            if self._handle is not None:
                with contextlib.suppress(Exception, asyncio.CancelledError):
                    await asyncio.shield(self.close())
            # No ACK does not establish that the owner created nothing.
            cancelled.cleanup_confirmed = self.cleanup_confirmed
            if self.profile_captured:
                cancelled.sandbox_profile = self.profile
            raise
        return self

    @staticmethod
    def _violations(profile, selected):
        """B must meet the catalog profile (the ordinary one with exactly the one fixed bind and its receipt); A the ordinary hardened
        profile and no catalog receipt at all. Names only, never values."""
        if selected == 'B':
            return list(runner.catalog_violations(profile))
        bad = list(runner.hardened_violations(profile))
        if isinstance(profile, dict) and 'catalog' in profile and 'catalog' not in bad:
            bad.append('catalog')
        return bad

    async def _open(self):
        run_id, variant, selected, context = self._pin
        info = await health(self._settings, transport=self._transport)  # ActorError: nothing was asked to open
        if info['ready'] is not True:
            raise ActorError('owner_not_ready')
        if info['blocked'] is not False:
            raise ActorError('owner_blocked')
        installation = self._installation_pin or info['installation_id']
        image = self._image_pin or info['image_id']
        if info['installation_id'] != installation:
            raise ActorError('owner_response_invalid')
        if image is None or info['image_id'] != image:
            raise ActorError('image_mismatch')
        try:
            value = await _request(self._settings, self._transport, 'open_catalog', run_id=run_id, variant=variant,
                                   catalog_profile=selected, context_sha256=context, catalog_id=proto.CATALOG_ID,
                                   catalog_sha256=proto.CATALOG_SHA256)
        except wire.RemoteError as exc:
            raise ActorError(exc.reason, exc.violations or None, cleanup_confirmed=exc.cleanup_confirmed) from None
        except ActorError as exc:
            exc.cleanup_confirmed = None if exc.reason == 'owner_peer_unverified' else False  # state of the owner unknown
            raise
        try:
            value = wire.validate_catalog_open(value, run_id=run_id, variant=variant, catalog_profile=selected,
                                               context_sha256=context, installation_id=installation, image_id=image)
        except wire.WireError:
            raise ActorError('owner_response_invalid', cleanup_confirmed=False) from None
        self._handle = value['handle']
        self._receipt = {key: value[key] for key in wire.CATALOG_IDENTITY_FIELDS}
        self.name, self.created, self.cleanup_confirmed = value['name'], True, False
        profile = value['profile']
        self.profile, self.profile_captured = profile, True
        violations = self._violations(profile, selected)
        if not violations and runner.profile_digest(profile) != value['profile_sha256']:
            violations = ['profile_digest']
        if violations:
            error = ActorError('profile_rejected', violations, sandbox_profile=profile)
            try:
                await asyncio.shield(self.close())
            except ActorError as cleanup:  # an unconfirmed cleanup outranks the original error
                cleanup.cleanup_confirmed, cleanup.sandbox_profile = False, profile
                raise cleanup from None
            error.cleanup_confirmed = self.cleanup_confirmed
            raise error

    async def _call(self, op, validator, **fields):
        if self._handle is None:
            raise ActorError('unknown_handle')
        try:
            value = await _request(self._settings, self._transport, op, handle=self._handle, **fields)
        except wire.RemoteError as exc:
            raise ActorError(exc.reason) from None
        try:
            return validator(value)
        except wire.WireError:
            raise ActorError('owner_response_invalid') from None

    def _note(self, measurement):
        if measurement['memory_measurement']['available'] is True:
            self.measurement = {key: measurement[key] for key in wire.MEASUREMENT_FIELDS}

    async def execute(self, command, timeout=10):
        # `timeout` is accepted for runner.Session compatibility; the owner enforces its own bound for the call.
        result = await self._call('execute', lambda value: wire.validate_result(value, op='execute'), command=command)
        self._note(result)
        return result

    async def probe(self, name):
        """The fixed probe task_result or measure by name. The capture probe belongs to another domain: refused here, nothing sent."""
        if not isinstance(name, str) or name not in proto.PROBE_NAMES:
            raise ActorError('invalid_name')
        if name not in ('task_result', 'measure'):
            raise ActorError('wrong_domain')
        result = await self._call('probe', lambda value: wire.validate_result(value, op='probe', name=name), name=name)
        self._note(result)
        return result

    async def measure(self):
        await self.probe('measure')
        return self.measurement

    async def exec_fixed(self, script, timeout=10, *, output_limit=None):
        """Only the registered task-result read is recognized (TASK_RESULT_COMMAND); it is translated to the fixed probe `task_result`.
        Any other script, the capture script and the catalog probe script included, is refused and nothing is sent."""
        if type(script) is not str or script != TASK_RESULT_COMMAND or output_limit is not None:
            raise ActorError('script_not_registered')
        return await self.probe('task_result')

    async def catalog_check(self):
        """The owner's fixed check of the catalog on this cell: a typed view {probe, host_check, check_index}, as copies.

        The request carries only the handle (no path, script or index). The answer must carry the nine fields of this cell and a
        check_index strictly above the last one accepted; a transport failure, refusal or malformed answer is an ActorError and never an
        observation (and is not repeated). `probe.state` unavailable is neither absent nor a denial: the caller decides what it means."""
        if self._handle is None:
            raise ActorError('unknown_handle')
        if self._check_index >= wire.CATALOG_CHECK_MAX_INDEX:
            raise ActorError('catalog_check_exhausted')  # refused here: the owner would end the lease on a check beyond its bound
        identity, after = dict(self._receipt), self._check_index
        view = await self._call('catalog_check', lambda value: wire.validate_catalog_check(value, identity=identity, after=after))
        self._check_index = view['check_index']
        return {'probe': dict(view['probe']), 'host_check': dict(view['host_check']), 'check_index': view['check_index']}

    async def close(self):
        """Restitute through the owner. Confirmed only by a receipt with the original nine fields; otherwise the obligation stays."""
        if self._handle is None:
            return
        try:
            value = await _request(self._settings, self._transport, 'close', handle=self._handle)
            receipt = wire.validate_catalog_close(value, receipt=self._receipt)
        except wire.RemoteError as exc:
            self.cleanup_confirmed = False
            error = ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
            error.owner_reason = exc.reason
            raise error from None
        except wire.WireError:
            self.cleanup_confirmed = False
            raise ActorError('cleanup_unconfirmed', cleanup_confirmed=False) from None
        except ActorError as exc:
            self.cleanup_confirmed = False
            error = ActorError('cleanup_unconfirmed', cleanup_confirmed=False)
            error.owner_reason = exc.reason
            raise error from None
        self.oom_killed = receipt['oom_killed']
        self._note(receipt)
        self.cleanup_confirmed, self.created, self._handle = True, False, None

    async def __aexit__(self, exc_type, exc, tb):
        await asyncio.shield(self.close())
