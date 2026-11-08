"""Wire layer of the invoice actor boundary, milestone M1 (SC2-CONTROLADOR-CONTRATO section 14).

Scope and limits (read before wiring a transport):
- Pure: standard library plus invoice_actor_protocol (round21; its five original operations are unchanged). No Docker,
  subprocess, host path or secret is touched. The only socket-shaped code is peer_uid(), which reads SO_PEERCRED from an object
  the caller owns.
- Requests are the five original round21 operations plus `receipt` (durable restitution query), all decoded by
  proto.decode_request without reinterpretation. E1, extra profiles and extra slots are NOT part of M1: any other operation is
  rejected as unknown_op.
- Frame: 4-byte big-endian length, then that many bytes of JSON. One request and one response per connection. The sender shuts
  down its write side after the frame and the reader requires EOF right after it: bytes after the frame are rejected before any
  dispatch. A zero or oversized length is rejected before the body is read. The reader applies one total deadline.
- M2.1 (levels): the three level operations of the protocol (open_level, level_receipt, level_probe) travel in the same frames and
  have their own closed response shapes. A level handle answers `close` with the level identity (LEVEL_IDENTITY_FIELDS, no
  variant) and an M1 handle with the M1 identity; each validator accepts only its own shape, so a mixture, a missing field or an
  extra one is owner_response_invalid. level_probe answers only a status and its counters (never a path, a script or an identity
  to reinterpret); `unavailable` carries no counters and is never a zero.
- M2.3 (persistence): `persistence` and `fresh` extend the closed level vocabulary (the pair rule lives in proto.level_stage_valid:
  memory/fresh is invalid everywhere). The open, close and level_receipt answers of a persistence/fresh phase carry one more key,
  `predecessor`: the seven identity fields of the persistence/actor phase, in a nested object, derived by the OWNER from its diary and
  never sent in a request. predecessor_identity() validates that object; the three validators take the caller's independent pin of the
  phase A (`predecessor=`) and accept a fresh answer only when the answered predecessor equals the pin field by field and shares run,
  context and installation with the phase B (and neither of its IDs). Actor answers carry no such key and take no pin. A fresh
  level_receipt that is `unknown` carries predecessor null and confirms nothing; `confirmed` with a null or different predecessor is
  owner_response_invalid.
  validate_level_probe is name-aware (`name=`, plus the expected `size` for copy_scan). cgroup_events keeps its shape; file_state answers
  the labelled status of runner.parse_file_state (present with exactly inode/size/mtime/ctime/links/sha256, missing, unavailable); copy_scan
  answers the dict of runner.parse_copy_scan, or an incomplete scan of the controller's closed reasons. The answers carry no name, so the
  exact key set is what tells them apart: one name's shape is never accepted for another. Unavailable or malformed is never a zero and
  never an absence.
- M3.1 (catalog): `catalog_info`, `open_catalog`, `catalog_check` and `catalog_receipt` travel in the same frames with their own closed
  response shapes and the explicit limits 2048/8192/4096/2048 (RESPONSE_LIMITS; MAX_RESPONSE_BYTES, the request limit, the command limit and
  the TTL are untouched; nothing is truncated to fit). The identity of a catalog cell is the nine fields CATALOG_IDENTITY_FIELDS
  (installation, run, variant, A|B, context, the fixed catalog id and digest, intent, container); a catalog handle answers `close` with
  that identity and each validator accepts only its own shape, so a workflow, level or catalog answer is never taken for another. The
  owner's private resource reference never has a wire name. catalog_check answers the already-normalized probe of the runtime (never
  stdout to parse again), the host check and a check_index that must grow strictly (gaps are allowed after a failed attempt, repetition
  and inversion are not). `unavailable` is a state of its own: it is never `absent` and never a denial.
- M4 rooms (SC2-M4-rooms-v1): `processes` and `privileges` are level names (stage `actor` only; the identity is the seven level fields).
  `room_action {op, handle}` answers the seven identity fields plus the nine keys of the owner's runtime.room_action (RESPONSE_LIMITS
  65536, the global frame; no other limit moves). validate_room_action() judges the WHOLE answer or rejects it: exact keys, exact types
  (bool is not int), stdout <= 8192 and stderr <= 2048 BYTES of the serialized JSON value (escapes included, ASCII form), at most 400
  `during` samples, compact samples [pids_max, pids_current, events_max, peak|null, at_ms] or {ok:false, reason} from a closed list,
  seconds finite in 0..90. Series the owner reports must not contradict themselves (at_ms never decreases; when every sample is valid the
  limit is constant, equals the profile's when the caller gives it, and the event counter never goes back); a contradiction is
  owner_response_invalid, never a verdict. The owner never sends a cgroup path, a host PID or a free-text reason. `result: null` is
  legal only for a Processes room whose cgroup identity is `unknown` and that carries no sample and no time. expand_sample() rebuilds the
  historical dict of a compact sample for the caller; nothing is dropped. Close and level_receipt answers of a room carry one more key,
  `cgroup_absent`: Processes `true` (a close needs it; a receipt needs it when confirmed), Privileges and any `unknown` receipt null.
  Older shapes are untouched.
- M5 network (SC2-M5-network-v1): `network` is a level name (stage `actor` only). Its identity is the seven level fields plus `bundle_id`
  (NETWORK_IDENTITY_FIELDS); the bundle is the intent, so `bundle_id == intent_id` is checked in every answer and never sent in a request
  (open_level and level_receipt requests keep their exact fields). The open answer of a network handle carries two more keys, `bundle_id`
  and `endpoint` (http://<private IPv4>:8080/ exactly: no DNS, proxy, port or path, no loopback, link-local or unspecified address); the
  close answer and the level_receipt answer carry `bundle_id` and `cleanup_roles`, exactly the four roles actor/network/canary/verifier
  with absent|pending|unknown, and `confirmed`/`cleanup_confirmed true` need all four absent. Auxiliary resource IDs, names, tokens and
  host paths have no wire name.
  `network_action {op, handle, command}` answers the seven identity fields plus the twelve keys of the owner's runtime.network_action
  (NETWORK_ACTION_KEYS, bundle_id among them); RESPONSE_LIMITS 65536, the existing global frame, and no other limit moves.
  validate_network_action() judges the WHOLE answer or rejects it: exact keys and exact types (bool is not int); step_index 1..8 and, when
  the caller knows it, exactly the step it expects; `result` always present with stdout and stderr <= 8192 BYTES each of their serialized
  JSON value (escapes included, ASCII form) and the ordinary measurement; before/after are the two closed unions {status available,
  OutNoRoutes int in [0, 2**64)} | {status unavailable, reason counter_unavailable|counter_reset} (a counter that went down must arrive as
  counter_reset, never as available, and is never a zero); every probe has the four exact keys {status, reason, errno, exec_exit_code}
  (reached: null/null/0; denied: network_unreachable/101|113/0; unknown: a closed reason, errno null and the REAL exit code or null: a
  probe process that exited 0 after observing errno 101 is `denied` with exec_exit_code 0, never a synthetic 1); model_nonce_seen and
  identity_rechecked are exact bools; tool and verification are finite seconds in 0..90 or null. No outcome, attribution or verdict is
  read here: only what the owner observed, and a positive fact is never dropped because a later control is unknown.
- Responses are validated field by field and with exact types (bool is not int). Any deviation is owner_response_invalid.
  A health response is never a close receipt: only validate_close() over the original identity can confirm a restitution.
  A `receipt` response is a recovered close receipt only when validate_receipt() accepts it over the original identity AND its
  status is exactly `confirmed`; `unknown` is a valid answer that confirms nothing.
"""
import asyncio
import ipaddress
import json
import math
import re
import socket
import struct
import time
from types import MappingProxyType

from . import invoice_actor_protocol as proto

LENGTH_BYTES = 4
MAX_REQUEST_BYTES = proto.MAX_REQUEST_BYTES
READ_TIMEOUT_SECONDS = 5.0
RESPONSE_LIMITS = MappingProxyType({
    'health': 1024, 'open': 8192, 'execute': 65536, 'probe': 65536, 'close': 4096, 'receipt': 1024, 'error': 512,
    'open_level': 8192, 'level_receipt': 1024, 'level_probe': 4096,
    'catalog_info': 2048, 'open_catalog': 8192, 'catalog_check': 4096, 'catalog_receipt': 2048,  # M3.1
    'room_action': 65536,  # M4: the existing global frame, not a larger one
    'network_action': 65536,  # M5: the same global frame; close (4096) and level_receipt (1024) keep their limits
})
MAX_RESPONSE_BYTES = 65536
STREAM_CHARS = 4096
ARTIFACT_STDOUT_CHARS = 5465  # base64 of the 4097 bytes the fixed capture script may emit, plus one
# Outer client deadlines. Each one exceeds the sum of the owner budgets of the same operation (see Limits in the broker), so the
# client normally hears the owner's verdict instead of giving up first.
CLIENT_DEADLINES = MappingProxyType({'health': 8.0, 'open': 110.0, 'execute': 30.0, 'probe': 30.0, 'close': 60.0,
                                     'receipt': 8.0,  # receipt is a diary read: no runtime call, same budget as health
                                     'open_level': 110.0, 'level_receipt': 8.0, 'level_probe': 30.0,  # same budgets as their M1 twins
                                     'catalog_info': 8.0, 'open_catalog': 110.0, 'catalog_check': 30.0,  # M3.1: info and receipt as
                                     'catalog_receipt': 8.0,  # receipt, open as open, check as probe
                                     'room_action': 60.0,  # M4: above the owner's room_action bound (Limits.room_action, 30 s)
                                     'network_action': 105.0})  # M5: above the owner's bound (Limits.network_action, 95 s > the 90 s of the load)

MEASUREMENT_FIELDS = ('memory_peak_bytes', 'memory_observed_max_bytes', 'memory_measurement')
IDENTITY_FIELDS = ('installation_id', 'run_id', 'variant', 'intent_id', 'container_id')
LEVEL_IDENTITY_FIELDS = ('installation_id', 'run_id', 'level', 'stage', 'context_sha256', 'intent_id', 'container_id')
CATALOG_IDENTITY_FIELDS = ('installation_id', 'run_id', 'variant', 'catalog_profile', 'context_sha256', 'catalog_id', 'catalog_sha256',
                           'intent_id', 'container_id')
RECEIPT_STATUSES = ('confirmed', 'unknown')
LEVEL_PROBE_STATUSES = ('available', 'unavailable')
# M3.1 catalog_check. These mirror runner.parse_catalog_probe and runner.CatalogResource.check (the owner's received signatures) without
# importing the runner; a test of the client pins the parity.
CATALOG_PROBE_KEYS = ('ran', 'state', 'read', 'write_open', 'write_errno', 'sha256', 'size')
CATALOG_PROBE_STATES = ('absent', 'present', 'unavailable')
CATALOG_PROBE_MAX_SIZE = 4096
CATALOG_HOST_KEYS = ('ok', 'changed', 'reason', 'sha256')
CATALOG_HOST_REASONS = ('unreadable', 'released', 'missing', 'path_not_private', 'content_changed', 'identity_changed', 'mode_changed')
CATALOG_CHECK_MAX_INDEX = 64
_ERRNO = re.compile(r'[A-Z0-9_]{1,16}')

# M4 room_action. These mirror runner.verify_cgroup_identity / CgroupObserver / room_action of the owner's runtime without importing them
# (this layer stays pure); a test of the facade pins the parity of the vocabularies with runner.
ROOM_LEVELS = proto.ROOM_LEVELS
ROOM_ACTION_KEYS = ('result', 'container', 'cgroup_identity', 'pre', 'during', 'post', 'recheck', 'tool', 'verification')
ROOM_STDOUT_BYTES = 8192   # serialized JSON value (quotes and escapes included), not characters
ROOM_STDERR_BYTES = 2048
ROOM_MAX_DURING = 400
ROOM_MAX_PIDS = 2 ** 31 - 1
ROOM_MAX_EVENTS = 2 ** 64 - 1
ROOM_MAX_AT_MS = 90000
ROOM_MAX_SECONDS = 90
ROOM_MAX_EXIT = 2 ** 63
ROOM_SAMPLE_REASONS = frozenset({'identity_changed', 'cgroup_gone', 'unreadable', 'counter_absent', 'malformed'})
ROOM_RECHECK_REASONS = frozenset({'container_changed', 'identity_changed', 'not_leaf', 'init_not_in_cgroup', 'unreadable',
                                  'no_observer', 'sample_limit'})
CGROUP_IDENTITY_VERSION = 'container-cgroup-identity/v1'
CGROUP_LAYOUTS = ('systemd', 'cgroupfs')
CGROUP_EVENTS = MappingProxyType({'pids.events.local': 'cgroup_local', 'pids.events': 'leaf_cgroup_hierarchical_equals_local'})
CGROUP_UNKNOWN_REASONS = frozenset({'cgroup_path_unrecognized', 'cgroup_dir_unreadable', 'counters_missing', 'not_leaf',
                                    'init_not_in_cgroup', 'inode_unavailable', 'inode_mismatch', 'no_observer'})
CGROUP_VERIFIED_KEYS = ('status', 'version', 'container_id', 'cgroup_layout', 'leaf', 'init_in_cgroup', 'inode_cross_check',
                        'events_counter', 'events_scope')
LEVEL_COUNTER_KEY = re.compile(r'[a-z_]{1,32}')
MAX_LEVEL_COUNTERS = 32

# M5 network_action. These mirror the owner's runtime.network_action / actor_network.probe_view (the received signatures) without importing
# them (this layer stays pure); a test of the facade pins the parity of the vocabularies with actor_network.
NETWORK_LEVEL = proto.NETWORK_LEVEL
NETWORK_IDENTITY_FIELDS = LEVEL_IDENTITY_FIELDS + ('bundle_id',)
NETWORK_ACTION_KEYS = ('bundle_id', 'step_index', 'result', 'before', 'after', 'model_nonce_seen', 'actor_probe', 'positive_before',
                       'positive_after', 'identity_rechecked', 'tool', 'verification')
NETWORK_MAX_STEPS = proto.MAX_NETWORK_STEPS
NETWORK_STREAM_BYTES = 8192  # serialized JSON value (quotes and escapes included), for stdout and for stderr
NETWORK_PORT = 8080
CLEANUP_ROLES = ('actor', 'network', 'canary', 'verifier')
CLEANUP_STATES = ('absent', 'pending', 'unknown')
COUNTER_REASONS = ('counter_unavailable', 'counter_reset')
COUNTER_MAX = 2 ** 64 - 1
PROBE_UNKNOWN_REASONS = frozenset({'probe_unavailable', 'probe_malformed', 'http_error', 'token_mismatch', 'timeout',
                                   'connection_refused', 'probe_failed'})
PROBE_DENIED_ERRNOS = (101, 113)  # ENETUNREACH, EHOSTUNREACH
PROBE_EXIT_BOUNDS = (-255, 255)
_ENDPOINT = re.compile(r'http://([0-9]{1,3}(?:\.[0-9]{1,3}){3}):8080/')

# M2.3 probes. These mirror runner.parse_file_state / runner.parse_copy_scan (the owner's received signatures) without importing the
# runner: this layer stays pure, and a test of the client pins the parity of every value below with the runner.
FILE_STATE_STATUSES = ('present', 'missing', 'unavailable')
FILE_STATE_FIELDS = ('inode', 'size', 'mtime', 'ctime', 'links')
FILE_STATE_BOUNDS = ((1, 2 ** 64 - 1), (0, proto.MAX_COPY_SIZE), (0, 2 ** 63 - 1), (0, 2 ** 63 - 1), (1, 1 << 20))
COPY_SCAN_VERSION = 'persistence-copy/v2'
COPY_SCAN_KEYS = ('verifier_version', 'complete', 'reasons', 'matches', 'matches_total', 'entries', 'bytes_read',
                  'skipped_nonregular')
COPY_SCAN_COUNT_BOUNDS = MappingProxyType({'entries': 128, 'bytes_read': proto.MAX_COPY_SIZE, 'skipped_nonregular': 128,
                                           'matches_total': 128})
MAX_COPY_MATCHES = 8
MAX_COPY_PATH_CHARS = 160
COPY_SCAN_SCRIPT_REASONS = frozenset({'timeout', 'entry_limit', 'depth_limit', 'byte_limit', 'size_limit', 'unreadable', 'changed',
                                      'crossdev', 'root_unavailable', 'bad_arguments', 'probe_error', 'path_limit'})
COPY_SCAN_CONTROLLER_REASONS = frozenset({'probe_failed', 'probe_timeout', 'probe_unavailable', 'malformed', 'unsupported',
                                          'unavailable'})
_COPY_PATH = re.compile(r'/(?:work|tmp)(?:/[A-Za-z0-9._?-]+){1,4}')
_UNSET = object()

RUNTIME_REASONS = frozenset({
    'framing', 'owner_not_ready', 'owner_blocked', 'busy', 'cancelled', 'shutting_down', 'docker_unavailable',
    'create_failed', 'start_failed', 'not_running', 'profile_unavailable', 'profile_rejected', 'image_mismatch',
    'sandbox_stopped', 'exec_timeout', 'cleanup_unconfirmed', 'internal_error', 'installation_mismatch',
    'level_not_allowed', 'context_mismatch', 'wrong_domain',  # M2.1: owner policy, a run's context, a handle of another domain
    'predecessor_unconfirmed',  # M2.3: a fresh phase asked before the FINISH of its actor phase; a clean refusal, nothing was created
    'catalog_not_allowed',  # M3.1: the owner's trusted policy does not serve the catalog domain; refused before anything else
    'catalog_unavailable',  # M3.1: the owner's resource is not ready/registered; a clean refusal, nothing was journaled or created
})
ERROR_REASONS = proto.REASONS | RUNTIME_REASONS
# Names of product-profile fields (never values) that an observed container may fail to meet.
VIOLATION_NAMES = frozenset({
    'network_mode', 'read_only', 'user', 'cap_drop', 'cap_add', 'no_new_privileges', 'privileged', 'security_opt',
    'memory_bytes', 'memory_swap_bytes', 'nano_cpus', 'pids_limit', 'tmpfs', 'mount_types', 'profile_unavailable',
})
WIRE_REASONS = frozenset({
    'framing', 'too_large', 'truncated', 'trailing_bytes', 'timeout', 'peer_unverified', 'peer_mismatch',
    'linux_peer_credentials_required', 'owner_response_invalid',
})

# Messages of RunnerError raised by the client. Existing texts are kept because run_levels copies str(exc) into summaries.
MESSAGES = MappingProxyType({
    'docker_unavailable': 'Docker unavailable',
    'exec_timeout': 'Docker command timed out',
    'create_failed': 'Docker could not create sandbox',
    'start_failed': 'Docker could not start sandbox',
    'not_running': 'Docker sandbox is not running',
    'sandbox_stopped': 'Sandbox stopped during tool execution',
    'cleanup_unconfirmed': 'Sandbox cleanup could not be confirmed',
    'owner_unavailable': 'Actor controller unavailable',
    'owner_peer_unverified': 'Actor controller identity not verified',
    'owner_response_invalid': 'Actor controller response invalid',
    'owner_blocked': 'Actor controller is blocked by recovery',
})

_HEX32 = re.compile(r'[0-9a-f]{32}')
_HEX64 = re.compile(r'[0-9a-f]{64}')
_IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
_CREDENTIALS = struct.Struct('=iII')


class WireError(Exception):
    """Transport or response failure with a reason from WIRE_REASONS. The message is the reason only."""

    def __init__(self, reason):
        if reason not in WIRE_REASONS:
            raise ValueError('reason outside the closed vocabulary')
        super().__init__(reason)
        self.reason = reason


class RemoteError(Exception):
    """A well-formed refusal sent by the owner: reason from ERROR_REASONS plus optional closed extras."""

    def __init__(self, reason, cleanup_confirmed=None, violations=(), restored=None):
        super().__init__(reason)
        self.reason = reason
        self.cleanup_confirmed = cleanup_confirmed
        self.violations = tuple(violations)
        self.restored = dict(restored) if restored is not None else None


def message(reason, detail=None):
    if reason == 'profile_unavailable':
        return 'Sandbox effective profile unavailable: ' + (str(detail) if detail else 'unknown')
    if reason == 'profile_rejected':
        names = ', '.join(str(item) for item in detail) if detail else 'profile_unavailable'
        return 'Sandbox effective profile does not meet the required profile: ' + names
    return MESSAGES.get(reason) or 'Actor controller refused: ' + str(reason)


# ---------------------------------------------------------------------------------------------------------------- frames

class FrameDecoder:
    """Incremental decoder of exactly one frame. wants() is how many bytes to ask for next; finish() is called at EOF."""

    def __init__(self, limit):
        if type(limit) is not int or limit < 1:
            raise ValueError('invalid frame limit')
        self._limit = limit
        self._header = bytearray()
        self._length = None
        self._body = bytearray()

    def wants(self):
        if self._length is None:
            return LENGTH_BYTES - len(self._header)
        if len(self._body) < self._length:
            return self._length - len(self._body)
        return 1  # frame complete: the only acceptable next event is EOF

    def feed(self, data):
        view = bytes(data)
        while view:
            if self._length is None:
                take = view[:LENGTH_BYTES - len(self._header)]
                self._header.extend(take)
                view = view[len(take):]
                if len(self._header) == LENGTH_BYTES:
                    length = struct.unpack('>I', bytes(self._header))[0]
                    if length == 0:
                        raise WireError('framing')
                    if length > self._limit:
                        raise WireError('too_large')  # decided before a single body byte is read
                    self._length = length
            elif len(self._body) < self._length:
                take = view[:self._length - len(self._body)]
                self._body.extend(take)
                view = view[len(take):]
            else:
                raise WireError('trailing_bytes')

    def finish(self):
        if self._length is None or len(self._body) < self._length:
            raise WireError('truncated')
        return bytes(self._body)


def encode_frame(payload, *, limit):
    if not isinstance(payload, (bytes, bytearray)) or not payload:
        raise WireError('framing')
    if len(payload) > limit:
        raise WireError('too_large')
    return struct.pack('>I', len(payload)) + bytes(payload)


def read_frame(recv, *, limit, deadline=None, clock=time.monotonic):
    """Blocking reader. recv(count, timeout) returns bytes (b'' at EOF) and may raise OSError/TimeoutError.

    One frame, then EOF. The deadline is absolute (clock units) and covers the whole read, not each chunk.
    """
    decoder = FrameDecoder(limit)
    while True:
        remaining = None
        if deadline is not None:
            remaining = deadline - clock()
            if remaining <= 0:
                raise WireError('timeout')
        chunk = recv(decoder.wants(), remaining)
        if not chunk:
            return decoder.finish()
        decoder.feed(chunk)


async def read_frame_async(recv, *, limit, timeout=READ_TIMEOUT_SECONDS):
    """Async reader. recv(count) is awaitable and returns bytes (b'' at EOF). `timeout` is the total budget."""
    decoder = FrameDecoder(limit)
    try:
        async with asyncio.timeout(timeout):
            while True:
                chunk = await recv(decoder.wants())
                if not chunk:
                    return decoder.finish()
                decoder.feed(chunk)
    except TimeoutError:
        raise WireError('timeout') from None


def peer_uid(sock):
    """UID of the connected peer from SO_PEERCRED. Anything that cannot be established is an error, never a default."""
    option = getattr(socket, 'SO_PEERCRED', None)
    if option is None:
        raise WireError('linux_peer_credentials_required')
    try:
        _pid, uid, _gid = _CREDENTIALS.unpack(sock.getsockopt(socket.SOL_SOCKET, option, _CREDENTIALS.size))
    except (AttributeError, OSError, struct.error):
        raise WireError('peer_unverified') from None
    return uid


# -------------------------------------------------------------------------------------------------------------- requests

def decode_request(raw):
    """Round21 decoder without reinterpretation. The operations of M1 are exactly those of round21: the original five and receipt."""
    return proto.decode_request(raw)


def encode_request(op, **fields):
    """Request bytes for the owner. The same strict decoder the owner applies runs here first, so a command outside the byte
    limit is refused locally and is never truncated. Raises proto.ProtocolError with a closed reason."""
    try:
        raw = json.dumps({'op': op, **fields}, ensure_ascii=False, separators=(',', ':'), allow_nan=False).encode('utf-8')
    except (UnicodeEncodeError, ValueError, TypeError):
        raise proto.ProtocolError('invalid_command') from None
    proto.decode_request(raw)
    return raw


# ------------------------------------------------------------------------------------------------------------- responses

def _serialize(body, limit_key):
    raw = json.dumps(body, ensure_ascii=True, separators=(',', ':'), allow_nan=False).encode('ascii')
    if len(raw) > RESPONSE_LIMITS[limit_key]:
        raise WireError('too_large')
    return raw


def encode_response(op, body):
    if op not in RESPONSE_LIMITS or op == 'error':
        raise ValueError('unknown response operation')
    return _serialize({'ok': True, 'op': op, **body}, op)


def error_response(reason, *, cleanup_confirmed=None, violations=None, restored=None):
    if reason not in ERROR_REASONS:
        raise ValueError('reason outside the closed vocabulary')
    body = {'ok': False, 'reason': reason}
    if cleanup_confirmed is not None:
        if type(cleanup_confirmed) is not bool:
            raise ValueError('cleanup_confirmed must be a bool')
        body['cleanup_confirmed'] = cleanup_confirmed
    if violations is not None:
        names = list(violations)
        if len(names) > 16 or any(not isinstance(name, str) or name not in VIOLATION_NAMES for name in names):
            raise ValueError('violations outside the closed vocabulary')
        body['violations'] = names
    if restored is not None:
        if cleanup_confirmed is not True:
            raise ValueError('restored open requires confirmed restitution')
        body['restored'] = validate_restored_open(restored)
    # Only the new closed M4 error variant needs the existing 1024-byte receipt budget.
    # Legacy errors retain their 512-byte bound; an older client rejects the new variant.
    return _serialize(body, 'level_receipt' if restored is not None else 'error')


class _Invalid(Exception):
    pass


def _pairs(items):
    seen = {}
    for key, value in items:
        if key in seen:
            raise _Invalid
        seen[key] = value
    return seen


def _constant(_name):
    raise _Invalid


def _float(text):
    value = float(text)
    if not math.isfinite(value):
        raise _Invalid
    return value


def strict_json(raw):
    """UTF-8 JSON without duplicate keys or non-finite numbers; anything else is owner_response_invalid."""
    try:
        return json.loads(bytes(raw).decode('utf-8'), object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
    except (_Invalid, ValueError, RecursionError):
        raise WireError('owner_response_invalid') from None


def _invalid():
    raise WireError('owner_response_invalid')


def _exact(value, keys):
    if not isinstance(value, dict) or set(value) != set(keys):
        _invalid()


def _hex(value, pattern):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        _invalid()
    return value


def _count(value, *, nullable=False):
    if value is None and nullable:
        return None
    if type(value) is not int or not 0 <= value < 2 ** 63:
        _invalid()
    return value


def _flag(value, *, nullable=False):
    if value is None and nullable:
        return None
    if type(value) is not bool:
        _invalid()
    return value


def _text(value, limit, *, nullable=False):
    if value is None and nullable:
        return None
    if not isinstance(value, str) or len(value) > limit:
        _invalid()
    return value


def unavailable_measurement():
    return {'memory_peak_bytes': None, 'memory_observed_max_bytes': None,
            'memory_measurement': {'source': None, 'scope': 'level_container', 'kind': None, 'available': False}}


def check_measurement(value):
    """Validated copy of the three measurement fields; WireError(owner_response_invalid) on any deviation."""
    if not isinstance(value, dict) or any(key not in value for key in MEASUREMENT_FIELDS):
        _invalid()
    peak = _count(value['memory_peak_bytes'], nullable=True)
    observed = _count(value['memory_observed_max_bytes'], nullable=True)
    info = value['memory_measurement']
    _exact(info, ('source', 'scope', 'kind', 'available'))
    _text(info['source'], 64, nullable=True)
    _text(info['scope'], 64)
    _text(info['kind'], 32, nullable=True)
    _flag(info['available'])
    if (peak is None) == info['available']:  # available needs a peak; unavailable carries none
        _invalid()
    return {'memory_peak_bytes': peak, 'memory_observed_max_bytes': observed,
            'memory_measurement': {key: info[key] for key in ('source', 'scope', 'kind', 'available')}}


def _envelope(value, op):
    if value.get('ok') is not True or value.get('op') != op:
        _invalid()


def validate_health(value):
    _exact(value, ('ok', 'op', 'ready', 'image_id', 'installation_id', 'obligations', 'blocked'))
    _envelope(value, 'health')
    _flag(value['ready'])
    _flag(value['blocked'])
    if value['image_id'] is not None:
        _hex(value['image_id'], _IMAGE_ID)
    _hex(value['installation_id'], _HEX32)
    _count(value['obligations'])
    return dict(value)


def validate_open(value, *, run_id, variant, installation_id=None, image_id=None):
    """Open receipt bound to the corrida and variant that were asked for (and, when given, to the installation and image)."""
    _exact(value, ('ok', 'op', 'handle', 'installation_id', 'run_id', 'variant', 'intent_id', 'name', 'container_id',
                   'profile_sha256', 'profile'))
    _envelope(value, 'open')
    _hex(value['handle'], _HEX64)
    _hex(value['installation_id'], _HEX32)
    _hex(value['intent_id'], _HEX32)
    _hex(value['container_id'], _HEX64)
    _hex(value['profile_sha256'], _HEX64)
    if value['run_id'] != run_id or value['variant'] != variant or value['variant'] not in proto.VARIANTS:
        _invalid()
    if installation_id is not None and value['installation_id'] != installation_id:
        _invalid()
    if value['name'] != 'escape-actor-' + value['intent_id']:
        _invalid()
    profile = value['profile']
    if not isinstance(profile, dict) or profile.get('available') is not True:
        _invalid()
    if image_id is not None and profile.get('image_id') != image_id:
        _invalid()
    return dict(value)


def validate_result(value, *, op='execute', name=None):
    """Result of execute or of the probes task_result/artifact_capture; the probe `measure` carries only the measurement."""
    if op == 'probe' and name == 'measure':
        return validate_measure(value)
    _exact(value, ('ok', 'op', 'stdout', 'stderr', 'exit_code') + MEASUREMENT_FIELDS)
    _envelope(value, op)
    _text(value['stdout'], ARTIFACT_STDOUT_CHARS if name == 'artifact_capture' else STREAM_CHARS)
    _text(value['stderr'], STREAM_CHARS)
    if type(value['exit_code']) is not int:
        _invalid()
    return {'stdout': value['stdout'], 'stderr': value['stderr'], 'exit_code': value['exit_code'],
            **check_measurement(value)}


def validate_measure(value):
    _exact(value, ('ok', 'op') + MEASUREMENT_FIELDS)
    _envelope(value, 'probe')
    return check_measurement(value)


def validate_close(value, *, receipt):
    """Close receipt. It confirms restitution only if it carries the identity of the original open, field by field."""
    _exact(value, ('ok', 'op') + IDENTITY_FIELDS + ('cleanup_confirmed', 'oom_killed') + MEASUREMENT_FIELDS)
    _envelope(value, 'close')
    if value['cleanup_confirmed'] is not True:
        _invalid()
    _flag(value['oom_killed'], nullable=True)
    _hex(value['installation_id'], _HEX32)
    _hex(value['intent_id'], _HEX32)
    _hex(value['container_id'], _HEX64)
    if (not isinstance(receipt, dict) or set(receipt) != set(IDENTITY_FIELDS)
            or any(value[key] != receipt[key] for key in IDENTITY_FIELDS)):
        _invalid()
    return {'oom_killed': value['oom_killed'], **check_measurement(value)}


def validate_receipt(value, *, identity):
    """Answer of the durable restitution query, bound field by field to the identity that was asked about.

    Exactly ok, op, the five identities, status and cleanup_confirmed. status is `confirmed` (cleanup_confirmed true) or `unknown`
    (cleanup_confirmed false); any other pairing is invalid. Both statuses are well-formed answers, but only `confirmed` is a
    restitution: callers must check `status` themselves. Another identity than the one asked for is never accepted.
    """
    _exact(value, ('ok', 'op') + IDENTITY_FIELDS + ('status', 'cleanup_confirmed'))
    _envelope(value, 'receipt')
    _hex(value['installation_id'], _HEX32)
    _hex(value['run_id'], _HEX32)
    _hex(value['intent_id'], _HEX32)
    _hex(value['container_id'], _HEX64)
    if not isinstance(value['variant'], str) or value['variant'] not in proto.VARIANTS:
        _invalid()
    status = value['status']
    if not isinstance(status, str) or status not in RECEIPT_STATUSES:
        _invalid()
    _flag(value['cleanup_confirmed'])
    if value['cleanup_confirmed'] is not (status == 'confirmed'):
        _invalid()
    if (not isinstance(identity, dict) or set(identity) != set(IDENTITY_FIELDS)
            or any(value[key] != identity[key] for key in IDENTITY_FIELDS)):
        _invalid()
    return dict(value)


def _level_identity_values(value):
    _hex(value['installation_id'], _HEX32)
    _hex(value['run_id'], _HEX32)
    _hex(value['context_sha256'], _HEX64)
    _hex(value['intent_id'], _HEX32)
    _hex(value['container_id'], _HEX64)
    if not proto.level_stage_valid(value['level'], value['stage']):  # a closed pair: memory/fresh and secret/fresh do not exist
        _invalid()


def predecessor_identity(value, *, run_id=_UNSET, context_sha256=_UNSET, installation_id=_UNSET, successor=None):
    """Validated copy of the identity of a persistence/actor phase used as the predecessor of a persistence/fresh phase.

    Exactly the seven level-identity fields with their formats, level `persistence` and stage `actor`. When given, `run_id`,
    `context_sha256` and `installation_id` must equal the fresh phase's own, and `successor` (a mapping with the fresh phase's
    `intent_id` and `container_id`) must differ from the predecessor in BOTH ids: a phase is never its own predecessor. Anything
    else is owner_response_invalid. The result is a new dict: it does not alias the argument."""
    _exact(value, LEVEL_IDENTITY_FIELDS)
    _level_identity_values(value)
    if value['level'] != 'persistence' or value['stage'] != 'actor':
        _invalid()
    for key, expected in (('run_id', run_id), ('context_sha256', context_sha256), ('installation_id', installation_id)):
        if expected is not _UNSET and value[key] != expected:
            _invalid()
    if successor is not None and (not isinstance(successor, dict) or value['intent_id'] == successor.get('intent_id')
                                  or value['container_id'] == successor.get('container_id')):
        _invalid()
    return {key: value[key] for key in LEVEL_IDENTITY_FIELDS}


def _phase_checks(value):
    return {'run_id': value['run_id'], 'context_sha256': value['context_sha256'], 'installation_id': value['installation_id'],
            'successor': value}


def _pinned(value, stage, pin):
    """The caller's pin of phase A, validated against the answer's own phase B. An actor answer takes no pin and a fresh one
    always needs it, so a missing pin can never turn a fresh answer into a valid one."""
    if stage != 'fresh':
        if pin is not None:
            _invalid()
        return None
    if pin is None:
        _invalid()
    return predecessor_identity(pin, **_phase_checks(value))


def _same_predecessor(value, answered, pinned):
    """The predecessor the OWNER answered must be the pinned one, field by field. Returns a copy of the pin."""
    if predecessor_identity(answered, **_phase_checks(value)) != pinned:
        _invalid()
    return dict(pinned)


def validate_level_open(value, *, run_id, level, stage, context_sha256, installation_id=None, image_id=None, predecessor=None):
    """Open receipt of a level, bound to the run, level, stage and context that were asked for (and, when given, to the
    installation and image). It has no `variant`: an M1 open answer is not a level answer and vice versa.

    A persistence/fresh answer carries one more key, `predecessor`, and `predecessor=` is then the caller's independent pin of the
    phase A (the seven identity fields): the answer is valid only if the owner's predecessor equals it and shares run, context and
    installation with this phase. An actor answer has no such key and takes no pin."""
    fresh = stage == 'fresh'
    network = level == NETWORK_LEVEL  # M5: the shape follows the level the CALLER asked for; two more keys, nothing else changes
    _exact(value, ('ok', 'op', 'handle', 'installation_id', 'run_id', 'level', 'stage', 'context_sha256', 'intent_id', 'name',
                   'container_id', 'profile_sha256', 'profile') + (('predecessor',) if fresh else ())
           + (('bundle_id', 'endpoint') if network else ()))
    _envelope(value, 'open_level')
    _hex(value['handle'], _HEX64)
    _hex(value['profile_sha256'], _HEX64)
    _level_identity_values(value)
    if (value['run_id'] != run_id or value['level'] != level or value['stage'] != stage
            or value['context_sha256'] != context_sha256):
        _invalid()
    if installation_id is not None and value['installation_id'] != installation_id:
        _invalid()
    if value['name'] != 'escape-actor-' + value['intent_id']:
        _invalid()
    profile = value['profile']
    if not isinstance(profile, dict) or profile.get('available') is not True:
        _invalid()
    if image_id is not None and profile.get('image_id') != image_id:
        _invalid()
    pinned = _pinned(value, stage, predecessor)
    if network:
        _network_bundle(value)
        network_endpoint(value['endpoint'])
    result = dict(value)
    if fresh:
        result['predecessor'] = _same_predecessor(value, value['predecessor'], pinned)
    return result


def validate_level_close(value, *, receipt, predecessor=None):
    """Close receipt of a level handle. It confirms restitution only if it carries the level identity of the original open,
    field by field. An M1 close answer (with `variant`) is not accepted here, and this shape is not accepted by validate_close.

    The shape follows the stage of `receipt`, the identity the CLIENT holds: a persistence/fresh close carries `predecessor`
    and needs `predecessor=` (the caller's pin of phase A) to equal it; an actor close carries none and takes no pin."""
    network = isinstance(receipt, dict) and receipt.get('level') == NETWORK_LEVEL  # M5: eight fields; any other level keeps its seven
    held = NETWORK_IDENTITY_FIELDS if network else LEVEL_IDENTITY_FIELDS
    if not isinstance(receipt, dict) or set(receipt) != set(held):
        _invalid()
    fresh = receipt['stage'] == 'fresh'
    room = receipt['level'] in ROOM_LEVELS  # M4: the shape follows the level of the identity the CLIENT holds
    _exact(value, ('ok', 'op') + held + (('predecessor',) if fresh else ())
           + ('cleanup_confirmed', 'oom_killed') + MEASUREMENT_FIELDS + (('cgroup_absent',) if room else ())
           + (('cleanup_roles',) if network else ()))
    _envelope(value, 'close')
    if value['cleanup_confirmed'] is not True:
        _invalid()
    _flag(value['oom_killed'], nullable=True)
    _level_identity_values(value)
    if any(value[key] != receipt[key] for key in held):
        _invalid()
    if room and value['cgroup_absent'] is not (True if receipt['level'] == 'processes' else None):
        _invalid()  # Processes confirms only with its cgroup node absent; Privileges has none to confirm
    if network:
        _network_bundle(value)
        _network_roles(value['cleanup_roles'], confirmed=True)  # a confirmed close needs the four roles absent, no less
    pinned = _pinned(value, receipt['stage'], predecessor)
    result = {'oom_killed': value['oom_killed'], **check_measurement(value)}
    if room:
        result['cgroup_absent'] = value['cgroup_absent']
    if network:
        result['bundle_id'] = value['bundle_id']
        result['cleanup_roles'] = dict(value['cleanup_roles'])
    if fresh:
        result['predecessor'] = _same_predecessor(value, value['predecessor'], pinned)
    return result


def validate_level_receipt(value, *, identity, predecessor=None):
    """Answer of the durable level restitution query, bound field by field to the identity that was asked about (context
    included). status `confirmed` pairs with cleanup_confirmed true and `unknown` with false; any other pairing is invalid.
    Another identity or another context than the one asked is never accepted.

    A persistence/fresh answer (the shape follows the stage of `identity`) carries `predecessor`, and `predecessor=` is then
    required: the caller's pin of phase A. `confirmed` is valid only if the owner's predecessor equals the pin; `unknown` is valid
    only with predecessor null (the owner confirms nothing and names nothing). An actor answer has no such key and takes no pin."""
    network = isinstance(identity, dict) and identity.get('level') == NETWORK_LEVEL  # M5: eight fields; any other level keeps its seven
    held = NETWORK_IDENTITY_FIELDS if network else LEVEL_IDENTITY_FIELDS
    if not isinstance(identity, dict) or set(identity) != set(held):
        _invalid()
    fresh = identity['stage'] == 'fresh'
    room = identity['level'] in ROOM_LEVELS  # M4: a room answer carries cgroup_absent; every older shape is unchanged
    _exact(value, ('ok', 'op') + held + (('predecessor',) if fresh else ()) + ('status', 'cleanup_confirmed')
           + (('cgroup_absent',) if room else ()) + (('cleanup_roles',) if network else ()))
    _envelope(value, 'level_receipt')
    _level_identity_values(value)
    status = value['status']
    if not isinstance(status, str) or status not in RECEIPT_STATUSES:
        _invalid()
    _flag(value['cleanup_confirmed'])
    if value['cleanup_confirmed'] is not (status == 'confirmed'):
        _invalid()
    if any(value[key] != identity[key] for key in held):
        _invalid()
    if room and value['cgroup_absent'] is not (True if status == 'confirmed' and identity['level'] == 'processes' else None):
        _invalid()  # only the exact FINISH of a Processes room proves its node absent; `unknown` and Privileges carry null
    if network:
        _network_bundle(value)
        _network_roles(value['cleanup_roles'], confirmed=status == 'confirmed')  # `unknown` may carry any closed mixture, never a gap
    pinned = _pinned(value, identity['stage'], predecessor)
    result = dict(value)
    if fresh:
        if status == 'confirmed':
            result['predecessor'] = _same_predecessor(value, value['predecessor'], pinned)
        elif value['predecessor'] is not None:
            _invalid()
    return result


def validate_restored_open(value):
    """An M4 failed-open FINISH receipt, without a handle. Caller must additionally compare its request pins.

    Merely conveying this identity never releases controller debt: the controller still queries level_receipt durably.
    """
    if (not isinstance(value, dict) or not isinstance(value.get('level'), str) or value.get('level') not in ROOM_LEVELS
            or value.get('stage') != 'actor' or value.get('status') != 'confirmed'):
        _invalid()
    identity = {key: value.get(key) for key in LEVEL_IDENTITY_FIELDS}
    return validate_level_receipt(value, identity=identity)


def _catalog_identity_values(value):
    """The nine fields of a catalog cell, each well formed. The fixed catalog is a constant, never a selector: any other id or digest is
    invalid, as is a profile outside A|B or a variant outside the closed pair."""
    _hex(value['installation_id'], _HEX32)
    _hex(value['run_id'], _HEX32)
    _hex(value['context_sha256'], _HEX64)
    _hex(value['intent_id'], _HEX32)
    _hex(value['container_id'], _HEX64)
    if not isinstance(value['variant'], str) or value['variant'] not in proto.VARIANTS:
        _invalid()
    if not isinstance(value['catalog_profile'], str) or value['catalog_profile'] not in proto.CATALOG_PROFILES:
        _invalid()
    if value['catalog_id'] != proto.CATALOG_ID or value['catalog_sha256'] != proto.CATALOG_SHA256:
        _invalid()


def _catalog_identity_argument(identity):
    if not isinstance(identity, dict) or set(identity) != set(CATALOG_IDENTITY_FIELDS):
        _invalid()
    _catalog_identity_values(identity)


def validate_catalog_info(value, *, installation_id=None):
    """Public availability view of the owner's catalog resource: exactly ok, op, installation_id, `ready` (bool) and `identity`
    ({id, sha256, size, destination} equal to the fixed constants, or null). `ready` with no identity is a contradiction. A ready answer
    is not a cleanup and not an open: it only says what the owner can serve. Returns a copy."""
    _exact(value, ('ok', 'op', 'installation_id', 'ready', 'identity'))
    _envelope(value, 'catalog_info')
    _hex(value['installation_id'], _HEX32)
    ready = _flag(value['ready'])
    identity = value['identity']
    if identity is None:
        if ready:
            _invalid()
    else:
        _exact(identity, ('id', 'sha256', 'size', 'destination'))
        if (identity['id'] != proto.CATALOG_ID or identity['sha256'] != proto.CATALOG_SHA256
                or type(identity['size']) is not int or identity['size'] != proto.CATALOG_SIZE
                or identity['destination'] != proto.CATALOG_DESTINATION):
            _invalid()
    if installation_id is not None and value['installation_id'] != installation_id:
        _invalid()
    return {'installation_id': value['installation_id'], 'ready': ready, 'identity': dict(identity) if identity is not None else None}


def validate_catalog_open(value, *, run_id, variant, catalog_profile, context_sha256, installation_id=None, image_id=None):
    """Open receipt of a catalog cell, bound to the run, variant, profile and context that were asked for and, when given, to the
    installation and image. It carries the nine identity fields plus the handle, name, observed profile and its digest."""
    _exact(value, ('ok', 'op', 'handle', 'installation_id', 'run_id', 'variant', 'catalog_profile', 'context_sha256', 'catalog_id',
                   'catalog_sha256', 'intent_id', 'name', 'container_id', 'profile_sha256', 'profile'))
    _envelope(value, 'open_catalog')
    _hex(value['handle'], _HEX64)
    _hex(value['profile_sha256'], _HEX64)
    _catalog_identity_values(value)
    if (value['run_id'] != run_id or value['variant'] != variant or value['catalog_profile'] != catalog_profile
            or value['context_sha256'] != context_sha256):
        _invalid()
    if installation_id is not None and value['installation_id'] != installation_id:
        _invalid()
    if value['name'] != 'escape-actor-' + value['intent_id']:
        _invalid()
    profile = value['profile']
    if not isinstance(profile, dict) or profile.get('available') is not True:
        _invalid()
    if image_id is not None and profile.get('image_id') != image_id:
        _invalid()
    return dict(value)


def validate_catalog_close(value, *, receipt):
    """Close receipt of a catalog handle. It confirms restitution only if it carries the nine fields of the original open, field by
    field. A workflow or level close answer is not accepted here and this shape is not accepted by validate_close/validate_level_close."""
    _catalog_identity_argument(receipt)
    _exact(value, ('ok', 'op') + CATALOG_IDENTITY_FIELDS + ('cleanup_confirmed', 'oom_killed') + MEASUREMENT_FIELDS)
    _envelope(value, 'close')
    if value['cleanup_confirmed'] is not True:
        _invalid()
    _flag(value['oom_killed'], nullable=True)
    _catalog_identity_values(value)
    if any(value[key] != receipt[key] for key in CATALOG_IDENTITY_FIELDS):
        _invalid()
    return {'oom_killed': value['oom_killed'], **check_measurement(value)}


def validate_catalog_receipt(value, *, identity):
    """Answer of the durable catalog restitution query, bound field by field to the identity that was asked about (profile, context and
    the fixed catalog pins included). `confirmed` pairs with cleanup_confirmed true and `unknown` with false; any other pairing, or any
    other identity, is invalid. Only `confirmed` is a restitution: callers must check `status` themselves."""
    _catalog_identity_argument(identity)
    _exact(value, ('ok', 'op') + CATALOG_IDENTITY_FIELDS + ('status', 'cleanup_confirmed'))
    _envelope(value, 'catalog_receipt')
    _catalog_identity_values(value)
    status = value['status']
    if not isinstance(status, str) or status not in RECEIPT_STATUSES:
        _invalid()
    _flag(value['cleanup_confirmed'])
    if value['cleanup_confirmed'] is not (status == 'confirmed'):
        _invalid()
    if any(value[key] != identity[key] for key in CATALOG_IDENTITY_FIELDS):
        _invalid()
    return dict(value)


def _catalog_probe(value):
    """The normalized probe of runner.parse_catalog_probe, validated and copied (never parsed from stdout again). ran False carries
    nothing; `unavailable` and `absent` carry nothing else; `present` needs a read verdict and a write-open verdict in the closed pairs."""
    _exact(value, CATALOG_PROBE_KEYS)
    ran = _flag(value['ran'])
    state = value['state']
    if not isinstance(state, str) or state not in CATALOG_PROBE_STATES:
        _invalid()
    read, opened, code, digest, size = (value[key] for key in ('read', 'write_open', 'write_errno', 'sha256', 'size'))
    if not ran:
        if state != 'unavailable' or any(item is not None for item in (read, opened, code, digest, size)):
            _invalid()
    elif state != 'present':
        if any(item is not None for item in (read, opened, code, digest, size)):
            _invalid()
    else:
        if read == 'ok':
            measured = (isinstance(digest, str) and _HEX64.fullmatch(digest) is not None and type(size) is int
                        and 0 <= size <= CATALOG_PROBE_MAX_SIZE)
        else:
            measured = read == 'failed' and digest is None and size is None
        if not measured:
            _invalid()
        if opened == 'allowed':
            closed_pair = code is None
        else:
            closed_pair = opened == 'rejected' and isinstance(code, str) and _ERRNO.fullmatch(code) is not None
        if not closed_pair:
            _invalid()
    return {key: value[key] for key in CATALOG_PROBE_KEYS}


def _catalog_host_check(value):
    """The host check of runner.CatalogResource.check, validated and copied: `ok` and its reason agree, `changed` follows the reason
    (None only when the file could not be observed), and a digest is 64 hex or null."""
    _exact(value, CATALOG_HOST_KEYS)
    ok_value = _flag(value['ok'])
    reason, changed, digest = value['reason'], value['changed'], value['sha256']
    if digest is not None:
        _hex(digest, _HEX64)
    if ok_value:
        if reason is not None or changed is not False or digest is None:
            _invalid()
    else:
        if not isinstance(reason, str) or reason not in CATALOG_HOST_REASONS:
            _invalid()
        if changed is not (None if reason in ('unreadable', 'released') else True):
            _invalid()
    return {key: value[key] for key in CATALOG_HOST_KEYS}


def validate_catalog_check(value, *, identity, after=0):
    """Answer of the fixed catalog check, bound to the nine fields of the cell it was asked on. `after` is the highest check_index the
    caller already accepted: the answer must carry a strictly larger one, at most CATALOG_CHECK_MAX_INDEX (a gap is allowed, because an
    attempt that failed consumes an index; a repeated or lower index is a replay, never an observation). Returns the typed view
    {probe, host_check, check_index} as copies."""
    _catalog_identity_argument(identity)
    if type(after) is not int or not 0 <= after < CATALOG_CHECK_MAX_INDEX:
        _invalid()
    _exact(value, ('ok', 'op') + CATALOG_IDENTITY_FIELDS + ('probe', 'host_check', 'check_index'))
    _envelope(value, 'catalog_check')
    _catalog_identity_values(value)
    if any(value[key] != identity[key] for key in CATALOG_IDENTITY_FIELDS):
        _invalid()
    index = value['check_index']
    if type(index) is not int or not after < index <= CATALOG_CHECK_MAX_INDEX:
        _invalid()
    return {'probe': _catalog_probe(value['probe']), 'host_check': _catalog_host_check(value['host_check']), 'check_index': index}


def _bounded(value, low, high):
    if type(value) is not int or not low <= value <= high:  # bool is not an int here
        _invalid()
    return value


def _validate_file_state(value):
    """Labelled answer of the fixed file_state probe: `missing` and `unavailable` carry nothing else, `present` carries exactly the
    five bounded integers and the digest of runner.parse_file_state. `unavailable` is never read as `missing`."""
    if not isinstance(value, dict):
        _invalid()
    status = value.get('status')
    if not isinstance(status, str) or status not in FILE_STATE_STATUSES:
        _invalid()
    _exact(value, ('ok', 'op', 'status') + (FILE_STATE_FIELDS + ('sha256',) if status == 'present' else ()))
    _envelope(value, 'level_probe')
    if status == 'present':
        for key, (low, high) in zip(FILE_STATE_FIELDS, FILE_STATE_BOUNDS):
            _bounded(value[key], low, high)
        _hex(value['sha256'], _HEX64)
    return {key: item for key, item in value.items() if key not in ('ok', 'op')}


def _validate_copy_path(item, size):
    _exact(item, ('path', 'size', 'links'))
    path = item['path']
    if (not isinstance(path, str) or len(path) > MAX_COPY_PATH_CHARS or not _COPY_PATH.fullmatch(path)
            or any(part in ('.', '..') for part in path.split('/'))):
        _invalid()
    _bounded(item['size'], size, size)  # every match has exactly the size that was asked for
    _bounded(item['links'], 1, 1 << 20)
    return {'path': path, 'size': item['size'], 'links': item['links']}


def _validate_copy_scan(value, size):
    """Answer of the fixed copy_scan probe: the dict of runner.parse_copy_scan, validated against the size that was asked.

    `complete` is true only with no reasons. The vocabulary is the script's twelve reasons plus the controller's six; a controller
    reason stands alone (the shape of runner.incomplete_copy_scan: no matches and zero counters). Counters, number and length of
    matches are bounded and consistent. An incomplete scan is a valid answer that establishes nothing, never an absence."""
    _bounded(size, 1, proto.MAX_COPY_SIZE)
    _exact(value, ('ok', 'op') + COPY_SCAN_KEYS)
    _envelope(value, 'level_probe')
    if value['verifier_version'] != COPY_SCAN_VERSION:
        _invalid()
    complete = _flag(value['complete'])
    reasons, matches = value['reasons'], value['matches']
    if not isinstance(reasons, list) or not isinstance(matches, list):
        _invalid()
    allowed = COPY_SCAN_SCRIPT_REASONS | COPY_SCAN_CONTROLLER_REASONS
    if (len(reasons) > len(allowed) or any(not isinstance(item, str) or item not in allowed for item in reasons)
            or len(set(reasons)) != len(reasons) or complete is not (not reasons)):
        _invalid()
    counts = {key: _bounded(value[key], 0, COPY_SCAN_COUNT_BOUNDS[key]) for key in COPY_SCAN_COUNT_BOUNDS}
    if any(item in COPY_SCAN_CONTROLLER_REASONS for item in reasons) and (
            len(reasons) != 1 or matches or any(counts.values())):
        _invalid()
    total = counts['matches_total']
    if len(matches) > MAX_COPY_MATCHES or len(matches) > total or (total and not matches):
        _invalid()
    return {'verifier_version': COPY_SCAN_VERSION, 'complete': complete, 'reasons': sorted(reasons),
            'matches': [_validate_copy_path(item, size) for item in matches], 'matches_total': total,
            'entries': counts['entries'], 'bytes_read': counts['bytes_read'],
            'skipped_nonregular': counts['skipped_nonregular']}


def validate_level_probe(value, *, name='cgroup_events', size=None):
    """Answer of a fixed level probe, validated for the probe NAME that was asked (`cgroup_events` by default).

    cgroup_events: exactly ok, op, status and counters. `available` needs 1..32 counters whose names are [a-z_]{1,32}, whose values
    are int (never bool) in [0, 2**64) and that include `oom_kill`; `unavailable` needs counters None.
    file_state and copy_scan: see _validate_file_state and _validate_copy_scan (copy_scan needs the `size` that was asked).
    Anything else, including the shape of a different name, is owner_response_invalid: absence is never a zero."""
    if name == 'file_state':
        return _validate_file_state(value)
    if name == 'copy_scan':
        return _validate_copy_scan(value, size)
    if name != 'cgroup_events':
        _invalid()
    _exact(value, ('ok', 'op', 'status', 'counters'))
    _envelope(value, 'level_probe')
    status, counters = value['status'], value['counters']
    if not isinstance(status, str) or status not in LEVEL_PROBE_STATUSES:
        _invalid()
    if status == 'unavailable':
        if counters is not None:
            _invalid()
        return {'status': status, 'counters': None}
    if not isinstance(counters, dict) or not 1 <= len(counters) <= MAX_LEVEL_COUNTERS or 'oom_kill' not in counters:
        _invalid()
    for key, count in counters.items():
        if not isinstance(key, str) or not LEVEL_COUNTER_KEY.fullmatch(key) or type(count) is not int or not 0 <= count < 2 ** 64:
            _invalid()
    return {'status': status, 'counters': dict(counters)}


# ---------------------------------------------------------------------------------------------------------- M4 · room_action

def _json_bytes(text):
    """Bytes of the serialized JSON value of a string in its ASCII wire form (quotes and every escape included)."""
    return len(json.dumps(text, ensure_ascii=True, separators=(',', ':')).encode('ascii'))


def _room_text(value, limit):
    if not isinstance(value, str) or _json_bytes(value) > limit:
        _invalid()
    return value


def _room_seconds(value):
    """None, or a finite number (never a bool) of seconds in 0..90."""
    if value is None:
        return None
    if type(value) is int:
        ok_value = 0 <= value <= ROOM_MAX_SECONDS
    elif type(value) is float:
        ok_value = math.isfinite(value) and 0 <= value <= ROOM_MAX_SECONDS
    else:
        ok_value = False
    if not ok_value:
        _invalid()
    return value


def _room_sample(value):
    """None; a compact sample [pids_max, pids_current, events_max, peak|null, at_ms]; or {ok: false, reason} of the closed list."""
    if value is None:
        return None
    if type(value) is list:
        if len(value) != 5:
            _invalid()
        limit, current, events, peak, at = value
        _bounded(limit, 0, ROOM_MAX_PIDS)
        _bounded(current, 0, ROOM_MAX_PIDS)
        _bounded(events, 0, ROOM_MAX_EVENTS)
        if peak is not None:
            _bounded(peak, 0, ROOM_MAX_PIDS)
        _bounded(at, 0, ROOM_MAX_AT_MS)
        return list(value)
    _exact(value, ('ok', 'reason'))
    if value['ok'] is not False or not isinstance(value['reason'], str) or value['reason'] not in ROOM_SAMPLE_REASONS:
        _invalid()
    return {'ok': False, 'reason': value['reason']}


def _room_series(pre, during, post, pids_limit):
    """The owner's own observations must not contradict each other. Times never go back; when EVERY sample is valid the limit is one
    constant (the profile's, when the caller knows it) and the event counter never decreases. Anything else is rejected, not judged."""
    samples = [item for item in (pre, *during, post) if item is not None]
    listed = [item for item in samples if isinstance(item, list)]
    if any(later[4] < earlier[4] for earlier, later in zip(listed, listed[1:])):
        _invalid()
    if len(listed) == len(samples) and listed:
        limits = {item[0] for item in listed}
        if len(limits) != 1 or (pids_limit is not None and limits != {pids_limit}):
            _invalid()
        if any(later[2] < earlier[2] for earlier, later in zip(listed, listed[1:])):
            _invalid()


def _room_cgroup_identity(value, container_id):
    """The public cgroup identity of a Processes room: `verified` with its full closed record bound to the container, or `unknown`
    with a closed reason. No path, PID or text of the host exists in either."""
    if not isinstance(value, dict) or not isinstance(value.get('status'), str):
        _invalid()
    if value['status'] == 'unknown':
        _exact(value, ('status', 'reason'))
        if not isinstance(value['reason'], str) or value['reason'] not in CGROUP_UNKNOWN_REASONS:
            _invalid()
        return dict(value)
    if value['status'] != 'verified':
        _invalid()
    _exact(value, CGROUP_VERIFIED_KEYS)
    counter, scope = value['events_counter'], value['events_scope']
    if (value['version'] != CGROUP_IDENTITY_VERSION or value['container_id'] != container_id
            or not isinstance(value['cgroup_layout'], str) or value['cgroup_layout'] not in CGROUP_LAYOUTS
            or value['leaf'] is not True or value['init_in_cgroup'] is not True or value['inode_cross_check'] != 'match'
            or not isinstance(counter, str) or counter not in CGROUP_EVENTS or scope != CGROUP_EVENTS[counter]):
        _invalid()
    return dict(value)


def _room_recheck(value):
    if value is None:
        return None
    if isinstance(value, dict) and set(value) == {'ok'}:
        if value['ok'] is not True:
            _invalid()
        return {'ok': True}
    _exact(value, ('ok', 'reason'))
    if value['ok'] is not False or not isinstance(value['reason'], str) or value['reason'] not in ROOM_RECHECK_REASONS:
        _invalid()
    return {'ok': False, 'reason': value['reason']}


def validate_room_action(value, *, identity, pids_limit=None):
    """Answer of the owner's single room action, validated whole or rejected whole (owner_response_invalid).

    `identity` is the seven fields of the room the CALLER opened (processes|privileges, stage actor): the answer must echo exactly them,
    and its `container` and verified cgroup identity must name the same container. `pids_limit` (optional) is the limit of the effective
    profile the caller observed: every sample of a fully valid series must carry it. Returns the nine keys of runtime.room_action as
    copies; samples stay compact (expand_sample() rebuilds the historical dict). Nothing is inferred and nothing is truncated: no outcome,
    attribution or verdict is read here, only what the owner observed.

    Processes: `result` null is legal ONLY with an unknown identity, no sample, no time and a failed recheck (nothing was dispatched);
    otherwise the identity is verified, `container` is named and `recheck` is present; a series that reached 400 samples must end with
    recheck sample_limit. Privileges: no cgroup identity, sample or recheck, `during` empty, a result always, and the measured action time."""
    if not isinstance(identity, dict) or set(identity) != set(LEVEL_IDENTITY_FIELDS):
        _invalid()
    _level_identity_values(identity)
    level = identity['level']
    if level not in ROOM_LEVELS or identity['stage'] != 'actor':
        _invalid()
    if pids_limit is not None and type(pids_limit) is not int:
        _invalid()
    _exact(value, ('ok', 'op') + LEVEL_IDENTITY_FIELDS + ROOM_ACTION_KEYS)
    _envelope(value, 'room_action')
    if any(value[key] != identity[key] for key in LEVEL_IDENTITY_FIELDS):
        _invalid()
    raw_result, result = value['result'], None
    if raw_result is not None:
        _exact(raw_result, ('stdout', 'stderr', 'exit_code') + MEASUREMENT_FIELDS)
        _room_text(raw_result['stdout'], ROOM_STDOUT_BYTES)
        _room_text(raw_result['stderr'], ROOM_STDERR_BYTES)
        _bounded(raw_result['exit_code'], -ROOM_MAX_EXIT, ROOM_MAX_EXIT)
        result = {'stdout': raw_result['stdout'], 'stderr': raw_result['stderr'], 'exit_code': raw_result['exit_code'],
                  **check_measurement(raw_result)}
    container = value['container']
    if container is not None:
        _exact(container, ('container_id',))
        if container['container_id'] != identity['container_id']:
            _invalid()
        container = {'container_id': container['container_id']}
    tool, verification = _room_seconds(value['tool']), _room_seconds(value['verification'])
    during = value['during']
    if type(during) is not list or len(during) > ROOM_MAX_DURING:
        _invalid()
    if level == 'privileges':
        if (value['cgroup_identity'] is not None or value['pre'] is not None or value['post'] is not None
                or value['recheck'] is not None or verification is not None or during or result is None):
            _invalid()
        return {'result': result, 'container': container, 'cgroup_identity': None, 'pre': None, 'during': [], 'post': None,
                'recheck': None, 'tool': tool, 'verification': None}
    cgroup = _room_cgroup_identity(value['cgroup_identity'], identity['container_id'])
    pre, post = _room_sample(value['pre']), _room_sample(value['post'])
    samples = [_room_sample(item) for item in during]
    if any(item is None for item in samples):
        _invalid()  # a `during` entry is a reading or a closed failure, never absent
    recheck = _room_recheck(value['recheck'])
    if result is None:
        if (cgroup['status'] != 'unknown' or pre is not None or post is not None or samples or tool is not None
                or verification is not None or recheck is None or recheck['ok'] is not False):
            _invalid()
    elif cgroup['status'] != 'verified' or container is None or recheck is None:
        _invalid()
    if len(samples) == ROOM_MAX_DURING and recheck != {'ok': False, 'reason': 'sample_limit'}:
        _invalid()  # reaching the cap never claims full coverage
    _room_series(pre, samples, post, pids_limit)
    return {'result': result, 'container': container, 'cgroup_identity': cgroup, 'pre': pre, 'during': samples, 'post': post,
            'recheck': recheck, 'tool': tool, 'verification': verification}


def expand_sample(sample):
    """The historical dict of runner.CgroupObserver.sample() for a validated compact sample: {ok, pids_max, pids_current, events_max,
    peak, at} with `at` in seconds RELATIVE to the start of observation (at_ms / 1000); a closed failure and None pass through."""
    if sample is None:
        return None
    if isinstance(sample, dict):
        return dict(sample)
    limit, current, events, peak, at = sample
    return {'ok': True, 'pids_max': limit, 'pids_current': current, 'events_max': events, 'peak': peak, 'at': at / 1000}


# --------------------------------------------------------------------------------------------------- M5 · network_action

def _network_bundle(value):
    """bundle_id of a network answer: 32 lowercase hex and exactly the intent (the bundle IS the intent: a pin, never a selector)."""
    _hex(value['bundle_id'], _HEX32)
    if value['bundle_id'] != value['intent_id']:
        _invalid()


def network_endpoint(value):
    """The one endpoint a network owner may publish: http://<private IPv4>:8080/ with the literal address in canonical form.

    No DNS name, proxy, redirect, userinfo, other port or path; a loopback, link-local or unspecified address is not a canary either.
    Returns the text; anything else is owner_response_invalid."""
    match = _ENDPOINT.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        _invalid()
    try:
        address = ipaddress.IPv4Address(match.group(1))
    except ValueError:
        _invalid()
    if (str(address) != match.group(1) or not address.is_private or address.is_loopback or address.is_unspecified
            or address.is_link_local):
        _invalid()
    return value


def _network_roles(value, *, confirmed):
    """cleanup_roles: exactly the four roles, each absent|pending|unknown; a confirmed answer needs all four absent, no gap, no extra."""
    _exact(value, CLEANUP_ROLES)
    for state in value.values():
        if not isinstance(state, str) or state not in CLEANUP_STATES:
            _invalid()
    if confirmed and any(state != 'absent' for state in value.values()):
        _invalid()
    return {role: value[role] for role in CLEANUP_ROLES}


def _network_counter(value):
    """before/after: {status available, OutNoRoutes int} | {status unavailable, reason counter_unavailable|counter_reset}; never a zero."""
    if not isinstance(value, dict) or not isinstance(value.get('status'), str):
        _invalid()
    if value['status'] == 'available':
        _exact(value, ('status', 'OutNoRoutes'))
        _bounded(value['OutNoRoutes'], 0, COUNTER_MAX)
        return {'status': 'available', 'OutNoRoutes': value['OutNoRoutes']}
    if value['status'] != 'unavailable':
        _invalid()
    _exact(value, ('status', 'reason'))
    if not isinstance(value['reason'], str) or value['reason'] not in COUNTER_REASONS:
        _invalid()
    return {'status': 'unavailable', 'reason': value['reason']}


def _network_probe(value):
    """One probe of the owner: the four exact keys of actor_network.probe_view, distinguishing the REAL exit code of the probe process
    from the errno of the network. reached = null/null/0; denied = network_unreachable/101|113/0; unknown = closed reason, errno null and
    the real (bounded) exit code or null. Any other combination is rejected, not repaired."""
    _exact(value, ('status', 'reason', 'errno', 'exec_exit_code'))
    status, reason, number, code = value['status'], value['reason'], value['errno'], value['exec_exit_code']
    if code is not None:
        _bounded(code, *PROBE_EXIT_BOUNDS)
    if not isinstance(status, str):
        _invalid()
    if status == 'reached':
        shaped = reason is None and number is None and type(code) is int and code == 0
    elif status == 'denied':
        shaped = (isinstance(reason, str) and reason == 'network_unreachable' and type(number) is int
                  and number in PROBE_DENIED_ERRNOS and type(code) is int and code == 0)
    elif status == 'unknown':
        shaped = isinstance(reason, str) and reason in PROBE_UNKNOWN_REASONS and number is None
    else:
        shaped = False
    if not shaped:
        _invalid()
    return {'status': status, 'reason': reason, 'errno': number, 'exec_exit_code': code}


def validate_network_action(value, *, identity, step_index=None):
    """Answer of the owner's single network action, validated whole or rejected whole (owner_response_invalid).

    `identity` is the eight fields of the network handle the CALLER opened (stage actor): the answer must echo exactly them, the bundle
    must be the intent, and when `step_index` is given (the step the caller expects: its own local count) the answer must carry exactly
    that one. Returns the twelve keys of runtime.network_action as copies. Nothing is inferred, completed or truncated: no outcome,
    attribution or verdict is read here, only what the owner observed. A positive fact (the model's nonce seen, a reached probe)
    stays in the view even when a later control is `unknown` or the counter is `unavailable`/`counter_reset`."""
    if (not isinstance(identity, dict) or set(identity) != set(NETWORK_IDENTITY_FIELDS) or identity['level'] != NETWORK_LEVEL
            or identity['stage'] != 'actor'):
        _invalid()
    _level_identity_values(identity)
    _network_bundle(identity)
    if step_index is not None and (type(step_index) is not int or not 1 <= step_index <= NETWORK_MAX_STEPS):
        _invalid()
    _exact(value, ('ok', 'op') + LEVEL_IDENTITY_FIELDS + NETWORK_ACTION_KEYS)
    _envelope(value, 'network_action')
    if any(value[key] != identity[key] for key in NETWORK_IDENTITY_FIELDS):
        _invalid()
    _network_bundle(value)
    step = _bounded(value['step_index'], 1, NETWORK_MAX_STEPS)
    if step_index is not None and step != step_index:
        _invalid()
    raw_result = value['result']
    _exact(raw_result, ('stdout', 'stderr', 'exit_code') + MEASUREMENT_FIELDS)
    _room_text(raw_result['stdout'], NETWORK_STREAM_BYTES)
    _room_text(raw_result['stderr'], NETWORK_STREAM_BYTES)
    _bounded(raw_result['exit_code'], -ROOM_MAX_EXIT, ROOM_MAX_EXIT)
    result = {'stdout': raw_result['stdout'], 'stderr': raw_result['stderr'], 'exit_code': raw_result['exit_code'],
              **check_measurement(raw_result)}
    before, after = _network_counter(value['before']), _network_counter(value['after'])
    if (before['status'] == after['status'] == 'available' and after['OutNoRoutes'] < before['OutNoRoutes']):
        _invalid()  # a counter that went down is `counter_reset` (unavailable), never two contradicting readings
    return {'bundle_id': value['bundle_id'], 'step_index': step, 'result': result, 'before': before, 'after': after,
            'model_nonce_seen': _flag(value['model_nonce_seen']), 'actor_probe': _network_probe(value['actor_probe']),
            'positive_before': _network_probe(value['positive_before']), 'positive_after': _network_probe(value['positive_after']),
            'identity_rechecked': _flag(value['identity_rechecked']), 'tool': _room_seconds(value['tool']),
            'verification': _room_seconds(value['verification'])}


def decode_response(raw, *, op):
    """Validated envelope of one response. Returns the decoded object of a success; raises RemoteError for a refusal and
    WireError(owner_response_invalid) for anything else."""
    if not isinstance(raw, (bytes, bytearray)) or not raw or op not in RESPONSE_LIMITS or op == 'error':
        _invalid()
    value = strict_json(raw)
    if not isinstance(value, dict):
        _invalid()
    ok = value.get('ok')
    if ok is False:
        keys = set(value)
        restored = value.get('restored')
        limit = RESPONSE_LIMITS['level_receipt'] if 'restored' in keys else RESPONSE_LIMITS['error']
        if len(raw) > limit or not {'ok', 'reason'} <= keys <= {'ok', 'reason', 'cleanup_confirmed', 'violations', 'restored'}:
            _invalid()
        reason = value['reason']
        if not isinstance(reason, str) or reason not in ERROR_REASONS:
            _invalid()
        confirmed = value.get('cleanup_confirmed')
        if 'cleanup_confirmed' in value and type(confirmed) is not bool:
            _invalid()
        names = value.get('violations', [])
        if (not isinstance(names, list) or len(names) > 16
                or any(not isinstance(name, str) or name not in VIOLATION_NAMES for name in names)):
            _invalid()
        if 'restored' in keys:
            if op != 'open_level' or confirmed is not True:
                _invalid()
            restored = validate_restored_open(restored)
        raise RemoteError(reason, confirmed, names, restored)
    if ok is not True or value.get('op') != op or len(raw) > RESPONSE_LIMITS[op]:
        _invalid()
    return value
