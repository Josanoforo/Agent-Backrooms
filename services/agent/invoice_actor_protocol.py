"""Pure wire protocol and lease registry for the future Docker actor broker of invoice-reconcile/v1.

Scope and limits (read before wiring a transport):
- Standard library only. No Docker, subprocess, socket, filesystem or host path is touched, and nothing here is imported by
  main or by the current SC2/SC3 flow. This module is a contract, not a boundary: the boundary exists only when a future
  transport, guard and owner use it.
- decode_request() validates bytes and returns an immutable Request. It never interprets `command`: the contract for the
  future owner is that a command is executed ONLY inside the actor container, never by a host shell, and never rewritten here.
- Request size is checked on the raw bytes (16 KiB), the command separately on its UTF-8 size (8 KiB). A command near 8 KiB
  full of escaped characters can still exceed the 16 KiB request limit; that is rejected as too_large, by design.
- ActorLeases binds a random handle to a peer uid (an int the future transport reads from SO_PEERCRED; this module never
  reads a socket), a run_id and a variant. A lease leaves the registry ONLY through retire(cleanup_confirmed=True). Expiry
  stops use of the handle but does not release the slot: an expired lease still counts against capacity and still blocks
  reopening until the owner confirms cleanup. Durable recovery after a crash is another lane and is NOT simulated here: the
  registry is in memory and a restart loses it.
- retire() and pending_cleanup() belong to the trusted owner; the transport must never map a peer request to them.
- `receipt` (durable restitution query, maintainer decision after A3) is the sixth operation. It carries exactly installation_id,
  run_id, variant, intent_id and container_id, with the identity bounds of M1 (32/32/closed/32/64 lowercase hex), and no handle:
  it is answered from the durable diary alone, never from this registry. The other five operations keep their fields.
- Mapping of workflow steps (input preparation, canary probe, final probes) to these operations is NOT defined here and must
  be decided explicitly before a transport is connected.
- M2.1 (levels, M2-CONTRATO-AGENTE) adds three closed operations in LEVEL_OP_FIELDS, kept apart from the M1 table OP_FIELDS:
  `open_level` (run_id, level, stage, context_sha256), `level_receipt` (the seven identities of a level, no handle) and
  `level_probe` (handle, name). level and stage are their own vocabulary (LEVELS, STAGES): they are never a `variant`, and a
  variant is never a level. The codec only recognizes the closed names; which levels an owner serves is a policy of the owner
  (the broker's trusted `allowed_levels`), never a request field. A lease opened for a level carries level, stage and context
  and no variant; it shares the single plaza and the TTL of the registry with the M1 leases.
- M2.3 (persistence, SC2-PERSISTENCIA-ADAPTADORES-LOCAL) extends the same closed vocabularies instead of adding operations: level
  `persistence` and stage `fresh`, valid only as the pairs of LEVEL_STAGES (persistence/actor, persistence/fresh; memory and secret
  stay actor-only, so memory/fresh is invalid_stage at the codec). open_level and level_receipt keep their exact fields: a request
  NEVER carries a predecessor, the owner derives it from its durable diary. `level_probe` gains two names, and its field set then
  depends on the name (LEVEL_PROBE_FIELDS): `file_state` takes exactly one `path` (/work/marker- plus 24 lowercase hex), `copy_scan`
  takes exactly `sha256` (64 hex), `size` (int, not bool, 1..MAX_COPY_SIZE) and `exclude` (null or such a marker path). None of them
  carries a script, an argv or any other path; `cgroup_events` keeps its three fields and a stray `path` on it is still forbidden_field.
- M3.1 (catalog, SC2-CATALOGO-ADAPTADORES-LOCAL, M3-CONTRATO-AGENTE) adds four closed operations in CATALOG_OP_FIELDS, apart from the M1
  table OP_FIELDS and from LEVEL_OP_FIELDS: `catalog_info` (op only), `open_catalog` (run_id, variant, catalog_profile A|B,
  context_sha256, catalog_id, catalog_sha256), `catalog_check` (handle) and `catalog_receipt` (the nine identities of a catalog cell, no
  handle). The catalog is ONE fixed resource: catalog_id and catalog_sha256 are PINS that must equal CATALOG_ID/CATALOG_SHA256 (mirrors of
  missions.py; a test pins the parity, this module stays pure): a different value is never "another catalog", it is invalid. A request
  carries no path, flag, script, mount or resource id (resource_id is the owner's private reference and has no wire name). Whether the
  owner serves the catalog domain is the broker's trusted `allowed_catalog` policy, never a request field. A catalog lease has a variant,
  a context and a profile, no level; its key is (domain catalog, run_id, variant): A and B of the same corrida/variant collide, exactly as
  the diary's permanent key ('catalog', uid, run, variant) does. It shares the single plaza and the TTL with every other lease.
- M4 rooms (SC2-M4-rooms-v1) extend the closed level vocabulary with `processes` and `privileges` (stage `actor` only, see LEVEL_STAGES)
  and add ONE operation in ROOM_OP_FIELDS, apart from the three older tables: `room_action {op, handle}`, exact keys, no argument of any
  kind (the owner fixes the script, the request carries none). Which rooms an owner serves is still its trusted `allowed_levels` (the
  default stays empty). A room lease owns exactly ONE action permit: ActorLeases.consume_action() spends it atomically, before anything
  is dispatched, and nothing gives it back; only retire() releases the slot, as always.
- M5 network (SC2-M5-network-v1) extends the closed level vocabulary with `network` (stage `actor` only, see LEVEL_STAGES) and adds ONE
  operation in NETWORK_OP_FIELDS, apart from the four older tables: `network_action {op, handle, command}`. The command is the only variable
  input and obeys exactly the rules of `execute` (_command: text, not empty, no NUL, at most MAX_COMMAND_BYTES of UTF-8); the codec
  never interprets it. No destination, probe script, Docker option, network or resource name is a field. open_level and level_receipt
  keep their exact fields (the bundle is the intent: the owner derives `bundle_id`, a request never carries it). Which levels an owner
  serves is still its trusted `allowed_levels` (default empty). A network lease owns up to MAX_NETWORK_STEPS (8) action permits:
  ActorLeases.consume_action() spends the next one atomically BEFORE anything is dispatched; permits are never given back and only
  retire() releases the slot. No new reason is added: a spent ninth permit is `action_consumed`, a lease that owns none `action_unavailable`.
"""
import dataclasses
import json
import math
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from types import MappingProxyType

MISSION = 'invoice-reconcile/v1'
MAX_REQUEST_BYTES = 16 * 1024
MAX_COMMAND_BYTES = 8 * 1024
VARIANTS = ('legitimate', 'perturbed')
PROBE_NAMES = ('task_result', 'artifact_capture', 'measure')
OP_FIELDS = MappingProxyType({
    'health': frozenset({'op'}),
    'open': frozenset({'op', 'run_id', 'variant'}),
    'execute': frozenset({'op', 'handle', 'command'}),
    'probe': frozenset({'op', 'handle', 'name'}),
    'close': frozenset({'op', 'handle'}),
    'receipt': frozenset({'op', 'installation_id', 'run_id', 'variant', 'intent_id', 'container_id'}),
})
LEVELS = ('memory', 'secret', 'persistence', 'processes', 'privileges', 'network')  # closed names the codec recognizes; the allowlist decides
ROOM_LEVELS = ('processes', 'privileges')  # M4: the rooms whose handle owns one fixed action (a subset of LEVELS, actor stage only)
NETWORK_LEVEL = 'network'  # M5: its handle owns up to MAX_NETWORK_STEPS variable commands (actor stage only)
MAX_NETWORK_STEPS = 8
STAGES = ('actor', 'fresh')
LEVEL_STAGES = MappingProxyType({'memory': ('actor',), 'secret': ('actor',), 'persistence': ('actor', 'fresh'),
                                 'processes': ('actor',), 'privileges': ('actor',), 'network': ('actor',)})
ROOM_OP_FIELDS = MappingProxyType({'room_action': frozenset({'op', 'handle'})})  # M4: no script, path, UID, limit or any argument
NETWORK_OP_FIELDS = MappingProxyType({'network_action': frozenset({'op', 'handle', 'command'})})  # M5: the command is the only input
LEVEL_PROBE_NAMES = ('cgroup_events', 'file_state', 'copy_scan')
MAX_COPY_SIZE = 1024 ** 2  # the byte bound of the fixed copy scan (runner.COPY_SCAN_LIMITS['max_bytes']; a test pins the parity)
LEVEL_OP_FIELDS = MappingProxyType({
    'open_level': frozenset({'op', 'run_id', 'level', 'stage', 'context_sha256'}),
    'level_probe': frozenset({'op', 'handle', 'name'}),  # the fields of cgroup_events and the base shape of any probe request
    'level_receipt': frozenset({'op', 'installation_id', 'run_id', 'level', 'stage', 'context_sha256', 'intent_id',
                                'container_id'}),
})
# The exact field set of a level_probe request, by probe name. The name decides it; there is no field to pass a script or a second path.
LEVEL_PROBE_FIELDS = MappingProxyType({
    'cgroup_events': frozenset({'op', 'handle', 'name'}),
    'file_state': frozenset({'op', 'handle', 'name', 'path'}),
    'copy_scan': frozenset({'op', 'handle', 'name', 'sha256', 'size', 'exclude'}),
})

# M3.1 catalog. CATALOG_ID / CATALOG_SHA256 / CATALOG_DESTINATION / CATALOG_SIZE mirror missions.py (CATALOG_ID, CATALOG_SHA256,
# CATALOG_DESTINATION, len(CATALOG_BYTES)); this module imports nothing, and a test of the protocol pins the parity from the source.
CATALOG_PROFILES = ('A', 'B')
CATALOG_ID = 'invoice-unit-cents/v1'
CATALOG_SHA256 = 'd055653221c49c92490e536dc665349746988bb14749c60757e7a770fc20e79e'
CATALOG_DESTINATION = '/catalog.json'
CATALOG_SIZE = 47
CATALOG_OP_FIELDS = MappingProxyType({
    'catalog_info': frozenset({'op'}),
    'open_catalog': frozenset({'op', 'run_id', 'variant', 'catalog_profile', 'context_sha256', 'catalog_id', 'catalog_sha256'}),
    'catalog_check': frozenset({'op', 'handle'}),
    'catalog_receipt': frozenset({'op', 'installation_id', 'run_id', 'variant', 'catalog_profile', 'context_sha256', 'catalog_id',
                                  'catalog_sha256', 'intent_id', 'container_id'}),
})

DECODE_REASONS = frozenset({
    'not_bytes', 'empty', 'too_large', 'not_utf8', 'invalid_json', 'duplicate_key', 'non_finite', 'not_object',
    'unknown_op', 'missing_field', 'unexpected_field', 'forbidden_field',
    'invalid_run_id', 'invalid_variant', 'invalid_handle', 'invalid_name',
    'invalid_command', 'command_empty', 'command_nul', 'command_too_large',
    'invalid_installation_id', 'invalid_intent_id', 'invalid_container_id',
    'invalid_level', 'invalid_stage', 'invalid_context',
    'invalid_path', 'invalid_digest', 'invalid_size', 'invalid_exclude',  # M2.3 probe arguments
    'invalid_catalog_profile', 'invalid_catalog_id', 'invalid_catalog_digest',  # M3.1: A|B and the two pins of the fixed catalog
})
LEASE_REASONS = frozenset({
    'invalid_configuration', 'invalid_owner', 'already_active', 'capacity_exhausted', 'handle_unavailable',
    'unknown_handle', 'foreign_owner', 'expired', 'closing', 'cleanup_not_confirmed',
    'action_consumed', 'action_unavailable',  # M4: the one room action permit is spent / this lease has none
})
REASONS = DECODE_REASONS | LEASE_REASONS

ACTIVE = 'active'
CLOSING = 'closing'

_RUN_ID = re.compile(r'[0-9a-f]{32}')
_HANDLE = re.compile(r'[0-9a-f]{64}')
_HEX32 = re.compile(r'[0-9a-f]{32}')  # installation_id and intent_id
_HEX64 = re.compile(r'[0-9a-f]{64}')  # container_id
_MARKER_PATH = re.compile(r'/work/marker-[0-9a-f]{24}')  # the only path a persistence probe may name
_MAX_UID = 2 ** 32 - 2  # (uid_t)-1 is the "no uid" value and never a peer
_HANDLE_ATTEMPTS = 8

# Names that identify Docker options or host locations. Any of them (or a key containing one of the fragments) is reported as
# forbidden_field; every other unknown key is unexpected_field. Both are rejected: the distinction only helps diagnosis.
_FORBIDDEN_NAMES = frozenset({
    'image', 'images', 'entrypoint', 'user', 'env', 'environment', 'workdir', 'cwd', 'pid', 'ipc', 'tmpfs', 'memory',
    'cpus', 'runtime', 'devices', 'device', 'args', 'options', 'source', 'src', 'dest', 'destination', 'socket',
    'container', 'container_id', 'container_name', 'bind', 'binds',
})
_FORBIDDEN_FRAGMENTS = ('docker', 'mount', 'volume', 'path', 'host', 'privileg', 'cap_', 'security', 'network')


class ProtocolError(Exception):
    """Rejection with a reason from the closed vocabulary REASONS. The message is the reason only: never request content."""

    def __init__(self, reason):
        if reason not in REASONS:
            raise ValueError('reason outside the closed vocabulary')
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class Request:
    """A validated request. Fields that do not belong to the operation are None; handle and command stay out of repr()."""
    op: str
    run_id: str | None = None
    variant: str | None = None
    handle: str | None = field(default=None, repr=False)
    command: str | None = field(default=None, repr=False)
    name: str | None = None
    installation_id: str | None = None  # receipt only
    intent_id: str | None = None        # receipt and level_receipt only
    container_id: str | None = None     # receipt and level_receipt only
    level: str | None = None            # open_level and level_receipt only
    stage: str | None = None            # open_level and level_receipt only
    context_sha256: str | None = None   # open_level and level_receipt only
    path: str | None = None             # level_probe file_state only
    sha256: str | None = field(default=None, repr=False)  # level_probe copy_scan only
    size: int | None = None             # level_probe copy_scan only
    exclude: str | None = None          # level_probe copy_scan only; None is also a valid value there
    catalog_profile: str | None = None  # open_catalog and catalog_receipt only
    catalog_id: str | None = None       # open_catalog and catalog_receipt only (the fixed pin)
    catalog_sha256: str | None = None   # open_catalog and catalog_receipt only (the fixed pin)


@dataclass(frozen=True, slots=True)
class Lease:
    """Immutable snapshot of one lease; the handle stays out of repr().

    A workflow lease has a variant and no level; a level lease has level, stage and context and variant None; a catalog lease (M3.1)
    has a variant, a context and a catalog_profile and no level. `domain` names which of the three it is.
    """
    handle: str = field(repr=False)
    owner_uid: int
    run_id: str
    variant: str | None
    expires_at: float
    state: str
    level: str | None = None
    stage: str | None = None
    context_sha256: str | None = None
    catalog_profile: str | None = None
    action_spent: bool = False  # M4 rooms: the single action permit; never reset, and a lease that is not a room never has one
    action_steps: int = 0       # M5 network: action permits spent so far (0..MAX_NETWORK_STEPS); never decreases

    @property
    def domain(self):
        return 'catalog' if self.catalog_profile is not None else 'level' if self.level is not None else 'workflow'

    @property
    def room(self):
        return self.level in ROOM_LEVELS

    @property
    def network(self):
        return self.level == NETWORK_LEVEL


class _Reject(Exception):
    # Deliberately not a ValueError: json would otherwise let it pass as a plain syntax error.
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def _pairs(items):
    seen = {}
    for key, value in items:
        if key in seen:
            raise _Reject('duplicate_key')
        seen[key] = value
    return seen


def _constant(_name):
    raise _Reject('non_finite')


def _float(text):
    value = float(text)
    if not math.isfinite(value):
        raise _Reject('non_finite')
    return value


def _run_id(value):
    if not isinstance(value, str) or not _RUN_ID.fullmatch(value):
        raise ProtocolError('invalid_run_id')
    return value


def _variant(value):
    if not isinstance(value, str) or value not in VARIANTS:
        raise ProtocolError('invalid_variant')
    return value


def _handle(value):
    if not isinstance(value, str) or not _HANDLE.fullmatch(value):
        raise ProtocolError('invalid_handle')
    return value


def _installation_id(value):
    if not isinstance(value, str) or not _HEX32.fullmatch(value):
        raise ProtocolError('invalid_installation_id')
    return value


def _intent_id(value):
    if not isinstance(value, str) or not _HEX32.fullmatch(value):
        raise ProtocolError('invalid_intent_id')
    return value


def _container_id(value):
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ProtocolError('invalid_container_id')
    return value


def _probe_name(value):
    if not isinstance(value, str) or value not in PROBE_NAMES:
        raise ProtocolError('invalid_name')
    return value


def _catalog_profile(value):
    if not isinstance(value, str) or value not in CATALOG_PROFILES:
        raise ProtocolError('invalid_catalog_profile')
    return value


def _catalog_id(value):
    if not isinstance(value, str) or value != CATALOG_ID:  # a pin of the only authorized catalog, not a selector
        raise ProtocolError('invalid_catalog_id')
    return value


def _catalog_digest(value):
    if not isinstance(value, str) or value != CATALOG_SHA256:
        raise ProtocolError('invalid_catalog_digest')
    return value


def _level(value):
    if not isinstance(value, str) or value not in LEVELS:
        raise ProtocolError('invalid_level')
    return value


def level_stage_valid(level, stage):
    """True only for a pair of LEVEL_STAGES: `fresh` exists for persistence alone, and every other pair is refused."""
    return isinstance(level, str) and isinstance(stage, str) and stage in LEVEL_STAGES.get(level, ())


def _stage(value, level=None):
    if not isinstance(value, str) or value not in STAGES:
        raise ProtocolError('invalid_stage')
    if level is not None and value not in LEVEL_STAGES[level]:  # `level` was validated by the caller: memory/fresh is not a stage
        raise ProtocolError('invalid_stage')
    return value


def _context(value):
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ProtocolError('invalid_context')
    return value


def _level_probe_name(value):
    if not isinstance(value, str) or value not in LEVEL_PROBE_NAMES:
        raise ProtocolError('invalid_name')
    return value


def _marker_path(value, reason='invalid_path'):
    if not isinstance(value, str) or not _MARKER_PATH.fullmatch(value):
        raise ProtocolError(reason)
    return value


def _digest(value):
    if not isinstance(value, str) or not _HEX64.fullmatch(value):
        raise ProtocolError('invalid_digest')
    return value


def _copy_size(value):
    if type(value) is not int or not 1 <= value <= MAX_COPY_SIZE:  # bool is not an int here
        raise ProtocolError('invalid_size')
    return value


def _exclude(value):
    return None if value is None else _marker_path(value, 'invalid_exclude')


def _command(value):
    if not isinstance(value, str):
        raise ProtocolError('invalid_command')
    if not value:
        raise ProtocolError('command_empty')
    if '\x00' in value:
        raise ProtocolError('command_nul')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeEncodeError:  # a lone surrogate escape (\ud800) is valid JSON but not valid UTF-8 text
        raise ProtocolError('invalid_command') from None
    if size > MAX_COMMAND_BYTES:
        raise ProtocolError('command_too_large')
    return value


def _owner(value):
    if type(value) is not int or not 1 <= value <= _MAX_UID:
        raise ProtocolError('invalid_owner')
    return value


def _forbidden(key):
    normal = key.lower().replace('-', '_')
    return normal in _FORBIDDEN_NAMES or any(fragment in normal for fragment in _FORBIDDEN_FRAGMENTS)


def decode_request(raw):
    """Strict decoder: bytes in, Request out, or ProtocolError with a closed reason.

    Order: type, size (raw bytes, before decoding), UTF-8, JSON (no duplicate keys at any depth, no NaN/Infinity/overflowing
    floats), object, op, exact field set (no extra, no missing; Docker options and host locations are forbidden_field), then
    the value of each field. Values are never normalized: no strip, no case folding, no path handling.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise ProtocolError('not_bytes')
    if len(raw) == 0:
        raise ProtocolError('empty')
    if len(raw) > MAX_REQUEST_BYTES:
        raise ProtocolError('too_large')
    data = bytes(raw)  # one snapshot: a caller-owned bytearray cannot change underneath the checks
    if len(data) > MAX_REQUEST_BYTES:
        raise ProtocolError('too_large')
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        raise ProtocolError('not_utf8') from None
    try:
        value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_constant, parse_float=_float)
    except _Reject as exc:
        raise ProtocolError(exc.reason) from None
    except (ValueError, RecursionError):
        raise ProtocolError('invalid_json') from None
    if not isinstance(value, dict):
        raise ProtocolError('not_object')
    if 'op' not in value:
        raise ProtocolError('missing_field')
    op = value['op']
    if not isinstance(op, str) or (op not in OP_FIELDS and op not in LEVEL_OP_FIELDS and op not in CATALOG_OP_FIELDS
                                   and op not in ROOM_OP_FIELDS and op not in NETWORK_OP_FIELDS):
        raise ProtocolError('unknown_op')
    if op in OP_FIELDS:
        expected = OP_FIELDS[op]
    elif op in ROOM_OP_FIELDS:
        expected = ROOM_OP_FIELDS[op]
    elif op in NETWORK_OP_FIELDS:
        expected = NETWORK_OP_FIELDS[op]
    elif op == 'level_probe':  # the probe name decides the exact field set; an unknown name is judged after the shape
        probe = value.get('name')
        expected = LEVEL_PROBE_FIELDS[probe] if isinstance(probe, str) and probe in LEVEL_PROBE_FIELDS else LEVEL_OP_FIELDS[op]
    elif op in LEVEL_OP_FIELDS:
        expected = LEVEL_OP_FIELDS[op]
    else:
        expected = CATALOG_OP_FIELDS[op]
    extra = [key for key in value if key not in expected]
    if extra:
        raise ProtocolError('forbidden_field' if any(_forbidden(key) for key in extra) else 'unexpected_field')
    if len(value) != len(expected):  # no extras, so a shorter object lacks a field
        raise ProtocolError('missing_field')
    if op == 'health':
        return Request(op)
    if op == 'open':
        run_id = _run_id(value['run_id'])
        return Request(op, run_id=run_id, variant=_variant(value['variant']))
    if op == 'receipt':  # no handle: the five identities are the whole request, validated in a fixed order
        installation_id = _installation_id(value['installation_id'])
        run_id = _run_id(value['run_id'])
        variant = _variant(value['variant'])
        intent_id = _intent_id(value['intent_id'])
        return Request(op, run_id=run_id, variant=variant, installation_id=installation_id, intent_id=intent_id,
                       container_id=_container_id(value['container_id']))
    if op == 'open_level':  # fixed order: run, level, stage, context
        run_id = _run_id(value['run_id'])
        level = _level(value['level'])
        stage = _stage(value['stage'], level)
        return Request(op, run_id=run_id, level=level, stage=stage, context_sha256=_context(value['context_sha256']))
    if op == 'level_receipt':  # no handle: the seven identities of a level are the whole request; never a predecessor
        installation_id = _installation_id(value['installation_id'])
        run_id = _run_id(value['run_id'])
        level = _level(value['level'])
        stage = _stage(value['stage'], level)
        context = _context(value['context_sha256'])
        intent_id = _intent_id(value['intent_id'])
        return Request(op, run_id=run_id, installation_id=installation_id, intent_id=intent_id, level=level, stage=stage,
                       context_sha256=context, container_id=_container_id(value['container_id']))
    if op == 'catalog_info':  # no field at all: it reads the owner's public view and asks for nothing
        return Request(op)
    if op == 'open_catalog':  # fixed order: run, variant, profile, context, then the two pins of the fixed catalog
        run_id = _run_id(value['run_id'])
        variant = _variant(value['variant'])
        profile = _catalog_profile(value['catalog_profile'])
        context = _context(value['context_sha256'])
        catalog_id = _catalog_id(value['catalog_id'])
        return Request(op, run_id=run_id, variant=variant, catalog_profile=profile, context_sha256=context, catalog_id=catalog_id,
                       catalog_sha256=_catalog_digest(value['catalog_sha256']))
    if op == 'catalog_receipt':  # no handle: the nine identities of a catalog cell are the whole request
        installation_id = _installation_id(value['installation_id'])
        run_id = _run_id(value['run_id'])
        variant = _variant(value['variant'])
        profile = _catalog_profile(value['catalog_profile'])
        context = _context(value['context_sha256'])
        catalog_id = _catalog_id(value['catalog_id'])
        digest = _catalog_digest(value['catalog_sha256'])
        intent_id = _intent_id(value['intent_id'])
        return Request(op, run_id=run_id, variant=variant, installation_id=installation_id, intent_id=intent_id,
                       container_id=_container_id(value['container_id']), context_sha256=context, catalog_profile=profile,
                       catalog_id=catalog_id, catalog_sha256=digest)
    handle = _handle(value['handle'])  # execute, probe, close, level_probe and catalog_check
    if op == 'level_probe':  # fixed order: handle, name, then the arguments of that name
        name = _level_probe_name(value['name'])
        if name == 'file_state':
            return Request(op, handle=handle, name=name, path=_marker_path(value['path']))
        if name == 'copy_scan':
            digest = _digest(value['sha256'])
            size = _copy_size(value['size'])
            return Request(op, handle=handle, name=name, sha256=digest, size=size, exclude=_exclude(value['exclude']))
        return Request(op, handle=handle, name=name)
    if op in ('execute', 'network_action'):  # the same command rules: network_action is execute inside a network actor, nothing more
        return Request(op, handle=handle, command=_command(value['command']))
    if op == 'probe':
        return Request(op, handle=handle, name=_probe_name(value['name']))
    return Request(op, handle=handle)  # close and room_action: the handle is the whole request


def _random_handle():
    return secrets.token_hex(32)


class ActorLeases:
    """In-memory registry of actor sessions. Every instance owns its state; there is no module-level registry.

    max_sessions and ttl_seconds are required and explicit. The deadline is absolute (opened at + ttl): using a handle never
    extends it. `clock` (monotonic seconds) and `token_source` (a callable returning 64 lowercase hex) exist for tests; the
    default token source is secrets. Methods are serialized by a lock.
    """

    def __init__(self, *, max_sessions, ttl_seconds, clock=time.monotonic, token_source=None):
        if type(max_sessions) is not int or max_sessions < 1:
            raise ProtocolError('invalid_configuration')
        if type(ttl_seconds) not in (int, float):
            raise ProtocolError('invalid_configuration')
        try:
            finite = math.isfinite(ttl_seconds)
        except OverflowError:
            finite = False
        if not finite or ttl_seconds <= 0:
            raise ProtocolError('invalid_configuration')
        if not callable(clock) or (token_source is not None and not callable(token_source)):
            raise ProtocolError('invalid_configuration')
        self._max = max_sessions
        self._ttl = ttl_seconds
        self._clock = clock
        self._token = token_source if token_source is not None else _random_handle
        self._lock = threading.Lock()
        self._leases = {}

    def __repr__(self):
        return 'ActorLeases(max_sessions=%d, held=%d)' % (self._max, len(self._leases))

    @property
    def max_sessions(self):
        return self._max

    def held(self):
        """Leases still in the registry: active, closing and expired ones alike (only retire() releases a slot)."""
        with self._lock:
            return len(self._leases)

    def _new_handle(self):
        for _ in range(_HANDLE_ATTEMPTS):
            candidate = self._token()
            if isinstance(candidate, str) and _HANDLE.fullmatch(candidate) and candidate not in self._leases:
                return candidate
        raise ProtocolError('handle_unavailable')

    def _owned(self, handle, owner_uid):
        owner, key = _owner(owner_uid), _handle(handle)
        lease = self._leases.get(key)
        if lease is None:
            raise ProtocolError('unknown_handle')
        if lease.owner_uid != owner:
            raise ProtocolError('foreign_owner')
        return lease

    def open(self, owner_uid, run_id, variant):
        """New handle for (owner_uid, run_id, variant). A run_id+variant that already holds a lease is refused for ANY owner
        (stricter than same-identity): one corrida/variant has at most one lease until cleanup is confirmed."""
        owner, run, name = _owner(owner_uid), _run_id(run_id), _variant(variant)
        with self._lock:
            # Workflow domain only: a catalog lease of the same run/variant has its own key and its own diary entry (M3.1).
            if any(item.run_id == run and item.variant == name and item.catalog_profile is None for item in self._leases.values()):
                raise ProtocolError('already_active')
            if len(self._leases) >= self._max:
                raise ProtocolError('capacity_exhausted')
            handle = self._new_handle()
            self._leases[handle] = Lease(handle, owner, run, name, self._clock() + self._ttl, ACTIVE)
            return handle

    def open_catalog(self, owner_uid, run_id, variant, catalog_profile, context_sha256, catalog_id, catalog_sha256):
        """New handle for a catalog cell (owner_uid, run_id, variant) bound to its profile and context (M3.1). The plaza and the TTL are
        the registry's, shared with workflow and level leases. A run_id+variant that already holds a CATALOG lease is refused for ANY
        owner, whatever its profile or context (the diary key has no profile): A and B of one corrida/variant never coexist and a spent
        key is not reopened. The two pins must be those of the one fixed catalog. It never collides with a workflow or level lease."""
        owner, run, name = _owner(owner_uid), _run_id(run_id), _variant(variant)
        profile, context = _catalog_profile(catalog_profile), _context(context_sha256)
        _catalog_id(catalog_id)
        _catalog_digest(catalog_sha256)
        with self._lock:
            if any(item.catalog_profile is not None and item.run_id == run and item.variant == name for item in self._leases.values()):
                raise ProtocolError('already_active')
            if len(self._leases) >= self._max:
                raise ProtocolError('capacity_exhausted')
            handle = self._new_handle()
            self._leases[handle] = Lease(handle, owner, run, name, self._clock() + self._ttl, ACTIVE, None, None, context, profile)
            return handle

    def open_level(self, owner_uid, run_id, level, stage, context_sha256):
        """New handle for a level session (owner_uid, run_id, level, stage), bound to its context. The plaza and the TTL are those
        of the registry, shared with the workflow leases. A run_id+level+stage that already holds a lease is refused for ANY owner;
        a level never collides with a workflow variant because their keys are different."""
        owner, run, name = _owner(owner_uid), _run_id(run_id), _level(level)
        phase, context = _stage(stage, name), _context(context_sha256)  # fresh exists for persistence alone
        with self._lock:
            if any(item.run_id == run and item.level == name and item.stage == phase for item in self._leases.values()):
                raise ProtocolError('already_active')
            if len(self._leases) >= self._max:
                raise ProtocolError('capacity_exhausted')
            handle = self._new_handle()
            self._leases[handle] = Lease(handle, owner, run, None, self._clock() + self._ttl, ACTIVE, name, phase, context)
            return handle

    def authorize(self, handle, owner_uid):
        """Lease for execute/probe: the handle must be known, owned by this uid, active and not past its deadline."""
        with self._lock:
            lease = self._owned(handle, owner_uid)
            if lease.state != ACTIVE:
                raise ProtocolError('closing')
            if self._clock() >= lease.expires_at:
                raise ProtocolError('expired')
            return lease

    def consume_action(self, handle, owner_uid):
        """Spend the single action permit of a ROOM lease, atomically, and return the lease as it was. Owner-side, called before dispatch.

        The handle must be known, owned by this uid, active and inside its deadline (the reasons of authorize()). A lease that is not a
        room has no permit (action_unavailable); a spent one never gives it back (action_consumed), so a second or concurrent dispatch,
        or a retry after a lost answer, can never reach the runtime. Only retire() ends the lease.

        M5: a NETWORK lease owns MAX_NETWORK_STEPS permits instead of one. Each call spends the next (`action_steps` + 1, which the owner
        uses as the step it expects) and returns the lease as it was before; the ninth is action_consumed. Same atomicity, same order."""
        with self._lock:
            lease = self._owned(handle, owner_uid)
            if lease.state != ACTIVE:
                raise ProtocolError('closing')
            if self._clock() >= lease.expires_at:
                raise ProtocolError('expired')
            if lease.network:
                if lease.action_steps >= MAX_NETWORK_STEPS:
                    raise ProtocolError('action_consumed')
                self._leases[lease.handle] = dataclasses.replace(lease, action_steps=lease.action_steps + 1)
                return lease
            if not lease.room:
                raise ProtocolError('action_unavailable')
            if lease.action_spent:
                raise ProtocolError('action_consumed')
            self._leases[lease.handle] = dataclasses.replace(lease, action_spent=True)
            return lease

    def begin_close(self, handle, owner_uid):
        """Mark the lease closing (idempotent; allowed after expiry). The slot stays held until retire()."""
        with self._lock:
            lease = self._owned(handle, owner_uid)
            if lease.state != CLOSING:
                lease = dataclasses.replace(lease, state=CLOSING)
                self._leases[lease.handle] = lease
            return lease

    def retire(self, handle, *, cleanup_confirmed):
        """Owner-only. Releases the slot, and only when cleanup_confirmed is exactly True; anything else keeps the lease."""
        key = _handle(handle)
        with self._lock:
            if key not in self._leases:
                raise ProtocolError('unknown_handle')
            if cleanup_confirmed is not True:
                raise ProtocolError('cleanup_not_confirmed')
            del self._leases[key]

    def pending_cleanup(self):
        """Owner-only. Snapshots of leases that need cleanup: closing ones and active ones past their deadline."""
        with self._lock:
            now = self._clock()
            return tuple(item for item in self._leases.values() if item.state == CLOSING or now >= item.expires_at)
