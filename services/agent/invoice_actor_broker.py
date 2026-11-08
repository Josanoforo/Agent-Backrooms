"""Owner side of the invoice actor boundary, milestone M1 (SC2-CONTROLADOR-CONTRATO section 14, SC2-ACTOR-INVENTARIO-CONTRATO).

What this module is: the decision logic of the actor owner. `runtime` and `inventory` are INJECTED. This module imports neither
Docker, subprocess nor the durable diary; Sol connects the Docker runtime and the diary. Nothing here runs a host command.

Contract the injected parts must meet (anything else is treated as a failure, never as success):
- inventory: pending, begin, ack, starting, activate, closing, finish as in SC2-ACTOR-INVENTARIO-CONTRATO, each mutation returning
  an immutable intent (intent_id, name, controller_uid, run_id, variant, container_id, phase, profile_sha256). Failures are
  exceptions carrying a closed string in `.code` (StateError does). `installation_id` is an attribute. Calls are synchronous.
- runtime: async ready, installed_ids, create, inspect_created, start, inspect_running, execute, probe, close. Extra shapes the
  owner consumes (the interface document leaves them open):
    inspect_created -> {'compatible': bool, 'violations': [names]}
    inspect_running -> {'running': bool, 'container_id': 64hex, 'profile': dict, 'profile_sha256': 64hex, 'violations': [names]}
    execute -> {'stdout','stderr','exit_code', memory fields}; probe -> same for task_result/artifact_capture, memory fields only
    for measure; close -> {'cleanup_confirmed': True, 'oom_killed': bool|None, memory fields}.
  A runtime exception may carry `.reason` among docker_unavailable, sandbox_stopped, not_running, exec_timeout.

Ordering guaranteed on open: PENDING is durable before create; ACK before inspect or start; START_PENDING before start; ACTIVE
before the handle is returned. create and start are issued at most once; an ambiguous create blocks the owner (PENDING without an
ID is never cleared by an empty inventory or by time). Restitution only closes an ID the diary recognizes; FINISH is written only
after the runtime confirmed the close AND installed_ids no longer lists the ID. Foreign objects are never touched.

Serialization: one operation per handle at a time (a second one gets `busy`). close first marks the lease closing (new operations
get `closing`), then waits for the operation in flight, which ends or fails within its own limit. An operation whose outcome is
uncertain (timeout, runtime failure, invalid output) invalidates the lease and leads to restitution; it is never replayed.
A cancelled or disconnected client changes nothing: the owner keeps the obligation until the runtime confirms absence. TTL is
absolute from open (120 s in M1). health is read-only and separate from close.

Durable receipt query (`receipt`, maintainer decision after A3): the peer UID read from the socket is the only controller UID the
diary is asked about; the installation in the request must be this owner's. The answer comes from `inventory.receipt(
controller_uid=, run_id=, variant=, intent_id=, container_id=)`, which returns the exact FINISH intent or None and raises with a
closed `.code` otherwise. `confirmed` needs that FINISH and the owner re-checks every field of it; a valid identity without it is
`unknown`. The query is synchronous, read-only and serves any state (no lease, not recovered, blocked, shutting down): it never
touches the runtime, the lease registry, the tombstones or the diary's mutations, and it changes no owner state, so it can be
repeated. An inventory without `receipt` answers internal_error: it can never confirm. Health, leases and an empty installed_ids
are never a receipt.

M2.1 levels (M2-CONTRATO-AGENTE, SC2-M2-ADAPTADORES-LOCAL). `allowed_levels` is an immutable set chosen by the trusted owner
configuration, EMPTY by default so M1 consumers and doubles keep working untouched; the client can neither send nor change it.
Only when it is not empty does the broker require `inventory.begin_level` and `runtime.probe_level` (`receipt_level` is optional,
like `receipt`: without it a level receipt answers internal_error and never confirms).
- open_level: a level outside the allowlist (or a stage other than `actor`) is refused as level_not_allowed BEFORE anything else:
  no lease, no diary entry, no create. Otherwise the same ordered sequence as `open`, with `inventory.begin_level(controller_uid,
  run_id, level, stage, context_sha256)`; the intent has level, stage and context, never a variant. Replays of (UID, run, level,
  stage) are refused by the diary even after FINISH (already_active); a different context for another level of the same run is
  context_mismatch and blocks nothing. The plaza and the TTL are the single ones of M1: one session, workflow or level, at a time.
- Handles carry their domain. A level handle answers execute, probe(measure), level_probe and close; probe(task_result) and
  probe(artifact_capture) are wrong_domain there, and level_probe is wrong_domain on an M1 handle (or a non-memory level). Those
  refusals call nothing and leave the lease intact. Only `cgroup_events` exists: the owner fixes it, the request carries no
  script, path or argument, and the runtime is called as `probe_level(intent, 'cgroup_events')` with nothing else. A malformed
  answer (bool or negative counter, no oom_kill, extra keys) is an uncertain outcome: the lease ends and the ID is restituted.
- close of a level handle answers with the level identity (validated by actor_wire.validate_level_close); M1 handles keep theirs.
- level_receipt is the durable query of M1 `receipt` over `inventory.receipt_level`: synchronous, read-only, any owner state, no
  runtime. It is not gated by the allowlist (an owner whose policy shrank can still prove an old restitution); `confirmed` needs the
  exact FINISH of the full identity, context included. Recovery restitutes any recognized ID regardless of the allowlist and never
  issues create, start or execute.

M2.3 persistence (SC2-PERSISTENCIA-ADAPTADORES-LOCAL). The owner serves persistence/actor and persistence/fresh only when `persistence`
is in `allowed_levels`; the default stays empty and the bootstrap decides. Nothing else of the plaza, the phases or the TTL changes:
one session at a time, A restituted before B can even be begun.
- The predecessor of a fresh phase belongs to the DIARY. `inventory.begin_level` derives it inside its own transaction from the FINISH
  of the actor phase of the same UID, run and context, and returns it on the intent (`LevelIntent.predecessor`, a dataclass with the
  seven identity fields); the owner turns it into the wire object with dataclasses.asdict and never from a request, which has no such
  field. A fresh intent without a faithful predecessor (absent, not a dataclass, not persistence/actor, another run, context or
  installation, or sharing an ID with the fresh phase) is a diary that answered something else: the intent is tracked, the owner blocks
  and nothing is created. A fake diary that lacks the predecessor can therefore never produce a confirmation.
- StateError `predecessor_unconfirmed` (fresh asked before the FINISH of A) is a clean refusal like `invalid_transition`: a closed
  `predecessor_unconfirmed` reason, nothing journaled, no create, no block, and the plaza is released. `already_started` (replay of A or
  of B, even after FINISH) and `actor_busy` keep their mapping.
- A fresh open answer carries `predecessor`; the close answer of a fresh handle carries the predecessor of its durable FINISH; the
  `level_receipt` of a fresh phase is `confirmed` only with the predecessor of that exact FINISH and answers predecessor null when
  `unknown`. If the diary returns a FINISH of the right identity but no usable predecessor, the answer is a refusal (internal_error for
  the query, cleanup_unconfirmed for a close), never a confirmation.
- Fixed probes by name: file_state and copy_scan are served only on a persistence handle (actor or fresh); cgroup_events only on memory.
  The runtime is called as `probe_level(intent, name, **typed_args)` with exactly {path} or {sha256, size, exclude}, taken from the
  decoded request, never a script. On a fresh handle `exclude` must be null (the original path counts in a fresh sandbox): anything else
  is refused as invalid_exclude before the runtime. A malformed answer is an uncertain outcome like any other: the lease ends and the ID
  is restituted; `unavailable` and `missing` are legitimate answers that keep the session.

M3.1 catalog (M3-CONTRATO-AGENTE, SC2-CATALOGO-ADAPTADORES-LOCAL). `allowed_catalog` is a bool chosen by the trusted owner configuration
(constructor only; exactly a bool, FALSE by default, read-only): the client can neither send nor change it and `catalog_info` does not
carry it. Only when it is True does the broker require `inventory.begin_catalog` and, of the runtime, a SYNCHRONOUS `catalog_status()`
and an async `catalog_check(intent)` (`receipt_catalog` stays optional, like `receipt_level`). Disabled owners keep serving M1/M2 with
doubles that have no catalog method at all.
- catalog_info / open_catalog / catalog_check are refused as `catalog_not_allowed` BEFORE anything else when the policy is False: no
  lease, no diary entry, no create. catalog_info is a synchronous read of `runtime.catalog_status()`: it prepares, repairs, mounts and
  retires nothing and answers the fixed public identity {id, sha256, size, destination} rebuilt from constants (a runtime view that is
  not exactly {ready: bool, identity: that | None}, or that says ready without an identity, is internal_error, never forwarded).
- open_catalog follows the ordered sequence of `open` with `inventory.begin_catalog(controller_uid, run_id, variant, catalog_profile,
  context_sha256, catalog_id, catalog_sha256)`; the UID is the authenticated peer's, the catalog pins are the owner's constants. A
  resource that is not ready is refused as `catalog_unavailable` BEFORE the diary is touched, and the diary's own StateError
  catalog_unavailable/catalog_resource_exists is the same clean refusal (no obligation was born; the owner is not blocked). A replay of
  (UID, run, variant) is already_active even after FINISH, whatever the profile; another context for the same run/variant is
  context_mismatch; one plaza and one TTL are shared with workflow and level. An unknown exception blocks, as everywhere else.
- A catalog handle answers execute, probe(task_result), probe(measure), catalog_check and close. probe(artifact_capture), level_probe and
  every other operation are wrong_domain there; catalog_check is wrong_domain on any other handle. Those refusals call nothing and leave
  the lease intact. catalog_check calls `runtime.catalog_check(intent)` and nothing else (no path, script or index from the request); the
  answer must be exactly {probe, host_check, check_index} with a check_index that grows strictly per handle: anything else is an
  uncertain outcome (the lease ends, the ID is restituted) and nothing is replayed. The runtime's own `resource_id` never reaches a
  response: every catalog body is built field by field from the nine identity fields, never from asdict(intent).
- close of a catalog handle answers with the nine identity fields (actor_wire.validate_catalog_close). catalog_receipt is the durable
  query over `inventory.receipt_catalog`: synchronous, read-only, any owner state, no runtime, NOT gated by the policy (an owner whose
  policy shrank can still prove an old restitution); `confirmed` needs the exact FINISH of a catalog intent with all nine fields. A
  workflow or level intent returned by a diary can never confirm a catalog receipt, and (M3.1) a catalog intent can never confirm an M1
  receipt. Recovery restitutes any recognized catalog intent regardless of the policy and never issues create, start, execute or check.

M4 rooms (SC2-M4-rooms-v1, M4-ADAPTADORES-LOCAL). `processes` and `privileges` are level names served only when the trusted
`allowed_levels` lists them (the default stays empty); the stage is `actor`. Only then does the broker also require an ASYNC
`runtime.room_action(intent)`. Everything of open_level (same begin_level, UID, plaza, TTL, replay, handle, FINISH) is unchanged.
- A room handle answers `room_action`, probe(measure) and close. execute, level_probe, probe(task_result|artifact_capture) and catalog_check
  are wrong_domain on it, and room_action is wrong_domain on every other handle (workflow, memory/secret/persistence, catalog): those
  refusals call nothing and leave the lease intact.
- room_action spends the lease's single action permit (ActorLeases.consume_action) BEFORE the runtime is called, while holding the handle's
  op_lock (a concurrent request is `busy`, a later one `action_consumed`): a second dispatch, a concurrent one or a retry after a lost
  answer can never run the action again. The runtime is called as `room_action(intent)` and nothing else; the request carries no argument.
  Its nine-key answer is validated whole by actor_wire.validate_room_action (bound to the seven identity fields of the lease and to the
  profile's pids limit) BEFORE anything is published; no outcome, attribution or verdict is made here. A timeout, runtime failure, shape
  violation or oversized answer is an uncertain outcome: the lease ends and the ID is restituted, never replayed.
- close of a room restitutes through runtime.close and confirms ONLY when the runtime says so: Processes needs `cleanup_confirmed` true AND
  `cgroup_absent` true, Privileges `cgroup_absent` null. That is judged before installed_ids and before FINISH, so a Processes FINISH never
  exists without the node proven absent, and an unconfirmed close keeps the diary at CLOSE_PENDING. The close answer and the level_receipt
  of a room carry `cgroup_absent` (true only for a confirmed Processes receipt, null otherwise); the receipt comes from the durable FINISH
  of the exact identity, with no runtime. Recovery restitutes a room by its recognized ID and never issues room_action.

M5 network (SC2-M5-network-v1, M5-ADAPTADORES-LOCAL). `network` is a level name served only when the trusted `allowed_levels` lists it
(the default stays empty); the stage is `actor`. Only then does the broker also require an ASYNC `runtime.network_action(intent, command)`.
open_level (same begin_level, UID, plaza, TTL, replay, handle, FINISH) is unchanged apart from two keys of its answer, `bundle_id` (the
intent) and `endpoint` (re-checked here from runtime.inspect_running: http://<private IPv4>:8080/). The runtime prepares the three auxiliary
resources and registers NETWORK_ACTOR_PENDING INSIDE create(); this module never sees an auxiliary ID.
- A network handle answers `network_action`, probe(measure) and close. execute, level_probe, room_action, the other probes and catalog_check
  are wrong_domain (or the catalog policy refusal) on it, and network_action is wrong_domain on every other handle: those refusals call
  nothing and leave the lease intact.
- network_action spends the next of the lease's eight permits (ActorLeases.consume_action) BEFORE the runtime is called, while holding the
  handle's op_lock (a concurrent request is `busy`, the ninth `action_consumed`): a retry after a lost answer can never run the command again.
  The runtime is called as `network_action(intent, command)` and nothing else. Its twelve-key answer is judged whole by
  actor_wire.validate_network_action, bound to the seven identity fields, to `bundle_id == intent_id` (the pin, checked BEFORE the lease
  identity is mixed in) and to the step this owner expects, before anything is published; no outcome, attribution or verdict is made here.
  A timeout, runtime failure or shape violation ends the lease and restitutes the ID: nothing is replayed.
- close of a network handle restitutes through runtime.close and writes FINISH ONLY when the runtime confirms in aggregate, names the exact
  bundle and reports the four roles actor/network/canary/verifier as `absent`, and the actor inventory is empty. Otherwise the diary stays at
  CLOSE_PENDING. The close answer and the level_receipt carry `bundle_id` and `cleanup_roles`. level_receipt stays a diary read without
  runtime and is not gated by the policy: `confirmed` needs the exact FINISH (bundle == intent, actor absent, the three resources ABSENT); a
  matching pending intent reports its DURABLE partial states per role with status unknown, anything else all `unknown`.
- Preparation without an actor ACK: the auxiliaries exist before create() returns the actor ID, so after a failed create the intent held by
  the session can be stale. For a network intent this owner re-reads inventory.pending() and compares intent/UID/run/level/stage/context
  before touching anything. A CREATE_PENDING intent without an ID goes through inventory.closing and runtime.close, which retires only the
  ACKed auxiliaries and keeps a PENDING role without an ID pending. If the actor was never requested and the four roles are observed absent,
  inventory.finish(container_id=None) is a durable pre-actor abort (not a wire identity): the plaza is released and open answers its error
  with cleanup_confirmed true, with no tombstone and no close answer. If the actor was requested and its ACK is missing, or any role is
  pending/unknown, there is no FINISH and no handle: the owner blocks with create_uncertain and the debt stays. An ID is never adopted from a
  listing or a prefix. Recovery follows the same rules and never issues create, start, exec, probe or network_action.
"""
import asyncio
import collections
import contextlib
import inspect
import math
import os
import re
import socket
import time
from dataclasses import asdict, dataclass, fields, is_dataclass

from . import actor_wire as wire
from . import invoice_actor_protocol as proto

TTL_SECONDS = 120.0
MAX_CONNECTIONS = 4
TOMBSTONE_LIMIT = 256
TOMBSTONE_SECONDS = 600.0
REAP_INTERVAL_SECONDS = 5.0

_HEX32 = re.compile(r'[0-9a-f]{32}')
_HEX64 = re.compile(r'[0-9a-f]{64}')
_IMAGE_ID = re.compile(r'sha256:[0-9a-f]{64}')
_BLOCK = re.compile(r'[a-z][a-z0-9_]{0,39}')
_MAX_UID = 2 ** 32 - 2
_STATE_MAP = {'actor_busy': 'capacity_exhausted', 'already_started': 'already_active'}
_PASS_REASONS = frozenset({'docker_unavailable', 'sandbox_stopped', 'not_running', 'exec_timeout'})
_RUNTIME_METHODS = ('ready', 'installed_ids', 'create', 'inspect_created', 'start', 'inspect_running', 'execute', 'probe', 'close')
_INVENTORY_METHODS = ('pending', 'begin', 'ack', 'starting', 'activate', 'closing', 'finish')
_LEVEL_INVENTORY_METHODS = ('begin_level',)  # required only when allowed_levels is not empty; receipt_level stays optional
_LEVEL_RUNTIME_METHODS = ('probe_level',)    # required only when allowed_levels is not empty
_CATALOG_INVENTORY_METHODS = ('begin_catalog',)  # required only when allowed_catalog is True; receipt_catalog stays optional
_CATALOG_RUNTIME_METHODS = ('catalog_status', 'catalog_check')  # required only when allowed_catalog is True
_ROOM_RUNTIME_METHODS = ('room_action',)  # M4: required (async) only when allowed_levels names a room
_NETWORK_RUNTIME_METHODS = ('network_action',)  # M5: required (async) only when allowed_levels names `network`


@dataclass(frozen=True)
class Limits:
    """Upper bound, in seconds, of each runtime call. They bound the owner; they do not repeat anything."""
    ready: float = 5.0
    ids: float = 5.0
    create: float = 15.0
    inspect: float = 10.0
    start: float = 15.0
    execute: float = 20.0
    probe: float = 20.0
    close: float = 30.0
    room_action: float = 30.0  # M4: own profile checks + one fixed action (<= 10 s) + samples + recheck; the client waits 60 s
    network_action: float = 95.0  # M5: the load keeps its own 90 s plazo (controls + counters + command + probes); the client waits 105 s

    def __post_init__(self):
        for item in fields(self):
            value = getattr(self, item.name)
            if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
                raise ValueError('invalid limit ' + item.name)


class _Fail(Exception):
    def __init__(self, reason, **extras):
        super().__init__(reason)
        self.reason = reason
        self.extras = extras


class _Unconfirmed(Exception):
    """Absence of the recognized container was not established.

    `uncertain` (M5, pre-actor only) says that retrying cannot settle it: the actor was requested without an ACK, or a role is still
    PENDING without an ID. The caller then blocks with create_uncertain instead of the retried cleanup_unconfirmed."""

    def __init__(self, uncertain=False):
        super().__init__()
        self.uncertain = uncertain


class _Session:
    __slots__ = ('handle', 'owner_uid', 'run_id', 'variant', 'intent', 'op_lock', 'close_task', 'opening', 'closed', 'receipt',
                 'level', 'stage', 'context_sha256', 'catalog_profile', 'check_index', 'pids_limit', 'expected_step', 'endpoint', 'shell_steps')

    def __init__(self, handle, owner_uid, run_id, variant, level=None, stage=None, context_sha256=None, catalog_profile=None):
        self.handle, self.owner_uid, self.run_id, self.variant = handle, owner_uid, run_id, variant
        self.level, self.stage, self.context_sha256 = level, stage, context_sha256  # a level session has no variant
        self.catalog_profile = catalog_profile  # a catalog session has a variant, a context and A|B, and no level
        self.check_index = 0                    # highest catalog_check index already answered on this handle
        self.pids_limit = None                  # M4 room: pids limit of the effective profile observed at open (int) or None
        self.expected_step = None               # M5 network: the step the permit just spent stands for (set under the op_lock)
        self.endpoint = None                    # M5 network: the endpoint the runtime published at open, already validated
        self.shell_steps = 0                    # trusted exploratory-room dispatches, spent before runtime
        self.intent = None
        self.op_lock = asyncio.Lock()
        self.close_task = None
        self.opening = True
        self.closed = False
        self.receipt = None


def _violations(value):
    if isinstance(value, (list, tuple)) and value and len(value) <= 16 and all(
            isinstance(item, str) and item in wire.VIOLATION_NAMES for item in value):
        return sorted(set(value))
    return ['profile_unavailable']


def _check_created(raw):
    if isinstance(raw, dict) and raw.get('compatible') is True and not raw.get('violations'):
        return
    raise _Fail('profile_rejected', violations=_violations(raw.get('violations') if isinstance(raw, dict) else None))


def _check_running(raw, intent):
    if not isinstance(raw, dict):
        raise _Fail('profile_unavailable')
    if raw.get('running') is not True:
        raise _Fail('not_running')
    profile, digest = raw.get('profile'), raw.get('profile_sha256')
    if (raw.get('container_id') != intent.container_id or not isinstance(profile, dict) or profile.get('available') is not True
            or not isinstance(digest, str) or not _HEX64.fullmatch(digest) or digest != intent.profile_sha256
            or raw.get('violations')):
        raise _Fail('profile_rejected', violations=_violations(raw.get('violations')))
    return profile, digest


def _result_body(raw, name=None):
    keys = wire.MEASUREMENT_FIELDS if name == 'measure' else ('stdout', 'stderr', 'exit_code') + wire.MEASUREMENT_FIELDS
    if not isinstance(raw, dict) or any(key not in raw for key in keys):
        raise _Fail('internal_error')
    return {key: raw[key] for key in keys}


def _close_report(raw):
    if not isinstance(raw, dict) or raw.get('cleanup_confirmed') is not True:
        raise _Fail('cleanup_unconfirmed')
    oom = raw.get('oom_killed')
    if oom is not None and type(oom) is not bool:
        oom = None
    try:
        measurement = wire.check_measurement(raw)
    except wire.WireError:
        measurement = wire.unavailable_measurement()
    return oom, measurement


def _room_absent(raw, level):
    """cgroup_absent of a room close, judged on the runtime's own report. Processes: exactly True (the original node is proven absent);
    Privileges: None. Anything else (False, missing, another type) is an unconfirmed restitution, so no FINISH can follow. Other levels
    have no such key and keep their historical close shape."""
    if level == 'processes':
        if raw.get('cgroup_absent') is not True:
            raise _Fail('cleanup_unconfirmed')
        return True
    if level == 'privileges':
        if raw.get('cgroup_absent') is not None:
            raise _Fail('cleanup_unconfirmed')
    return None


def _network_roles(raw, intent):
    """The four cleanup roles the runtime reported for a network close, or None when the report is not exactly what is expected.

    Exact: a dict with the four roles actor/network/canary/verifier, each absent|pending|unknown (closed vocabulary), and a `bundle_id`
    equal to the intent (the pin). Nothing is completed or defaulted: a missing, extra or foreign value is None."""
    if not isinstance(raw, dict):
        return None
    roles = raw.get('cleanup_roles')
    if (raw.get('bundle_id') != getattr(intent, 'intent_id', None) or not isinstance(roles, dict)
            or set(roles) != set(wire.CLEANUP_ROLES)
            or any(not isinstance(state, str) or state not in wire.CLEANUP_STATES for state in roles.values())):
        return None
    return {role: roles[role] for role in wire.CLEANUP_ROLES}


def _network_confirmed(raw, intent):
    """Roles of a network close that may be FINISHed: aggregate cleanup true AND the exact bundle AND the four roles absent."""
    roles = _network_roles(raw, intent)
    if roles is None or raw.get('cleanup_confirmed') is not True or any(state != 'absent' for state in roles.values()):
        raise _Fail('cleanup_unconfirmed')
    return roles


def _durable_roles(intent):
    """cleanup_roles read from the DURABLE facts of a pending network intent (never from Docker, never from a listing).

    The actor is `absent` once the diary holds its observed absence; an auxiliary is `absent` or `pending` by its phase; everything else,
    a role never recorded included, is `unknown`. It confirms nothing: it only shows how far the restitution got."""
    roles = dict.fromkeys(wire.CLEANUP_ROLES, 'unknown')
    if getattr(intent, 'actor_absent', None) is True:
        roles['actor'] = 'absent'
    resources = getattr(intent, 'network_resources', ())
    for item in resources if isinstance(resources, (tuple, list)) else ():
        role, phase = getattr(item, 'role', None), getattr(item, 'phase', None)
        if isinstance(role, str) and role in roles and role != 'actor':
            roles[role] = 'absent' if phase == 'ABSENT' else 'pending' if phase == 'PENDING' else 'unknown'
    return roles


def _network_finish_consistent(intent):
    """A FINISH of a network intent that really closed everything: bundle == intent, the actor observed absent and the three auxiliary
    resources ABSENT, in creation order. A diary that answers a FINISH without that contradicts itself and never confirms."""
    resources = getattr(intent, 'network_resources', None)
    return (getattr(intent, 'bundle_id', None) == getattr(intent, 'intent_id', 0) and getattr(intent, 'actor_absent', None) is True
            and isinstance(resources, (tuple, list))
            and tuple(getattr(item, 'role', None) for item in resources) == ('network', 'canary', 'verifier')
            and all(getattr(item, 'phase', None) == 'ABSENT' for item in resources))


def _level_probe_body(raw, name='cgroup_events'):
    """What the runtime returned for a fixed probe, as a body for the wire validator, which judges keys and values.

    cgroup_events keeps its two keys. file_state and copy_scan are the runtime's own dicts (labelled status, or the scan): they are
    copied, and the envelope is the caller's, set AFTER them. A runtime that returns an `ok` or `op` key of its own is a runtime with
    the wrong shape, an uncertain outcome like any other extra key, never silently overwritten."""
    if name == 'cgroup_events':
        if not isinstance(raw, dict) or set(raw) != {'status', 'counters'}:
            raise _Fail('internal_error')
        return {'status': raw['status'], 'counters': raw['counters']}
    if not isinstance(raw, dict) or 'ok' in raw or 'op' in raw:
        raise _Fail('internal_error')
    return dict(raw)


def _probe_arguments(request):
    """The typed arguments of a fixed probe, only from the decoded request. cgroup_events has none."""
    if request.name == 'file_state':
        return {'path': request.path}
    if request.name == 'copy_scan':
        return {'sha256': request.sha256, 'size': request.size, 'exclude': request.exclude}
    return {}


def _probe_served(session, name):
    """Which handle may ask which probe: cgroup_events of a memory actor, file_state and copy_scan of a persistence phase."""
    if name == 'cgroup_events':
        return session.level == 'memory' and session.stage == 'actor'
    return session.level == 'persistence' and proto.level_stage_valid(session.level, session.stage)


def _ids_ok(ids):
    return isinstance(ids, (tuple, list)) and all(isinstance(item, str) and _HEX64.fullmatch(item) for item in ids)


def _allowed_levels(value):
    """Immutable copy of the trusted allowlist. A string, a mapping or an unknown name is a configuration error."""
    if not isinstance(value, (tuple, list, set, frozenset)) or any(
            not isinstance(item, str) or item not in proto.LEVELS for item in value):
        raise ValueError('invalid allowed levels')
    return frozenset(value)


def _allowed_catalog(value):
    """The trusted catalog policy: exactly a bool. A truthy int, a string or None is a configuration error, never a policy."""
    if type(value) is not bool:
        raise ValueError('invalid allowed catalog')
    return value


def _valid_socket_path(path):
    try:
        return (isinstance(path, str) and path.startswith('/') and len(path.encode('utf-8')) <= 107
                and not any(part in ('', '.', '..') for part in path.split('/')[1:])
                and not any(ord(char) < 32 or ord(char) == 127 for char in path))
    except UnicodeError:
        return False


class ActorBroker:
    def __init__(self, *, runtime, inventory, client_uid, image_id, socket_path=None, socket_mode=0o660,
                 ttl_seconds=TTL_SECONDS, limits=None, clock=time.monotonic, reap_interval=REAP_INTERVAL_SECONDS,
                 read_timeout=wire.READ_TIMEOUT_SECONDS, allowed_levels=(), allowed_catalog=False, allowed_shell_levels=()):
        allowed = _allowed_levels(allowed_levels)
        shell = _allowed_levels(allowed_shell_levels)
        if not shell <= allowed.intersection(proto.ROOM_LEVELS):
            raise ValueError('shell rooms must be explicitly allowed room levels')
        self._shell_levels = shell
        catalog = _allowed_catalog(allowed_catalog)
        if type(client_uid) is not int or not 1 <= client_uid <= _MAX_UID:
            raise ValueError('invalid client uid')
        if not isinstance(image_id, str) or not _IMAGE_ID.fullmatch(image_id):
            raise ValueError('invalid image id')
        if (any(not callable(getattr(runtime, name, None)) for name in _RUNTIME_METHODS)
                or any(not callable(getattr(inventory, name, None)) for name in _INVENTORY_METHODS)
                or not isinstance(getattr(inventory, 'installation_id', None), str)):
            raise ValueError('runtime or inventory does not meet the injected interface')
        if allowed and (any(not callable(getattr(inventory, name, None)) for name in _LEVEL_INVENTORY_METHODS)
                        or any(not callable(getattr(runtime, name, None)) for name in _LEVEL_RUNTIME_METHODS)):
            raise ValueError('runtime or inventory does not meet the level interface')
        if allowed & set(proto.ROOM_LEVELS) and any(
                not callable(getattr(runtime, name, None)) or not inspect.iscoroutinefunction(getattr(runtime, name))
                for name in _ROOM_RUNTIME_METHODS):
            raise ValueError('runtime does not meet the room interface')  # M4: an async room_action(intent) is required
        if proto.NETWORK_LEVEL in allowed and any(
                not callable(getattr(runtime, name, None)) or not inspect.iscoroutinefunction(getattr(runtime, name))
                for name in _NETWORK_RUNTIME_METHODS):
            raise ValueError('runtime does not meet the network interface')  # M5: an async network_action(intent, command) is required
        if catalog and (any(not callable(getattr(inventory, name, None)) for name in _CATALOG_INVENTORY_METHODS)
                        or any(not callable(getattr(runtime, name, None)) for name in _CATALOG_RUNTIME_METHODS)
                        or inspect.iscoroutinefunction(runtime.catalog_status)  # received: catalog_status is NOT awaitable
                        or not inspect.iscoroutinefunction(runtime.catalog_check)):  # and catalog_check is
            raise ValueError('runtime or inventory does not meet the catalog interface')
        if socket_path is not None and not _valid_socket_path(socket_path):
            raise ValueError('invalid socket path')
        if any(type(item) not in (int, float) or not math.isfinite(item) or item <= 0 for item in (reap_interval, read_timeout)):
            raise ValueError('invalid reap interval or read timeout')
        self.runtime, self.inventory = runtime, inventory
        self._allowed_levels = allowed
        self._allowed_catalog = catalog
        self._client_uid, self._image_id = client_uid, image_id
        self._socket_path, self._socket_mode = socket_path, socket_mode
        self._limits = limits if limits is not None else Limits()
        self._clock, self._reap_interval, self._read_timeout = clock, reap_interval, read_timeout
        # One plaza per installation in M1: the registry holds a single lease, with an absolute 120 s TTL by default.
        self.leases = proto.ActorLeases(max_sessions=1, ttl_seconds=ttl_seconds, clock=clock)
        self._sessions = {}
        self._tombs = collections.OrderedDict()
        self._tasks = set()
        self._intent = None
        self._blocked = None
        self._recovered = False
        self._shutdown = False
        self._connections = 0
        self._reconcile_gate = asyncio.Lock()
        self.socket_identity = None

    # ------------------------------------------------------------------------------------------------ state and helpers

    @property
    def allowed_levels(self):
        """The levels this owner serves (frozenset). Read-only: it is configuration, not something a request can change."""
        return self._allowed_levels

    @property
    def allowed_catalog(self):
        """Whether this owner serves the catalog domain (bool). Read-only: it is configuration, not something a request can change."""
        return self._allowed_catalog

    def status(self):
        return {'installation_id': self.inventory.installation_id, 'blocked': self._blocked,
                'obligations': 1 if self._intent is not None else 0, 'recovered': self._recovered}

    def _block(self, reason):
        if self._blocked is None:
            self._blocked = reason if _BLOCK.fullmatch(reason) else 'state_unavailable'

    @staticmethod
    def _state_reason(exc):
        code = getattr(exc, 'code', None)
        return code if isinstance(code, str) and _BLOCK.fullmatch(code) else 'state_unavailable'

    def _journal(self, method, *args, _refuse=None, **kwargs):
        """One diary mutation. A refusal before anything exists maps to a lease reason; any other failure blocks the owner.

        `_refuse` (level begin only) adds closed codes that are also a refusal before anything exists, not a failure."""
        try:
            return method(*args, **kwargs)
        except Exception as exc:
            code = self._state_reason(exc)
            if code in _STATE_MAP:
                raise _Fail(_STATE_MAP[code]) from None
            if _refuse and code in _refuse:
                raise _Fail(_refuse[code]) from None
            self._block(code)
            raise _Fail('owner_blocked') from None

    async def _timed(self, awaitable, name):
        try:
            return await asyncio.wait_for(awaitable, getattr(self._limits, name))
        except asyncio.TimeoutError:
            raise _Fail('timeout') from None
        except _Fail:
            raise
        except Exception as exc:
            reason = getattr(exc, 'reason', None)
            raise _Fail(reason if reason in _PASS_REASONS else 'runtime_error') from None

    async def _runtime_ready(self):
        try:
            return (await self._timed(self.runtime.ready(), 'ready')) is True
        except _Fail:
            return False

    def _spawn(self, coroutine):
        task = asyncio.ensure_future(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._done)
        return task

    def _done(self, task):
        self._tasks.discard(task)
        if not task.cancelled():
            task.exception()  # retrieved on purpose: failures are reported through state, not through an unobserved task

    async def drain(self):
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)

    def _remember(self, handle, owner_uid, receipt):
        self._tombs[handle] = (owner_uid, receipt, self._clock() + TOMBSTONE_SECONDS)
        while len(self._tombs) > TOMBSTONE_LIMIT:
            self._tombs.popitem(last=False)

    def _tomb(self, handle):
        now = self._clock()
        for key in [key for key, item in self._tombs.items() if now >= item[2]]:
            del self._tombs[key]
        item = self._tombs.get(handle)
        return (item[0], item[1]) if item is not None else None

    def _drop(self, session):
        self._sessions.pop(session.handle, None)
        with contextlib.suppress(proto.ProtocolError):
            self.leases.retire(session.handle, cleanup_confirmed=True)

    # -------------------------------------------------------------------------------------------------------- dispatch

    async def handle(self, peer_uid, raw):
        """Decide and answer one frame. Returns the response payload (unframed), or None when nothing may be said."""
        if peer_uid != self._client_uid:
            return None
        try:
            request = wire.decode_request(raw)
        except proto.ProtocolError as exc:
            return wire.error_response(exc.reason)
        try:
            if request.op == 'health':
                return await self._op_health()
            if request.op == 'open':
                return await self._op_open(peer_uid, request)
            if request.op == 'close':
                return await self._op_close(peer_uid, request)
            if request.op == 'receipt':
                return self._op_receipt(peer_uid, request)  # synchronous on purpose: no await, so no runtime call is possible
            if request.op == 'open_level':
                return await self._op_open_level(peer_uid, request)
            if request.op == 'level_receipt':
                return self._op_level_receipt(peer_uid, request)  # synchronous on purpose, like `receipt`
            if request.op == 'catalog_info':
                return self._op_catalog_info()  # synchronous on purpose: a read of the owner's public view
            if request.op == 'open_catalog':
                return await self._op_open_catalog(peer_uid, request)
            if request.op == 'catalog_receipt':
                return self._op_catalog_receipt(peer_uid, request)  # synchronous on purpose, like `receipt`
            return await self._op_operate(peer_uid, request)  # execute, probe, level_probe and catalog_check
        except asyncio.CancelledError:
            raise
        except Exception:
            return wire.error_response('internal_error')

    async def _op_health(self):
        ready = await self._runtime_ready()
        return wire.encode_response('health', {
            'ready': bool(ready and self._recovered and not self._shutdown), 'image_id': self._image_id,
            'installation_id': self.inventory.installation_id, 'obligations': 1 if self._intent is not None else 0,
            'blocked': self._blocked is not None})

    # ---------------------------------------------------------------------------------------------------------- receipt

    @staticmethod
    def _is_exact_finish(intent, uid, request):
        """The diary's answer must be the FINISH of exactly the identity asked about; anything else is not trusted."""
        return (intent is not None and getattr(intent, 'phase', None) == 'FINISH'
                and getattr(intent, 'controller_uid', None) == uid and getattr(intent, 'run_id', None) == request.run_id
                and getattr(intent, 'variant', None) == request.variant
                and getattr(intent, 'catalog_profile', None) is None  # M3.1: a catalog FINISH is never an M1 receipt
                and getattr(intent, 'intent_id', None) == request.intent_id
                and getattr(intent, 'container_id', None) == request.container_id)

    def _op_receipt(self, uid, request):
        if request.installation_id != self.inventory.installation_id:
            return wire.error_response('installation_mismatch')
        query = getattr(self.inventory, 'receipt', None)
        if not callable(query):
            return wire.error_response('internal_error')
        try:
            intent = query(controller_uid=uid, run_id=request.run_id, variant=request.variant, intent_id=request.intent_id,
                           container_id=request.container_id)
        except Exception as exc:  # read-only: nothing is blocked or marked here, the client simply gets no confirmation
            return wire.error_response('foreign_owner' if self._state_reason(exc) == 'identity_changed' else 'internal_error')
        if intent is None:
            confirmed = False
        elif self._is_exact_finish(intent, uid, request):
            confirmed = True
        else:
            return wire.error_response('internal_error')  # a diary that answers with another identity cannot confirm
        return wire.encode_response('receipt', {
            'installation_id': request.installation_id, 'run_id': request.run_id, 'variant': request.variant,
            'intent_id': request.intent_id, 'container_id': request.container_id,
            'status': 'confirmed' if confirmed else 'unknown', 'cleanup_confirmed': confirmed})

    @staticmethod
    def _is_exact_level_finish(intent, uid, request):
        """The diary's answer must be the FINISH of exactly the level identity asked about, context included."""
        return (intent is not None and getattr(intent, 'phase', None) == 'FINISH'
                and getattr(intent, 'controller_uid', None) == uid and getattr(intent, 'run_id', None) == request.run_id
                and getattr(intent, 'level', None) == request.level and getattr(intent, 'stage', None) == request.stage
                and getattr(intent, 'context_sha256', None) == request.context_sha256
                and getattr(intent, 'intent_id', None) == request.intent_id
                and getattr(intent, 'container_id', None) == request.container_id)

    @staticmethod
    def _matches_pending(pending, uid, request):
        """The pending intent IS the network identity asked about (same UID, run, level, stage, context, intent and container)."""
        return (pending is not None and getattr(pending, 'controller_uid', None) == uid
                and getattr(pending, 'run_id', None) == request.run_id and getattr(pending, 'level', None) == request.level
                and getattr(pending, 'stage', None) == request.stage
                and getattr(pending, 'context_sha256', None) == request.context_sha256
                and getattr(pending, 'intent_id', None) == request.intent_id
                and getattr(pending, 'container_id', None) == request.container_id)

    def _pending_roles(self, uid, request):
        """cleanup_roles of an `unknown` network receipt: the durable partial states of the matching pending intent, else all unknown.

        pending() is a read of the diary (no runtime, no mutation); a failing read or any other intent says nothing: all `unknown`."""
        unknown = dict.fromkeys(wire.CLEANUP_ROLES, 'unknown')
        try:
            pending = self.inventory.pending()
        except Exception:
            return unknown
        return _durable_roles(pending) if self._matches_pending(pending, uid, request) else unknown

    def _op_level_receipt(self, uid, request):
        if request.installation_id != self.inventory.installation_id:
            return wire.error_response('installation_mismatch')
        query = getattr(self.inventory, 'receipt_level', None)
        if not callable(query):
            return wire.error_response('internal_error')
        try:
            intent = query(controller_uid=uid, run_id=request.run_id, level=request.level, stage=request.stage,
                           context_sha256=request.context_sha256, intent_id=request.intent_id,
                           container_id=request.container_id)
        except Exception as exc:  # read-only: nothing is blocked or marked here, the client simply gets no confirmation
            return wire.error_response('foreign_owner' if self._state_reason(exc) == 'identity_changed' else 'internal_error')
        if intent is None:
            confirmed = False
        elif self._is_exact_level_finish(intent, uid, request) and (
                request.level != proto.NETWORK_LEVEL or _network_finish_consistent(intent)):
            confirmed = True
        else:
            return wire.error_response('internal_error')  # a diary that answers with another identity cannot confirm
        body = {
            'installation_id': request.installation_id, 'run_id': request.run_id, 'level': request.level,
            'stage': request.stage, 'context_sha256': request.context_sha256, 'intent_id': request.intent_id,
            'container_id': request.container_id, 'status': 'confirmed' if confirmed else 'unknown',
            'cleanup_confirmed': confirmed}
        if request.level == proto.NETWORK_LEVEL:
            # M5: the bundle is the intent. Roles are all `absent` only for the exact FINISH; otherwise the durable partial states of the
            # matching pending intent, or all `unknown`. A read of the diary: no runtime, no mutation, no block.
            body['bundle_id'] = request.intent_id
            body['cleanup_roles'] = (dict.fromkeys(wire.CLEANUP_ROLES, 'absent') if confirmed
                                     else self._pending_roles(uid, request))
        if request.level in proto.ROOM_LEVELS:
            # M4: the exact FINISH of a Processes room exists only after its node was proven absent; nothing else says true.
            body['cgroup_absent'] = True if confirmed and request.level == 'processes' else None
        if request.stage == 'fresh':
            # Confirmed names the predecessor of the exact FINISH the diary returned; unknown names nothing (null). Never the request's.
            body['predecessor'] = self._predecessor_of(intent) if confirmed else None
            if confirmed and body['predecessor'] is None:
                return wire.error_response('internal_error')  # a FINISH without a usable predecessor cannot confirm a fresh phase
        return wire.encode_response('level_receipt', body)

    # ------------------------------------------------------------------------------------------------- catalog (M3.1)

    def _catalog_view(self):
        """The owner's public catalog view from `runtime.catalog_status()` (synchronous, read-only), rebuilt from the fixed constants.

        {'ready': bool, 'identity': {id, sha256, size, destination} | None} or None. None means the runtime answered something else:
        not exactly the two keys, a non-bool `ready`, an identity that is not the fixed one (size an int, never a bool or a float), or
        `ready` with no identity. Nothing the runtime adds (a path, a registration, a resource id) is ever copied."""
        try:
            raw = self.runtime.catalog_status()
        except Exception:
            return None
        if not isinstance(raw, dict) or set(raw) != {'ready', 'identity'} or type(raw['ready']) is not bool:
            return None
        fixed = {'id': proto.CATALOG_ID, 'sha256': proto.CATALOG_SHA256, 'size': proto.CATALOG_SIZE,
                 'destination': proto.CATALOG_DESTINATION}
        identity = raw['identity']
        if identity is None:
            return {'ready': False, 'identity': None} if raw['ready'] is False else None
        if not isinstance(identity, dict) or identity != fixed or type(identity['size']) is not int:
            return None
        return {'ready': raw['ready'], 'identity': dict(fixed)}

    def _op_catalog_info(self):
        if not self._allowed_catalog:
            return wire.error_response('catalog_not_allowed')  # policy first, from configuration only
        view = self._catalog_view()
        if view is None:
            return wire.error_response('internal_error')
        return wire.encode_response('catalog_info', {'installation_id': self.inventory.installation_id, **view})

    @staticmethod
    def _is_exact_catalog_finish(intent, uid, request):
        """The diary's answer must be the FINISH of exactly the catalog identity asked about: profile, context and pins included."""
        return (intent is not None and getattr(intent, 'phase', None) == 'FINISH'
                and getattr(intent, 'controller_uid', None) == uid and getattr(intent, 'run_id', None) == request.run_id
                and getattr(intent, 'variant', None) == request.variant
                and getattr(intent, 'catalog_profile', None) == request.catalog_profile
                and getattr(intent, 'context_sha256', None) == request.context_sha256
                and getattr(intent, 'catalog_id', None) == request.catalog_id
                and getattr(intent, 'catalog_sha256', None) == request.catalog_sha256
                and getattr(intent, 'intent_id', None) == request.intent_id
                and getattr(intent, 'container_id', None) == request.container_id)

    def _op_catalog_receipt(self, uid, request):
        if request.installation_id != self.inventory.installation_id:
            return wire.error_response('installation_mismatch')
        query = getattr(self.inventory, 'receipt_catalog', None)
        if not callable(query):
            return wire.error_response('internal_error')
        try:
            intent = query(controller_uid=uid, run_id=request.run_id, variant=request.variant, catalog_profile=request.catalog_profile,
                           context_sha256=request.context_sha256, catalog_id=request.catalog_id, catalog_sha256=request.catalog_sha256,
                           intent_id=request.intent_id, container_id=request.container_id)
        except Exception as exc:  # read-only: nothing is blocked or marked here, the client simply gets no confirmation
            return wire.error_response('foreign_owner' if self._state_reason(exc) == 'identity_changed' else 'internal_error')
        if intent is None:
            confirmed = False
        elif self._is_exact_catalog_finish(intent, uid, request):
            confirmed = True
        else:
            return wire.error_response('internal_error')  # a diary that answers with another identity or domain cannot confirm
        return wire.encode_response('catalog_receipt', {
            'installation_id': request.installation_id, 'run_id': request.run_id, 'variant': request.variant,
            'catalog_profile': request.catalog_profile, 'context_sha256': request.context_sha256, 'catalog_id': request.catalog_id,
            'catalog_sha256': request.catalog_sha256, 'intent_id': request.intent_id, 'container_id': request.container_id,
            'status': 'confirmed' if confirmed else 'unknown', 'cleanup_confirmed': confirmed})

    def _catalog_identity(self, intent):
        """The nine public fields of a catalog intent, field by field: never asdict(intent), which would carry the private resource_id."""
        return {'installation_id': self.inventory.installation_id, 'run_id': intent.run_id, 'variant': intent.variant,
                'catalog_profile': intent.catalog_profile, 'context_sha256': intent.context_sha256, 'catalog_id': intent.catalog_id,
                'catalog_sha256': intent.catalog_sha256, 'intent_id': intent.intent_id, 'container_id': intent.container_id}

    # ------------------------------------------------------------------------------------------------------------ open

    async def _op_open_level(self, uid, request):
        # Policy first and from configuration only: nothing is leased, journaled or created for a level this owner does not serve.
        if request.level not in self._allowed_levels or not proto.level_stage_valid(request.level, request.stage):
            return wire.error_response('level_not_allowed')
        if self._shutdown:
            return wire.error_response('shutting_down')
        if self._blocked is not None:
            return wire.error_response('owner_blocked')
        if not self._recovered:
            return wire.error_response('owner_not_ready')
        try:
            handle = self.leases.open_level(uid, request.run_id, request.level, request.stage, request.context_sha256)
        except proto.ProtocolError as exc:
            return wire.error_response(exc.reason)
        session = _Session(handle, uid, request.run_id, None, request.level, request.stage, request.context_sha256)
        self._sessions[handle] = session
        return await asyncio.shield(self._spawn(self._open_steps(session)))  # not tied to the connection, as in `open`

    async def _op_open_catalog(self, uid, request):
        # Policy first and from configuration only: nothing is leased, journaled or created when this owner does not serve the domain.
        if not self._allowed_catalog:
            return wire.error_response('catalog_not_allowed')
        if self._shutdown:
            return wire.error_response('shutting_down')
        if self._blocked is not None:
            return wire.error_response('owner_blocked')
        if not self._recovered:
            return wire.error_response('owner_not_ready')
        try:
            handle = self.leases.open_catalog(uid, request.run_id, request.variant, request.catalog_profile, request.context_sha256,
                                              request.catalog_id, request.catalog_sha256)
        except proto.ProtocolError as exc:
            return wire.error_response(exc.reason)
        session = _Session(handle, uid, request.run_id, request.variant, None, None, request.context_sha256, request.catalog_profile)
        self._sessions[handle] = session
        return await asyncio.shield(self._spawn(self._open_steps(session)))  # not tied to the connection, as in `open`

    def _begin_catalog(self, session):
        """CREATE_PENDING of a catalog cell, durable before create. The UID is the peer's; the pins are the owner's constants."""
        intent = self._journal(self.inventory.begin_catalog, controller_uid=session.owner_uid, run_id=session.run_id,
                               variant=session.variant, catalog_profile=session.catalog_profile, context_sha256=session.context_sha256,
                               catalog_id=proto.CATALOG_ID, catalog_sha256=proto.CATALOG_SHA256,
                               _refuse={'invalid_transition': 'context_mismatch', 'catalog_unavailable': 'catalog_unavailable',
                                        'catalog_resource_exists': 'catalog_unavailable'})  # clean refusals: no obligation was born
        digest = getattr(intent, 'profile_sha256', None)
        if (getattr(intent, 'phase', None) != 'CREATE_PENDING' or getattr(intent, 'container_id', 0) is not None
                or getattr(intent, 'controller_uid', None) != session.owner_uid
                or getattr(intent, 'run_id', None) != session.run_id or getattr(intent, 'variant', None) != session.variant
                or getattr(intent, 'catalog_profile', None) != session.catalog_profile
                or getattr(intent, 'context_sha256', None) != session.context_sha256
                or getattr(intent, 'catalog_id', None) != proto.CATALOG_ID
                or getattr(intent, 'catalog_sha256', None) != proto.CATALOG_SHA256
                or not isinstance(getattr(intent, 'intent_id', None), str) or not _HEX32.fullmatch(intent.intent_id)
                or not isinstance(digest, str) or not _HEX64.fullmatch(digest)):
            # The diary answered with something else than the pending obligation asked for: nothing may be created or removed on it.
            self._track(session, intent)
            self._block('state_unavailable')
            raise _Fail('owner_blocked')
        return intent

    def _predecessor_of(self, intent):
        """The seven identity fields of the predecessor that the DIARY recorded on `intent`, or None.

        Taken with dataclasses.asdict from the intent's own `predecessor` (never from a request) and validated as a faithful
        persistence/actor identity of the same installation, run and context whose IDs differ from the intent's. A missing,
        non-dataclass or inconsistent predecessor is None, and None is never a confirmation."""
        previous = getattr(intent, 'predecessor', None)
        if previous is None or isinstance(previous, type) or not is_dataclass(previous):
            return None
        try:
            return wire.predecessor_identity(
                asdict(previous), run_id=getattr(intent, 'run_id', None), context_sha256=getattr(intent, 'context_sha256', None),
                installation_id=self.inventory.installation_id,
                successor={'intent_id': getattr(intent, 'intent_id', None), 'container_id': getattr(intent, 'container_id', None)})
        except (wire.WireError, TypeError, ValueError):
            return None

    def _begin(self, session):
        """CREATE_PENDING, durable before create. A level begins with its own identity and never carries a variant."""
        if session.catalog_profile is not None:
            return self._begin_catalog(session)
        if session.level is None:
            return self._journal(self.inventory.begin, controller_uid=session.owner_uid, run_id=session.run_id,
                                 variant=session.variant)
        intent = self._journal(self.inventory.begin_level, controller_uid=session.owner_uid, run_id=session.run_id,
                               level=session.level, stage=session.stage, context_sha256=session.context_sha256,
                               _refuse={'invalid_transition': 'context_mismatch',
                                        'predecessor_unconfirmed': 'predecessor_unconfirmed'})  # clean refusals: nothing exists
        if (getattr(intent, 'phase', None) != 'CREATE_PENDING' or getattr(intent, 'container_id', 0) is not None
                or getattr(intent, 'controller_uid', None) != session.owner_uid
                or getattr(intent, 'run_id', None) != session.run_id or getattr(intent, 'level', None) != session.level
                or getattr(intent, 'stage', None) != session.stage
                or getattr(intent, 'context_sha256', None) != session.context_sha256):
            # The diary answered with something else than the pending obligation asked for: nothing may be created or removed on it.
            self._track(session, intent)
            self._block('state_unavailable')
            raise _Fail('owner_blocked')
        recorded = getattr(intent, 'predecessor', None)
        if (session.stage == 'fresh') != (recorded is not None) or (recorded is not None and self._predecessor_of(intent) is None):
            # A fresh phase without a faithful predecessor, or an actor phase that has one: the same contradiction, and the same answer.
            self._track(session, intent)
            self._block('state_unavailable')
            raise _Fail('owner_blocked')
        if session.level == proto.NETWORK_LEVEL and (getattr(intent, 'bundle_id', None) != intent.intent_id
                                                     or getattr(intent, 'actor_requested', None) is not False):
            # M5: a network obligation is born with bundle == intent and no actor requested yet; anything else is a diary answering
            # something else, and nothing may be created or removed on it.
            self._track(session, intent)
            self._block('state_unavailable')
            raise _Fail('owner_blocked')
        return intent

    async def _op_open(self, uid, request):
        if self._shutdown:
            return wire.error_response('shutting_down')
        if self._blocked is not None:
            return wire.error_response('owner_blocked')
        if not self._recovered:
            return wire.error_response('owner_not_ready')
        try:
            handle = self.leases.open(uid, request.run_id, request.variant)  # capacity and replay of a live lease
        except proto.ProtocolError as exc:
            return wire.error_response(exc.reason)
        session = _Session(handle, uid, request.run_id, request.variant)
        self._sessions[handle] = session
        # The sequence is not tied to the connection: a disconnect leaves the lease with the owner (reaper), never half-done.
        return await asyncio.shield(self._spawn(self._open_steps(session)))

    @staticmethod
    def _check_network_running(running, intent):
        """bundle_id and endpoint of runtime.inspect_running for a network actor (its profile was already judged).

        The bundle must be the intent and the endpoint the one fixed shape http://<private IPv4>:8080/. Anything else is a runtime that
        answers something else: no handle is granted and the actor is restituted."""
        try:
            if running.get('bundle_id') != intent.intent_id:
                raise wire.WireError('owner_response_invalid')
            return wire.network_endpoint(running.get('endpoint'))
        except wire.WireError:
            raise _Fail('profile_unavailable') from None

    def _track(self, session, intent):
        session.intent = intent
        self._intent = intent

    async def _open_steps(self, session):
        try:
            return await self._open_sequence(session)
        except _Fail as fail:
            failure = fail
        except Exception:
            failure = _Fail('internal_error')
        return await self._open_failed(session, failure)

    async def _open_sequence(self, session):
        if not await self._runtime_ready():
            raise _Fail('owner_not_ready')
        try:
            ids = await self._timed(self.runtime.installed_ids(), 'ids')
        except _Fail:
            raise _Fail('owner_not_ready') from None
        if not _ids_ok(ids):
            self._block('inventory_unavailable')
            raise _Fail('owner_blocked')
        if ids:  # something of this installation exists that no intent of ours explains
            self._block('unrecognized_object')
            raise _Fail('owner_blocked')
        if session.catalog_profile is not None and (self._catalog_view() or {}).get('ready') is not True:
            # A resource that is not ready never reaches the diary or create: a create that failed for it would be ambiguous and block.
            raise _Fail('catalog_unavailable')
        intent = self._begin(session)  # CREATE_PENDING is durable before create
        self._track(session, intent)
        try:
            container_id = await self._timed(self.runtime.create(intent), 'create')  # exactly once, never retried
        except _Fail as fail:
            if session.level != proto.NETWORK_LEVEL:
                self._block('create_uncertain')
            # M5: for a network the auxiliaries may already be durable, so the verdict (a proven pre-actor abort, or create_uncertain)
            # is reached in _open_failed after re-reading the diary, never by assuming it here.
            raise _Fail('docker_unavailable' if fail.reason == 'docker_unavailable' else 'create_failed',
                        cleanup_confirmed=False) from None
        if not isinstance(container_id, str) or not _HEX64.fullmatch(container_id):
            if session.level != proto.NETWORK_LEVEL:
                self._block('create_uncertain')
            raise _Fail('create_failed', cleanup_confirmed=False)
        intent = self._journal(self.inventory.ack, intent.intent_id, container_id)  # ACK before inspect or start
        self._track(session, intent)
        try:
            created = await self._timed(self.runtime.inspect_created(intent), 'inspect')
        except _Fail:
            raise _Fail('profile_unavailable') from None
        _check_created(created)
        intent = self._journal(self.inventory.starting, intent.intent_id)  # START_PENDING before start
        self._track(session, intent)
        try:
            await self._timed(self.runtime.start(intent), 'start')  # exactly once
        except _Fail:
            raise _Fail('start_failed') from None
        try:
            running = await self._timed(self.runtime.inspect_running(intent), 'inspect')
        except _Fail:
            raise _Fail('profile_unavailable') from None
        profile, digest = _check_running(running, intent)  # identity and profile re-verified before the handle exists
        limit = profile.get('pids_limit')
        session.pids_limit = limit if type(limit) is int else None  # a room's samples must carry this limit (validate_room_action)
        if session.level == proto.NETWORK_LEVEL:
            session.endpoint = self._check_network_running(running, intent)  # bundle and endpoint re-verified before the handle exists
        intent = self._journal(self.inventory.activate, intent.intent_id)  # ACTIVE before the handle is returned
        self._track(session, intent)
        if session.catalog_profile is not None:
            response = wire.encode_response('open_catalog', {
                'handle': session.handle, **self._catalog_identity(intent), 'name': intent.name, 'profile_sha256': digest,
                'profile': profile})  # field by field: the intent's private resource_id has no wire name
        elif session.level is None:
            response = wire.encode_response('open', {
                'handle': session.handle, 'installation_id': self.inventory.installation_id, 'run_id': intent.run_id,
                'variant': intent.variant, 'intent_id': intent.intent_id, 'name': intent.name,
                'container_id': intent.container_id, 'profile_sha256': digest, 'profile': profile})
        else:
            body = {
                'handle': session.handle, 'installation_id': self.inventory.installation_id, 'run_id': intent.run_id,
                'level': intent.level, 'stage': intent.stage, 'context_sha256': intent.context_sha256,
                'intent_id': intent.intent_id, 'name': intent.name, 'container_id': intent.container_id,
                'profile_sha256': digest, 'profile': profile}
            if intent.stage == 'fresh':
                body['predecessor'] = self._predecessor_of(intent)  # the diary's, from the durable intent
                if body['predecessor'] is None:  # cannot happen after _begin; if it does, the handle is never granted
                    raise _Fail('internal_error')
            if intent.level == proto.NETWORK_LEVEL:
                body['bundle_id'], body['endpoint'] = intent.intent_id, session.endpoint  # M5: the two keys, field by field
            response = wire.encode_response('open_level', body)
        session.opening = False
        return response

    async def _open_failed(self, session, failure):
        session.opening = False
        reason = failure.reason if failure.reason in wire.ERROR_REASONS else 'internal_error'
        intent = session.intent
        if intent is None:  # nothing was journaled: the plaza is simply released
            self._drop(session)
            return wire.error_response(reason)
        if intent.container_id is None and getattr(intent, 'level', None) == proto.NETWORK_LEVEL:
            return await self._open_failed_preactor(session, intent, reason)
        if intent.container_id is None:  # CREATE_PENDING without an ID: blocks, nothing may be removed
            self._block('create_uncertain')
            return wire.error_response(reason, cleanup_confirmed=False)
        try:
            receipt = await self._restitute(intent, session)
        except _Unconfirmed:
            return wire.error_response('cleanup_unconfirmed', cleanup_confirmed=False)
        restored = None
        if getattr(intent, 'level', None) in proto.ROOM_LEVELS:
            # _restitute writes FINISH only after exact actor/cgroup absence. Convey the identity,
            # never a handle: the controller can persist it and query the existing durable receipt.
            restored = {'ok': True, 'op': 'level_receipt',
                        **{key: receipt[key] for key in wire.LEVEL_IDENTITY_FIELDS},
                        'status': 'confirmed', 'cleanup_confirmed': True,
                        'cgroup_absent': receipt['cgroup_absent']}
        return wire.error_response(reason, cleanup_confirmed=True, violations=failure.extras.get('violations'),
                                   restored=restored)

    @staticmethod
    def _same_obligation(fresh, session, intent):
        """The diary's pending intent is the very obligation this session opened: intent, UID, run, level, stage and context, still without
        an actor ID and still a network bundle. Anything else is not ours to touch."""
        return (fresh is not None and getattr(fresh, 'intent_id', None) == intent.intent_id
                and getattr(fresh, 'controller_uid', None) == session.owner_uid and getattr(fresh, 'run_id', None) == session.run_id
                and getattr(fresh, 'level', None) == session.level and getattr(fresh, 'stage', None) == session.stage
                and getattr(fresh, 'context_sha256', None) == session.context_sha256
                and getattr(fresh, 'container_id', 0) is None and getattr(fresh, 'bundle_id', None) == intent.intent_id)

    async def _open_failed_preactor(self, session, intent, reason):
        """A failed open of a network intent that holds no actor ID (M5).

        create() prepares the auxiliaries BEFORE it returns the actor ID, so `session.intent` may be stale: the diary is re-read and the
        obligation compared before anything is touched. A proven pre-actor abort frees the plaza and answers cleanup_confirmed true; anything
        else keeps the debt (lease, diary and block create_uncertain) and answers cleanup_confirmed false. No ID is ever adopted."""
        if self._blocked is not None:
            # This attempt already found the diary unreliable (a refused mutation, or an answer that is not the obligation asked for):
            # nothing may be created or removed on it, so nothing is touched and the debt stays as it is.
            return wire.error_response(reason, cleanup_confirmed=False)
        try:
            fresh = self.inventory.pending()
        except Exception as exc:
            self._block(self._state_reason(exc))
            return wire.error_response(reason, cleanup_confirmed=False)
        if not self._same_obligation(fresh, session, intent):
            self._block('state_unavailable')  # the diary does not hold the obligation this session opened
            return wire.error_response('owner_blocked', cleanup_confirmed=False)
        self._track(session, fresh)
        try:
            await self._restitute_preactor(fresh, session)
        except _Unconfirmed:
            self._block('create_uncertain')  # restart recovery re-evaluates it; nothing here clears it
            return wire.error_response(reason, cleanup_confirmed=False)
        return wire.error_response(reason, cleanup_confirmed=True)

    # --------------------------------------------------------------------------------------------------- restitution

    async def _restitute_preactor(self, intent, session):
        """Restitution of a network intent with NO actor ID (M5): CREATE_PENDING (or CLOSE_PENDING) without a container.

        inventory.closing + runtime.close retire only the auxiliaries the diary recognizes; a role PENDING without an ID stays pending even
        if a listing is empty. Returns None ONLY for a proven pre-actor abort: the actor was never requested, the runtime confirms in
        aggregate and names the exact bundle, the four roles are `absent` and the actor inventory is empty; then inventory.finish(
        container_id=None) is written (a durable abort, not a wire identity), the plaza is released and no tombstone exists. Otherwise it
        raises _Unconfirmed, with `uncertain` when retrying cannot settle it (the actor was requested without its ACK, or a role is
        pending): the debt, the diary state and the lease stay as they are."""
        requested = getattr(intent, 'actor_requested', None)
        if type(requested) is not bool:
            raise _Unconfirmed(uncertain=True)  # a diary that does not say whether the actor was requested
        try:
            closing = self._journal(self.inventory.closing, intent.intent_id)  # CLOSE_PENDING before the runtime removes anything
            self._intent = closing
            if session is not None:
                session.intent = closing
            raw = await self._timed(self.runtime.close(closing), 'close')
        except _Fail:
            raise _Unconfirmed(uncertain=requested) from None
        roles = _network_roles(raw, closing)
        if roles is None:
            raise _Unconfirmed(uncertain=True)
        if requested or raw.get('cleanup_confirmed') is not True or any(state != 'absent' for state in roles.values()):
            raise _Unconfirmed(uncertain=requested or 'pending' in roles.values())
        try:
            ids = await self._timed(self.runtime.installed_ids(), 'ids')
        except _Fail:
            raise _Unconfirmed() from None
        if not _ids_ok(ids) or ids:  # an actor that no intent explains: never FINISH over it
            raise _Unconfirmed()
        try:
            finished = self._journal(self.inventory.finish, closing.intent_id, container_id=None)
        except _Fail:
            raise _Unconfirmed(uncertain=True) from None
        if getattr(finished, 'phase', None) != 'FINISH' or getattr(finished, 'container_id', 0) is not None:
            self._block('state_unavailable')  # a diary that answers something else than the abort it was asked to write
            raise _Unconfirmed(uncertain=True)
        self._intent = None
        if session is not None:
            self._drop(session)

    async def _restitute(self, intent, session):
        """Close the recognized ID and, only after absence, write FINISH. Raises _Unconfirmed otherwise (state is kept)."""
        if intent is None or intent.container_id is None:
            raise _Unconfirmed()
        network = getattr(intent, 'level', None) == proto.NETWORK_LEVEL
        try:
            closing = self._journal(self.inventory.closing, intent.intent_id)  # CLOSE_PENDING before the runtime removes
            self._intent = closing
            if session is not None:
                session.intent = closing
            raw = await self._timed(self.runtime.close(closing), 'close')
            oom, measurement = _close_report(raw)
            absent = _room_absent(raw, getattr(closing, 'level', None))  # M4: before the inventory and before FINISH
            roles = _network_confirmed(raw, closing) if network else None  # M5: the exact bundle and the four roles absent
            ids = await self._timed(self.runtime.installed_ids(), 'ids')
            if not _ids_ok(ids) or closing.container_id in ids or (network and ids):
                raise _Unconfirmed()
            finished = self._journal(self.inventory.finish, closing.intent_id, container_id=closing.container_id)
        except _Unconfirmed:
            raise
        except _Fail:
            raise _Unconfirmed() from None
        self._intent = None
        if set(ids):
            self._block('unrecognized_object')  # evidence of something that is not ours: preserved, never removed
        if getattr(closing, 'catalog_profile', None) is not None:  # a catalog intent: the nine fields, never a workflow or level shape
            identity = self._catalog_identity(closing)
        elif getattr(closing, 'level', None) is not None:  # a level intent: its receipt carries the level identity, never a variant
            identity = {'installation_id': self.inventory.installation_id, 'run_id': closing.run_id, 'level': closing.level,
                        'stage': closing.stage, 'context_sha256': closing.context_sha256, 'intent_id': closing.intent_id,
                        'container_id': closing.container_id}
            if closing.stage == 'fresh':
                # The predecessor of the durable FINISH. None (a diary that did not return one) makes the close answer a refusal:
                # the restitution is complete, but a fresh receipt without its predecessor never confirms anything.
                identity['predecessor'] = self._predecessor_of(finished)
            if network:
                identity['bundle_id'] = closing.intent_id  # M5: the bundle is the intent, never taken from the runtime's own report
        else:
            identity = {'installation_id': self.inventory.installation_id, 'run_id': closing.run_id,
                        'variant': closing.variant, 'intent_id': closing.intent_id, 'container_id': closing.container_id}
        receipt = {**identity, 'cleanup_confirmed': True, 'oom_killed': oom, **measurement}
        if getattr(closing, 'level', None) in proto.ROOM_LEVELS:
            receipt['cgroup_absent'] = absent  # True (Processes, proven) or None (Privileges); never a guess
        if network:
            receipt['cleanup_roles'] = roles  # the four roles, every one absent: judged before FINISH
        if session is not None:
            session.closed, session.receipt, session.intent = True, receipt, closing
            self._remember(session.handle, session.owner_uid, receipt)
            self._drop(session)
        return receipt

    def _close_task(self, session):
        task = session.close_task
        if task is None or (task.done() and not session.closed):  # a failed attempt may be retried: close is idempotent by ID
            task = session.close_task = self._spawn(self._do_close(session))
        return task

    async def _do_close(self, session):
        async with session.op_lock:  # waits for the operation in flight, which ends or fails within its own limit
            if session.closed:
                return session.receipt
            try:
                return await self._restitute(session.intent, session)
            except _Unconfirmed:
                return None

    def _invalidate(self, session):
        with contextlib.suppress(proto.ProtocolError):
            self.leases.begin_close(session.handle, session.owner_uid)
        self._close_task(session)

    @staticmethod
    def _close_response(receipt):
        identity = (wire.CATALOG_IDENTITY_FIELDS if 'catalog_profile' in receipt else
                    wire.NETWORK_IDENTITY_FIELDS if receipt.get('level') == proto.NETWORK_LEVEL else
                    wire.LEVEL_IDENTITY_FIELDS if 'level' in receipt else wire.IDENTITY_FIELDS)  # each handle domain, its own shape
        if 'level' in receipt and receipt['stage'] == 'fresh':
            if not isinstance(receipt.get('predecessor'), dict):
                return wire.error_response('cleanup_unconfirmed', cleanup_confirmed=False)  # no predecessor, no receipt to give
            identity = identity + ('predecessor',)
        keys = identity + ('cleanup_confirmed', 'oom_killed') + wire.MEASUREMENT_FIELDS
        if 'level' in receipt and receipt['level'] in proto.ROOM_LEVELS:
            keys = keys + ('cgroup_absent',)  # M4: the only addition, and only for a room
        if receipt.get('level') == proto.NETWORK_LEVEL:
            keys = keys + ('cleanup_roles',)  # M5: bundle_id rode in with the identity; the four roles ride here
        return wire.encode_response('close', {key: receipt[key] for key in keys})

    async def _op_close(self, uid, request):
        tomb = self._tomb(request.handle)
        if tomb is not None:  # idempotent: the same receipt, only for the same peer
            owner, receipt = tomb
            return wire.error_response('foreign_owner') if owner != uid else self._close_response(receipt)
        session = self._sessions.get(request.handle)
        if session is not None and session.opening:
            return wire.error_response('unknown_handle')
        try:
            self.leases.begin_close(request.handle, uid)  # new operations now get `closing`
        except proto.ProtocolError as exc:
            return wire.error_response(exc.reason)
        if session is None:
            return wire.error_response('internal_error')
        receipt = await asyncio.shield(self._close_task(session))
        if receipt is None:
            return wire.error_response('cleanup_unconfirmed', cleanup_confirmed=False)
        return self._close_response(receipt)

    # ------------------------------------------------------------------------------------------------ execute / probe

    async def _op_operate(self, uid, request):
        if request.op == 'catalog_check' and not self._allowed_catalog:
            return wire.error_response('catalog_not_allowed')  # policy first, from configuration only
        try:
            lease = self.leases.authorize(request.handle, uid)
        except proto.ProtocolError as exc:
            return wire.error_response(exc.reason)
        session = self._sessions.get(lease.handle)
        if session is None or session.opening or session.closed:
            return wire.error_response('internal_error')
        # The handle's domain decides what it may ask. A refusal here runs nothing and leaves the lease and the container intact.
        room = session.level in proto.ROOM_LEVELS
        if request.op == 'room_action' and not room:
            return wire.error_response('wrong_domain')  # no workflow, memory/secret/persistence or catalog handle owns a room action
        if room and request.op == 'execute' and session.level not in self._shell_levels:
            return wire.error_response('wrong_domain')  # a room has no shell: only its fixed action, measure and close
        network = session.level == proto.NETWORK_LEVEL
        if request.op == 'network_action' and not network:
            return wire.error_response('wrong_domain')  # no workflow, other level or catalog handle owns a network action
        if network and request.op not in ('network_action', 'probe'):
            return wire.error_response('wrong_domain')  # a network handle: network_action, probe(measure) and close, nothing else
        if request.op == 'catalog_check':
            if session.catalog_profile is None:
                return wire.error_response('wrong_domain')  # a workflow or level handle never asks the catalog check
        elif session.catalog_profile is not None and request.op != 'execute' and not (
                request.op == 'probe' and request.name in ('task_result', 'measure')):
            return wire.error_response('wrong_domain')  # artifact_capture and level_probe belong to other domains
        elif request.op == 'level_probe':
            if not _probe_served(session, request.name):
                return wire.error_response('wrong_domain')  # an M1 handle, or a level without this probe
            if request.name == 'copy_scan' and session.stage == 'fresh' and request.exclude is not None:
                return wire.error_response('invalid_exclude')  # in a fresh sandbox the original path counts: it is never excluded
        elif session.level is not None and request.op == 'probe' and request.name != 'measure':
            return wire.error_response('wrong_domain')  # task_result and artifact_capture belong to the invoice workflow
        if session.op_lock.locked():
            return wire.error_response('busy')  # no queue
        await session.op_lock.acquire()  # no suspension between the check and the acquire
        if room and request.op == 'execute':
            # Trusted owner opt-in; spend BEFORE dispatch. A lost response never
            # refunds the permit. The same lease/UID/profile/TTL still apply.
            if getattr(session, 'shell_steps', 0) >= 12:  # eight model commands plus fixed preparation/observations
                session.op_lock.release()
                return wire.error_response('action_consumed')
            session.shell_steps = getattr(session, 'shell_steps', 0) + 1
        if request.op in ('room_action', 'network_action'):
            # The permit is spent HERE, under the op_lock and before anything is dispatched. Whatever happens next (success,
            # failure, timeout, a lost answer) it never comes back, so a room action runs at most once on its lease and a network
            # command at most once per step (eight in all).
            try:
                spent = self.leases.consume_action(lease.handle, uid)
            except proto.ProtocolError as exc:
                session.op_lock.release()
                return wire.error_response(exc.reason)
            if request.op == 'network_action':
                session.expected_step = spent.action_steps + 1  # the step this permit stands for; the runtime must answer exactly it
        return await asyncio.shield(self._spawn(self._run_operation(session, request)))

    def _room_action_body(self, raw, session):
        """Wire body of a room action: the lease's seven identity fields plus the runtime's nine keys, validated whole.

        The runtime answer must be exactly its nine keys; anything else, or any violation found by validate_room_action (bound to the
        lease identity and to the profile's pids limit), is an uncertain outcome. Nothing is inferred, completed or truncated here."""
        if not isinstance(raw, dict) or set(raw) != set(wire.ROOM_ACTION_KEYS):
            raise _Fail('internal_error')
        intent = session.intent
        identity = {'installation_id': self.inventory.installation_id, 'run_id': intent.run_id, 'level': intent.level,
                    'stage': intent.stage, 'context_sha256': intent.context_sha256, 'intent_id': intent.intent_id,
                    'container_id': intent.container_id}
        view = wire.validate_room_action({'ok': True, 'op': 'room_action', **identity, **{key: raw[key] for key in wire.ROOM_ACTION_KEYS}},
                                         identity=identity, pids_limit=session.pids_limit)
        return {**identity, **view}

    def _network_action_body(self, raw, session):
        """Wire body of a network action: the lease's seven identity fields plus the runtime's twelve keys, validated whole.

        `raw` must be exactly the twelve keys and its bundle_id must be the pin (the intent) BEFORE anything of the lease is mixed in.
        Any violation found by validate_network_action, bound to the identity, to the bundle and to the step of the permit just spent,
        is an uncertain outcome. Nothing is inferred, completed or truncated here, and no outcome or attribution is made."""
        intent = session.intent
        if not isinstance(raw, dict) or set(raw) != set(wire.NETWORK_ACTION_KEYS) or raw['bundle_id'] != intent.intent_id:
            raise _Fail('internal_error')
        identity = {'installation_id': self.inventory.installation_id, 'run_id': intent.run_id, 'level': intent.level,
                    'stage': intent.stage, 'context_sha256': intent.context_sha256, 'intent_id': intent.intent_id,
                    'container_id': intent.container_id}
        view = wire.validate_network_action({'ok': True, 'op': 'network_action', **identity, **raw},
                                            identity={**identity, 'bundle_id': intent.intent_id}, step_index=session.expected_step)
        return {**identity, **view}

    @staticmethod
    def _operation_reason(reason):
        if reason == 'timeout':
            return 'exec_timeout'
        return reason if reason in _PASS_REASONS else 'internal_error'

    async def _run_operation(self, session, request):
        failure = response = None
        try:
            try:
                if request.op == 'execute':
                    raw = await self._timed(self.runtime.execute(session.intent, request.command), 'execute')
                    body = wire.validate_result({'ok': True, 'op': 'execute', **_result_body(raw)}, op='execute')
                elif request.op == 'catalog_check':
                    # Fixed by the owner: the runtime gets the intent and nothing else (no path, script or index from the request).
                    # The probe it returns is already normalized (parse_catalog_probe ran once, in the runtime): it is validated,
                    # never parsed again, and a check_index that does not grow is a replay, not an observation.
                    raw = await self._timed(self.runtime.catalog_check(session.intent), 'probe')
                    identity = self._catalog_identity(session.intent)
                    if not isinstance(raw, dict) or set(raw) != {'probe', 'host_check', 'check_index'}:
                        raise _Fail('internal_error')
                    view = wire.validate_catalog_check({'ok': True, 'op': 'catalog_check', **identity, **raw}, identity=identity,
                                                       after=session.check_index)
                    session.check_index = view['check_index']
                    body = {**identity, **view}  # encoded below, with the response limit of `catalog_check`
                elif request.op == 'room_action':
                    # The permit is already spent. The runtime gets the intent and nothing else: no script, argument or selector.
                    raw = await self._timed(self.runtime.room_action(session.intent), 'room_action')
                    body = self._room_action_body(raw, session)
                elif request.op == 'network_action':
                    # The permit is already spent. The runtime gets the intent and the command and nothing else: no destination, probe
                    # script, resource name, option or token. Its twelve keys are judged whole before anything is published.
                    raw = await self._timed(self.runtime.network_action(session.intent, request.command), 'network_action')
                    body = self._network_action_body(raw, session)
                elif request.op == 'level_probe':
                    # Fixed by the owner: the runtime gets the intent, the name and the typed arguments of that name (none for
                    # cgroup_events, {path} or {sha256, size, exclude} for the persistence probes), never a script or another path.
                    raw = await self._timed(self.runtime.probe_level(session.intent, request.name, **_probe_arguments(request)),
                                            'probe')
                    body = wire.validate_level_probe({**_level_probe_body(raw, request.name), 'ok': True, 'op': 'level_probe'},
                                                     name=request.name, size=request.size)
                else:
                    raw = await self._timed(self.runtime.probe(session.intent, request.name), 'probe')
                    body = wire.validate_result({'ok': True, 'op': 'probe', **_result_body(raw, request.name)},
                                                op='probe', name=request.name)
                response = wire.encode_response(request.op, body)
            except _Fail as fail:
                failure = fail
            except wire.WireError:
                failure = _Fail('internal_error')
            except Exception:  # the action may have run: same treatment as any uncertain outcome
                failure = _Fail('internal_error')
        finally:
            session.op_lock.release()
        if failure is None:
            return response
        self._invalidate(session)  # uncertain outcome: the lease ends and the container is restituted; nothing is replayed
        return wire.error_response(self._operation_reason(failure.reason))

    # ------------------------------------------------------------------------------------------ recovery and serving

    async def reconcile(self):
        """Startup recovery (once, retried only for an unconfirmed restitution) and then the reaper of expired leases."""
        async with self._reconcile_gate:
            if self._shutdown:
                return
            if not self._recovered and self._blocked in (None, 'cleanup_unconfirmed'):
                await self._recover()
            if self._recovered:
                await self._reap()

    async def _recover(self):
        if self._blocked == 'cleanup_unconfirmed':
            self._blocked = None
        try:
            intent = self.inventory.pending()
        except Exception as exc:
            self._block(self._state_reason(exc))
            return
        try:
            ids = await self._timed(self.runtime.installed_ids(), 'ids')
        except _Fail:
            self._block('inventory_unavailable')
            return
        if not _ids_ok(ids):
            self._block('inventory_unavailable')
            return
        if intent is None:
            if ids:  # an object of the installation with no intent: evidence, not removal
                self._block('unrecognized_object')
                return
            self._intent, self._recovered = None, True
            return
        self._intent = intent
        if intent.container_id is None and getattr(intent, 'level', None) == proto.NETWORK_LEVEL:
            # M5: the preparation of a network may have been cut before the actor was ever requested. Only that, proven, ends here (no
            # create, start, exec, probe or action is ever issued); a requested actor without its ACK, or a role still PENDING, blocks.
            try:
                await self._restitute_preactor(intent, None)
            except _Unconfirmed as exc:
                self._block('create_uncertain' if exc.uncertain else 'cleanup_unconfirmed')  # the latter is retried by reconcile()
                return
            if self._blocked is None:
                self._recovered = True
            return
        if intent.container_id is None:  # PENDING without an ID: only an operator resolution under the diary contract clears it
            self._block('create_uncertain')
            return
        try:
            await self._restitute(intent, None)  # by recognized ID only; never create, start or exec
        except _Unconfirmed:
            self._block('cleanup_unconfirmed')
            return
        if self._blocked is None:
            self._recovered = True

    async def _reap(self):
        for lease in self.leases.pending_cleanup():
            session = self._sessions.get(lease.handle)
            if (session is None or session.opening or session.intent is None or session.intent.container_id is None):
                continue
            await asyncio.shield(self._close_task(session))

    async def _reaper(self):
        while True:
            await asyncio.sleep(self._reap_interval)
            with contextlib.suppress(Exception):
                await self.reconcile()

    async def _connection(self, reader, writer):
        self._connections += 1
        try:
            if self._connections > MAX_CONNECTIONS:
                return
            try:
                uid = wire.peer_uid(writer.get_extra_info('socket'))
            except wire.WireError:
                return
            if uid != self._client_uid:
                return  # closed without reading or answering
            try:
                raw = await wire.read_frame_async(reader.read, limit=wire.MAX_REQUEST_BYTES, timeout=self._read_timeout)
            except wire.WireError:
                response = wire.error_response('framing')
            else:
                response = await self.handle(uid, raw)  # dispatch only after the frame and its EOF
            if response is None:
                return
            writer.write(wire.encode_frame(response, limit=wire.MAX_RESPONSE_BYTES))
            await writer.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            self._connections -= 1
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def serve(self):
        if self._socket_path is None:
            raise ValueError('socket path required to serve')
        await self.reconcile()
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            listener.bind(self._socket_path)
            observed = os.stat(self._socket_path)
            self.socket_identity = (observed.st_dev, observed.st_ino)
            os.chmod(self._socket_path, self._socket_mode)
            listener.setblocking(False)
            # Passing an already-bound socket avoids asyncio's automatic removal of a pathname.
            server = await asyncio.start_server(self._connection, sock=listener)
        except BaseException:
            listener.close()
            raise
        reaper = None
        try:
            reaper = asyncio.create_task(self._reaper())
            await server.serve_forever()
        finally:
            self._shutdown = True
            if reaper is not None:
                reaper.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reaper
            server.close()
            await server.wait_closed()
            pending = set(self._tasks)
            if pending:
                await asyncio.wait(pending, timeout=self._limits.close + 5)  # whatever is left stays durable for recovery
