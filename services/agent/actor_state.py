"""Durable state of one invoice actor owner. Docker operations belong to the owner."""

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field, replace
import json
import os
import sqlite3
import sys
import uuid

from . import guard_state as storage, missions


SCHEMA = 'actor-recovery/v1'
LEVEL_SCHEMA = 'actor-recovery/v2'
PERSISTENCE_SCHEMA = 'actor-recovery/v3'
CATALOG_SCHEMA = 'actor-recovery/v4'
ROOM_SCHEMA = 'actor-recovery/v5'
NETWORK_SCHEMA = 'actor-recovery/v6'
NETWORK_ROLES = ('network', 'canary', 'verifier')
CATALOG_EVENTS = frozenset({'CATALOG_PREPARE_PENDING', 'CATALOG_READY', 'CATALOG_RELEASE_PENDING', 'CATALOG_RELEASED'})
LEVELS = ('memory', 'secret', 'persistence', 'processes', 'privileges', 'network')
StateError = storage.StateError
INSTALLATION_SQL = (
    'CREATE TABLE installation (singleton INTEGER PRIMARY KEY CHECK(singleton=1), '
    'schema TEXT NOT NULL, installation_id TEXT NOT NULL, guard_uid INTEGER NOT NULL, '
    'client_uid INTEGER NOT NULL, docker_id TEXT NOT NULL, docker_root TEXT NOT NULL, '
    'image_id TEXT NOT NULL, profile_sha256 TEXT NOT NULL, event_count INTEGER NOT NULL CHECK(event_count>=0))'
)
PREVIOUS = {
    'CREATE_ACK': ('CREATE_PENDING',), 'START_PENDING': ('CREATE_ACK',),
    'ACTIVE': ('START_PENDING',), 'CLOSE_PENDING': ('CREATE_ACK', 'START_PENDING', 'ACTIVE'),
    'FINISH': ('CLOSE_PENDING',),
}


@dataclass(frozen=True)
class ActorIntent:
    intent_id: str
    name: str
    controller_uid: int
    run_id: str
    variant: str
    container_id: str | None
    phase: str
    profile_sha256: str


@dataclass(frozen=True)
class LevelPredecessor:
    installation_id: str
    run_id: str
    level: str
    stage: str
    context_sha256: str
    intent_id: str
    container_id: str


@dataclass(frozen=True)
class CgroupAnchor:
    parts: tuple
    device: int
    inode: int
    root_device: int
    root_inode: int
    boot_id: str


@dataclass(frozen=True)
class NetworkResource:
    role: str
    name: str
    phase: str
    resource_id: str | None = None


@dataclass(frozen=True)
class LevelIntent:
    intent_id: str
    name: str
    controller_uid: int
    run_id: str
    level: str
    stage: str
    context_sha256: str
    container_id: str | None
    phase: str
    profile_sha256: str
    predecessor: LevelPredecessor | None = None
    cgroup_anchor: CgroupAnchor | None = field(default=None, repr=False)  # never wire/log repr
    start_requested: bool = False
    network_resources: tuple = field(default=(), repr=False)
    actor_requested: bool = False
    actor_absent: bool = False

    @property
    def bundle_id(self):
        return self.intent_id if self.level == 'network' else None


@dataclass(frozen=True)
class CatalogIntent:
    intent_id: str
    name: str
    controller_uid: int
    run_id: str
    variant: str
    catalog_profile: str
    context_sha256: str
    catalog_id: str
    catalog_sha256: str
    container_id: str | None
    phase: str
    profile_sha256: str
    resource_id: str  # owner-only reference; not a host path or a client authority


@dataclass(frozen=True, repr=False)
class CatalogRegistration:
    installation_id: str
    resource_id: str
    parent_directory: str
    parent_identity: tuple
    catalog_profile_sha256: str
    phase: str
    directory_identity: tuple | None = None
    file_identity: tuple | None = None

    @property
    def directory(self):
        return os.path.join(self.parent_directory, 'catalog-' + self.installation_id)

    @property
    def source_path(self):
        return os.path.join(self.directory, 'catalog.json')

    def __repr__(self):
        return 'CatalogRegistration(resource_id=%s, phase=%s)' % (self.resource_id, self.phase)


def valid_level_stage(level, stage):
    return level in LEVELS and (stage == 'actor' or (level == 'persistence' and stage == 'fresh'))


def valid_predecessor(intent, installation_id):
    """Validate the closed predecessor identity; durable ordering is checked by the diary."""
    previous = intent.predecessor
    if intent.stage != 'fresh':
        return previous is None
    return (intent.level == 'persistence' and isinstance(previous, LevelPredecessor)
        and previous.installation_id == installation_id and previous.run_id == intent.run_id
        and previous.context_sha256 == intent.context_sha256
        and previous.level == 'persistence' and previous.stage == 'actor'
        and storage._matches(storage.HEX32, previous.intent_id) and previous.intent_id != intent.intent_id
        and storage._matches(storage.HEX64, previous.container_id)
        and previous.container_id != intent.container_id)


def level_predecessor(installation_id, intent):
    if (not isinstance(intent, LevelIntent) or intent.level != 'persistence' or intent.stage != 'actor'
            or intent.phase != 'FINISH' or not storage._matches(storage.HEX64, intent.container_id)):
        raise StateError('predecessor_unconfirmed')
    return LevelPredecessor(installation_id, intent.run_id, intent.level, intent.stage,
                            intent.context_sha256, intent.intent_id, intent.container_id)


def _start_key(intent):
    if isinstance(intent, CatalogIntent):
        return ('catalog', intent.controller_uid, intent.run_id, intent.variant)
    if isinstance(intent, LevelIntent):
        return ('level', intent.controller_uid, intent.run_id, intent.level, intent.stage)
    return ('workflow', intent.controller_uid, intent.run_id, intent.variant)


def _receipt_key(intent):
    if isinstance(intent, CatalogIntent):
        return _start_key(intent) + (intent.catalog_profile, intent.context_sha256, intent.catalog_id,
            intent.catalog_sha256, intent.intent_id, intent.container_id)
    if isinstance(intent, LevelIntent):
        return _start_key(intent) + (intent.context_sha256, intent.intent_id, intent.container_id)
    return (intent.controller_uid, intent.run_id, intent.variant, intent.intent_id, intent.container_id)


class ActorInventory:
    def __init__(self, db, db_fd, dir_fd, installation_id, identity):
        self._db, self._db_fd, self._dir_fd = db, db_fd, dir_fd
        self.installation_id = installation_id
        self._identity = identity
        self._unavailable = False
        self._closed = False
        self._history()

    def _metadata(self):
        layout = self._db.execute('SELECT name, sql FROM sqlite_master ORDER BY name').fetchall()
        if layout != [('events', storage.EVENTS_SQL), ('installation', INSTALLATION_SQL)]:
            raise StateError('state_corrupt')
        rows = self._db.execute('SELECT * FROM installation').fetchall()
        if len(rows) != 1:
            raise StateError('state_corrupt')
        singleton, schema, installation, *values, count = rows[0]
        if (singleton != 1 or schema not in (SCHEMA, LEVEL_SCHEMA, PERSISTENCE_SCHEMA, CATALOG_SCHEMA, ROOM_SCHEMA, NETWORK_SCHEMA) or not storage._matches(storage.HEX32, installation)
                or type(count) is not int or not 0 <= count <= storage.MAX_EVENTS):
            raise StateError('state_corrupt')
        if installation != self.installation_id or tuple(values) != self._identity:
            raise StateError('identity_changed')
        self._schema = schema
        return installation, count

    def _resource_event(self, previous, kind, payload):
        if self._schema not in (CATALOG_SCHEMA, ROOM_SCHEMA, NETWORK_SCHEMA) or not isinstance(payload, dict):
            raise StateError('invalid_transition')
        if kind == 'CATALOG_PREPARE_PENDING':
            if previous is not None:
                raise StateError('catalog_resource_exists')
            if (set(payload) != {'resource_id', 'parent_directory', 'parent_identity', 'catalog_profile_sha256'}
                    or not storage._matches(storage.HEX32, payload['resource_id'])
                    or not storage._matches(storage.HEX64, payload['catalog_profile_sha256'])):
                raise StateError('invalid_transition')
            parent = payload['parent_directory']
            if (not isinstance(parent, str) or not 1 < len(parent) <= 1024 or not os.path.isabs(parent)
                    or os.path.normpath(parent) != parent or any(ord(c) < 32 or c in ',\"\'' for c in parent)):
                raise StateError('invalid_transition')
            identity = self._directory_identity(payload['parent_identity'])
            return CatalogRegistration(self.installation_id, payload['resource_id'], parent, identity,
                payload['catalog_profile_sha256'], kind)
        if previous is None or payload.get('resource_id') != previous.resource_id:
            raise StateError('invalid_transition')
        if kind == 'CATALOG_READY':
            if (previous.phase != 'CATALOG_PREPARE_PENDING'
                    or set(payload) != {'resource_id', 'directory_identity', 'file_identity'}):
                raise StateError('invalid_transition')
            directory = self._directory_identity(payload['directory_identity'])
            info = payload['file_identity']
            if (not isinstance(info, (list, tuple)) or len(info) != 8
                    or any(type(value) is not int or not 0 <= value < 2**64 for value in info)
                    or info[1] == 0 or info[2] != len(missions.CATALOG_BYTES) or info[5] != 1
                    or info[6] != self._identity[0] or info[7] != 0o444
                    or tuple(info[:2]) == directory[:2] or directory[:2] == previous.parent_identity[:2]):
                raise StateError('invalid_transition')
            return replace(previous, phase=kind, directory_identity=directory, file_identity=tuple(info))
        required = 'CATALOG_READY' if kind == 'CATALOG_RELEASE_PENDING' else 'CATALOG_RELEASE_PENDING'
        if (kind not in ('CATALOG_RELEASE_PENDING', 'CATALOG_RELEASED') or previous.phase != required
                or set(payload) != {'resource_id'}):
            raise StateError('invalid_transition')
        return replace(previous, phase=kind)

    def _directory_identity(self, value):
        if (not isinstance(value, (list, tuple)) or len(value) != 4
                or any(type(item) is not int or not 0 <= item < 2**64 for item in value)
                or value[1] == 0 or value[2] != self._identity[0] or value[3] != 0o700):
            raise StateError('invalid_transition')
        return tuple(value)

    def _new_intent(self, payload, resource=None):
        if isinstance(payload, dict) and 'catalog_profile' in payload:
            fields = {'intent_id', 'controller_uid', 'run_id', 'variant', 'catalog_profile', 'context_sha256',
                'catalog_id', 'catalog_sha256', 'profile_sha256', 'resource_id'}
            if (self._schema not in (CATALOG_SCHEMA, ROOM_SCHEMA, NETWORK_SCHEMA) or set(payload) != fields or resource is None
                    or resource.phase != 'CATALOG_READY' or payload['resource_id'] != resource.resource_id
                    or not storage._matches(storage.HEX32, payload['intent_id'])
                    or type(payload['controller_uid']) is not int or payload['controller_uid'] != self._identity[1]
                    or not storage._matches(storage.HEX32, payload['run_id'])
                    or payload['variant'] not in ('legitimate', 'perturbed') or payload['catalog_profile'] not in ('A', 'B')
                    or not storage._matches(storage.HEX64, payload['context_sha256'])
                    or payload['catalog_id'] != missions.CATALOG_ID or payload['catalog_sha256'] != missions.CATALOG_SHA256
                    or payload['profile_sha256'] != (self._identity[-1] if payload['catalog_profile'] == 'A' else resource.catalog_profile_sha256)):
                raise StateError('invalid_transition')
            return CatalogIntent(payload['intent_id'], 'escape-actor-' + payload['intent_id'], payload['controller_uid'],
                payload['run_id'], payload['variant'], payload['catalog_profile'], payload['context_sha256'],
                payload['catalog_id'], payload['catalog_sha256'], None, 'CREATE_PENDING', payload['profile_sha256'], resource.resource_id)
        if isinstance(payload, dict) and 'level' in payload:
            fields = {'intent_id', 'controller_uid', 'run_id', 'level', 'stage', 'context_sha256'}
            fresh = payload.get('level') == 'persistence' and payload.get('stage') == 'fresh'
            if fresh:
                fields.add('predecessor')
            if (self._schema not in (LEVEL_SCHEMA, PERSISTENCE_SCHEMA, CATALOG_SCHEMA, ROOM_SCHEMA, NETWORK_SCHEMA) or set(payload) != fields
                    or not storage._matches(storage.HEX32, payload['intent_id'])
                    or type(payload['controller_uid']) is not int or payload['controller_uid'] != self._identity[1]
                    or not storage._matches(storage.HEX32, payload['run_id']) or payload['level'] not in LEVELS
                    or not valid_level_stage(payload['level'], payload['stage'])
                    or (payload['level'] == 'persistence' and self._schema not in (PERSISTENCE_SCHEMA, CATALOG_SCHEMA, ROOM_SCHEMA, NETWORK_SCHEMA))
                    or (payload['level'] in ('processes', 'privileges') and self._schema not in (ROOM_SCHEMA, NETWORK_SCHEMA))
                    or (payload['level'] == 'network' and self._schema != NETWORK_SCHEMA)
                    or not storage._matches(storage.HEX64, payload['context_sha256'])):
                raise StateError('invalid_transition')
            previous = None
            if fresh:
                raw = payload['predecessor']
                if not isinstance(raw, dict) or set(raw) != set(LevelPredecessor.__dataclass_fields__):
                    raise StateError('invalid_transition')
                previous = LevelPredecessor(**raw)
            intent = LevelIntent(payload['intent_id'], 'escape-actor-' + payload['intent_id'], payload['controller_uid'],
                payload['run_id'], payload['level'], payload['stage'], payload['context_sha256'], None, 'CREATE_PENDING', self._identity[-1], previous)
            if not valid_predecessor(intent, self.installation_id):
                raise StateError('invalid_transition')
            return intent
        if not isinstance(payload, dict) or set(payload) != {'intent_id', 'controller_uid', 'run_id', 'variant'}:
            raise StateError('invalid_transition')
        intent_id, uid, run_id, variant = (payload[key] for key in ('intent_id', 'controller_uid', 'run_id', 'variant'))
        if (not storage._matches(storage.HEX32, intent_id) or type(uid) is not int or uid != self._identity[1]
                or not storage._matches(storage.HEX32, run_id) or variant not in ('legitimate', 'perturbed')):
            raise StateError('invalid_transition')
        return ActorIntent(intent_id, f'escape-actor-{intent_id}', uid, run_id, variant, None,
                           'CREATE_PENDING', self._identity[-1])

    def _network_event(self, current, kind, payload):
        if (self._schema != NETWORK_SCHEMA or not isinstance(current, LevelIntent) or current.level != 'network'
                or not isinstance(payload, dict) or payload.get('intent_id') != current.intent_id):
            raise StateError('invalid_transition')
        records = current.network_resources
        if kind == 'NETWORK_ACTOR_ABSENT':
            if (set(payload) != {'intent_id', 'container_id'} or current.phase != 'CLOSE_PENDING'
                    or payload['container_id'] != current.container_id
                    or (current.actor_requested and current.container_id is None)):
                raise StateError('invalid_transition')
            return replace(current, actor_absent=True)
        if kind == 'NETWORK_ACTOR_PENDING':
            if (set(payload) != {'intent_id'} or current.phase != 'CREATE_PENDING' or current.actor_requested
                    or tuple(r.role for r in records) != NETWORK_ROLES or any(r.phase != 'ACK' for r in records)):
                raise StateError('invalid_transition')
            return replace(current, actor_requested=True)
        fields = {'intent_id', 'role'} | ({'resource_id'} if kind != 'NETWORK_PENDING' else set())
        role = payload.get('role')
        if set(payload) != fields or role not in NETWORK_ROLES:
            raise StateError('invalid_transition')
        if kind == 'NETWORK_PENDING':
            if (current.phase != 'CREATE_PENDING' or current.actor_requested or len(records) >= 3
                    or role != NETWORK_ROLES[len(records)] or any(r.phase != 'ACK' for r in records)):
                raise StateError('invalid_transition')
            return replace(current, network_resources=records + (NetworkResource(role,
                'escape-net-' + current.intent_id + '-' + role, 'PENDING'),))
        selected = [r for r in records if r.role == role]
        if len(selected) != 1 or not storage._matches(storage.HEX64, payload['resource_id']):
            raise StateError('invalid_transition')
        previous = selected[0]
        if kind == 'NETWORK_ACK':
            if (current.phase != 'CREATE_PENDING' or current.actor_requested or previous.phase != 'PENDING'
                    or any(r.resource_id == payload['resource_id'] for r in records)):
                raise StateError('invalid_transition')
            new = replace(previous, phase='ACK', resource_id=payload['resource_id'])
        elif kind == 'NETWORK_ABSENT':
            if (current.phase != 'CLOSE_PENDING' or previous.phase not in ('ACK', 'ABSENT')
                    or previous.resource_id != payload['resource_id']):
                raise StateError('invalid_transition')
            new = replace(previous, phase='ABSENT')
        else:
            raise StateError('invalid_transition')
        return replace(current, network_resources=tuple(new if r.role == role else r for r in records))

    def _advance(self, current, kind, payload):
        if kind in ('NETWORK_PENDING', 'NETWORK_ACK', 'NETWORK_ABSENT', 'NETWORK_ACTOR_PENDING', 'NETWORK_ACTOR_ABSENT'):
            return self._network_event(current, kind, payload)
        if kind == 'ROOM_CGROUP_ANCHOR':
            from . import runner
            if (self._schema not in (ROOM_SCHEMA, NETWORK_SCHEMA) or not isinstance(current, LevelIntent) or current.level != 'processes'
                    or current.phase not in ('START_PENDING', 'ACTIVE', 'CLOSE_PENDING') or current.cgroup_anchor is not None
                    or not isinstance(payload, dict) or set(payload) != {'intent_id', 'anchor'}
                    or payload['intent_id'] != current.intent_id or not isinstance(payload['anchor'], dict)
                    or set(payload['anchor']) != set(CgroupAnchor.__dataclass_fields__)):
                raise StateError('invalid_transition')
            raw = payload['anchor']
            parts = raw['parts']
            if (not isinstance(parts, (tuple, list)) or any(type(part) is not str for part in parts)
                    or runner.parse_cgroup_membership('0::/' + '/'.join(parts), current.container_id) is None
                    or any(type(raw[key]) is not int or not 0 < raw[key] < 2**64 for key in ('device', 'inode', 'root_device', 'root_inode'))
                    or not isinstance(raw['boot_id'], str)
                    or runner.re.fullmatch(r'[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}', raw['boot_id']) is None):
                raise StateError('invalid_transition')
            if len(json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False)) > storage.MAX_PAYLOAD:
                raise StateError('invalid_transition')
            return replace(current, cgroup_anchor=CgroupAnchor(**{**raw, 'parts': tuple(parts)}))
        before_actor_close = (isinstance(current, LevelIntent) and current.level == 'network'
                              and current.phase == 'CREATE_PENDING' and kind == 'CLOSE_PENDING')
        if (current is None or kind not in PREVIOUS or (current.phase not in PREVIOUS[kind] and not before_actor_close)
                or not isinstance(payload, dict) or payload.get('intent_id') != current.intent_id):
            raise StateError('invalid_transition')
        fields = {'intent_id', 'container_id'} if kind in ('CREATE_ACK', 'FINISH') else {'intent_id'}
        container = payload.get('container_id', current.container_id)
        network = isinstance(current, LevelIntent) and current.level == 'network'
        no_actor = network and current.container_id is None and kind in ('CLOSE_PENDING', 'FINISH') and container is None
        if set(payload) != fields or (not no_actor and not storage._matches(storage.HEX64, container)):
            raise StateError('invalid_transition')
        if network:
            if kind == 'CREATE_ACK' and (not current.actor_requested or any(r.resource_id == container for r in current.network_resources)):
                raise StateError('invalid_transition')
            if kind == 'FINISH' and (not current.actor_absent or any(r.phase != 'ABSENT' for r in current.network_resources)
                    or (current.actor_requested and (container is None or len(current.network_resources) != 3))):
                raise StateError('invalid_transition')
        if kind == 'FINISH' and container != current.container_id:
            raise StateError('invalid_transition')
        if isinstance(current, LevelIntent) and current.predecessor is not None and container == current.predecessor.container_id:
            raise StateError('invalid_transition')
        extra = {'start_requested': True} if kind == 'START_PENDING' and isinstance(current, LevelIntent) else {}
        return replace(current, phase=kind, container_id=container, **extra)

    def _history(self, *, match=None):
        _, count = self._metadata()
        current, finished, used, ids, completed, resource = None, None, {}, set(), {}, None
        events = self._db.execute('SELECT sequence, kind, payload FROM events ORDER BY sequence LIMIT ?',
                                  (storage.MAX_EVENTS + 1,)).fetchall()
        if len(events) != count:
            raise StateError('state_corrupt')
        try:
            for ordinal, (sequence, kind, raw) in enumerate(events, 1):
                if sequence != ordinal:
                    raise StateError('state_corrupt')
                payload = storage._json_payload(raw)
                if kind in CATALOG_EVENTS:
                    if current is not None:
                        raise StateError('state_corrupt')
                    resource = self._resource_event(resource, kind, payload)
                    continue
                if kind == 'CREATE_PENDING' and current is None:
                    current = self._new_intent(payload, resource)
                    key = _start_key(current)
                    if key in used or current.intent_id in ids:
                        raise StateError('state_corrupt')
                    context = current.context_sha256 if isinstance(current, (LevelIntent, CatalogIntent)) else None
                    if context is not None and any(k[:3] == key[:3] and value != context for k, value in used.items()):
                        raise StateError('state_corrupt')
                    if isinstance(current, LevelIntent) and current.stage == 'fresh':
                        actor = completed.get(('level', current.controller_uid, current.run_id, 'persistence', 'actor'))
                        if actor is None or current.predecessor != level_predecessor(self.installation_id, actor):
                            raise StateError('state_corrupt')
                    used[key] = context
                    ids.add(current.intent_id)
                else:
                    current = self._advance(current, kind, payload)
                    if kind == 'FINISH':
                        identity = _receipt_key(current)
                        if match is None or identity == match:
                            finished = current
                        completed[_start_key(current)] = current
                        current = None
        except StateError as exc:
            raise StateError('state_corrupt') from exc
        if self._schema == CATALOG_SCHEMA and resource is None:
            raise StateError('state_corrupt')
        return current, finished, used, ids, count, completed, resource

    def _check(self):
        if self._closed or self._unavailable:
            raise StateError('state_unavailable')

    def pending(self):
        self._check()
        try:
            return self._history()[0]
        except (StateError, sqlite3.Error, OSError) as exc:
            self._unavailable = True
            raise StateError('state_unavailable') from exc

    def receipt(self, *, controller_uid, run_id, variant, intent_id, container_id):
        """Read an exact durable FINISH, including older completed runs. Never mutates state."""
        self._check()
        if (type(controller_uid) is not int or controller_uid != self._identity[1]
                or not storage._matches(storage.HEX32, run_id) or variant not in ('legitimate', 'perturbed')
                or not storage._matches(storage.HEX32, intent_id)
                or not storage._matches(storage.HEX64, container_id)):
            raise StateError('identity_changed')
        try:
            return self._history(match=(controller_uid, run_id, variant, intent_id, container_id))[1]
        except (StateError, sqlite3.Error, OSError) as exc:
            self._unavailable = True
            raise StateError('state_unavailable') from exc

    def receipt_level(self, *, controller_uid, run_id, level, stage, context_sha256, intent_id, container_id):
        """Read only an exact level FINISH, including old records in a mixed M1/M2 diary."""
        self._check()
        if (type(controller_uid) is not int or controller_uid != self._identity[1]
                or not storage._matches(storage.HEX32, run_id) or not valid_level_stage(level, stage)
                or not storage._matches(storage.HEX64, context_sha256)
                or not storage._matches(storage.HEX32, intent_id) or not storage._matches(storage.HEX64, container_id)):
            raise StateError('identity_changed')
        try:
            return self._history(match=('level', controller_uid, run_id, level, stage, context_sha256, intent_id, container_id))[1]
        except (StateError, sqlite3.Error, OSError) as exc:
            self._unavailable = True
            raise StateError('state_unavailable') from exc

    def catalog_resource(self):
        """Private owner-only registration, never a wire response; does not prepare or repair a file."""
        self._check()
        try:
            return self._history()[6]
        except (StateError, sqlite3.Error, OSError) as exc:
            self._unavailable = True
            raise StateError('state_unavailable') from exc

    def receipt_catalog(self, *, controller_uid, run_id, variant, catalog_profile, context_sha256,
                        catalog_id, catalog_sha256, intent_id, container_id):
        self._check()
        if (type(controller_uid) is not int or controller_uid != self._identity[1]
                or not storage._matches(storage.HEX32, run_id) or variant not in ('legitimate', 'perturbed')
                or catalog_profile not in ('A', 'B') or not storage._matches(storage.HEX64, context_sha256)
                or catalog_id != missions.CATALOG_ID or catalog_sha256 != missions.CATALOG_SHA256
                or not storage._matches(storage.HEX32, intent_id) or not storage._matches(storage.HEX64, container_id)):
            raise StateError('identity_changed')
        try:
            return self._history(match=('catalog', controller_uid, run_id, variant, catalog_profile,
                context_sha256, catalog_id, catalog_sha256, intent_id, container_id))[1]
        except (StateError, sqlite3.Error, OSError) as exc:
            self._unavailable = True
            raise StateError('state_unavailable') from exc

    def _record(self, kind, payload):
        self._check()
        try:
            with self._db:
                self._db.execute('BEGIN IMMEDIATE')
                current, finished, used, ids, count, completed, resource = self._history()
                if kind in CATALOG_EVENTS:
                    if current is not None: raise StateError('actor_busy')
                    if kind == 'CATALOG_PREPARE_PENDING' and self._schema not in (CATALOG_SCHEMA, ROOM_SCHEMA, NETWORK_SCHEMA):
                        self._db.execute('UPDATE installation SET schema=? WHERE singleton=1', (CATALOG_SCHEMA,))
                        self._schema = CATALOG_SCHEMA
                    next_intent = self._resource_event(resource, kind, payload)
                elif kind == 'CREATE_PENDING':
                    if isinstance(payload, dict) and 'catalog_profile' in payload:
                        if resource is None or resource.phase != 'CATALOG_READY':
                            raise StateError('catalog_unavailable')
                        if set(payload) != {'intent_id', 'controller_uid', 'run_id', 'variant', 'catalog_profile',
                                'context_sha256', 'catalog_id', 'catalog_sha256'}:
                            raise StateError('invalid_transition')
                        payload = {**payload, 'resource_id': resource.resource_id,
                            'profile_sha256': self._identity[-1] if payload['catalog_profile'] == 'A' else resource.catalog_profile_sha256}
                    # Version and the first level intention commit atomically. Unknown schemas never reach this point.
                    if isinstance(payload, dict) and 'level' in payload:
                        target = NETWORK_SCHEMA if payload['level'] == 'network' else ROOM_SCHEMA if payload['level'] in ('processes', 'privileges') else PERSISTENCE_SCHEMA if payload['level'] == 'persistence' else LEVEL_SCHEMA
                        versions = (SCHEMA, LEVEL_SCHEMA, PERSISTENCE_SCHEMA, CATALOG_SCHEMA, ROOM_SCHEMA, NETWORK_SCHEMA)
                        if versions.index(self._schema) < versions.index(target):
                            self._db.execute('UPDATE installation SET schema=? WHERE singleton=1', (target,))
                            self._schema = target
                        if payload.get('level') == 'persistence' and payload.get('stage') == 'fresh':
                            if (set(payload) != {'intent_id', 'controller_uid', 'run_id', 'level', 'stage', 'context_sha256'}
                                    or type(payload['controller_uid']) is not int or payload['controller_uid'] != self._identity[1]
                                    or not storage._matches(storage.HEX32, payload['run_id'])
                                    or not storage._matches(storage.HEX64, payload['context_sha256'])):
                                raise StateError('invalid_transition')
                            if current is not None:
                                raise StateError('actor_busy')
                            key = ('level', payload['controller_uid'], payload['run_id'], 'persistence', 'fresh')
                            if key in used:
                                raise StateError('already_started')
                            actor = completed.get(key[:-1] + ('actor',))
                            if actor is None:
                                raise StateError('predecessor_unconfirmed')
                            if actor.context_sha256 != payload['context_sha256']:
                                raise StateError('invalid_transition')
                            payload = {**payload, 'predecessor': asdict(level_predecessor(self.installation_id, actor))}
                    next_intent = self._new_intent(payload, resource)
                    if current is not None:
                        raise StateError('actor_busy')
                    key = _start_key(next_intent)
                    if key in used:
                        raise StateError('already_started')
                    if isinstance(next_intent, (LevelIntent, CatalogIntent)) and any(
                            k[:3] == key[:3] and context != next_intent.context_sha256 for k, context in used.items()):
                        raise StateError('invalid_transition')
                    if next_intent.intent_id in ids:
                        raise StateError('state_unavailable')
                elif kind == 'CLOSE_PENDING' and current is not None and current.phase == kind and payload['intent_id'] == current.intent_id:
                    return current
                elif kind == 'FINISH' and current is None and finished is not None and payload == {
                    'intent_id': finished.intent_id, 'container_id': finished.container_id,
                }:
                    return finished
                else:
                    next_intent = self._advance(current, kind, payload)
                if count == storage.MAX_EVENTS:
                    raise StateError('state_unavailable')
                raw = json.dumps(payload, sort_keys=True, separators=(',', ':'), allow_nan=False)
                self._db.execute('INSERT INTO events VALUES (?,?,?)', (count + 1, kind, raw))
                self._db.execute('UPDATE installation SET event_count=? WHERE singleton=1', (count + 1,))
            os.fsync(self._db_fd)
            os.fsync(self._dir_fd)
        except StateError as exc:
            if exc.code not in ('invalid_transition', 'actor_busy', 'already_started', 'predecessor_unconfirmed',
                                'catalog_unavailable', 'catalog_resource_exists'):
                self._unavailable = True
            raise
        except (sqlite3.Error, OSError) as exc:
            self._unavailable = True
            raise StateError('state_unavailable') from exc
        return next_intent

    def begin(self, *, controller_uid, run_id, variant):
        return self._record('CREATE_PENDING', {'intent_id': uuid.uuid4().hex, 'controller_uid': controller_uid,
                                               'run_id': run_id, 'variant': variant})

    def begin_level(self, *, controller_uid, run_id, level, stage, context_sha256):
        return self._record('CREATE_PENDING', {'intent_id': uuid.uuid4().hex, 'controller_uid': controller_uid,
            'run_id': run_id, 'level': level, 'stage': stage, 'context_sha256': context_sha256})

    def begin_catalog(self, *, controller_uid, run_id, variant, catalog_profile, context_sha256, catalog_id, catalog_sha256):
        return self._record('CREATE_PENDING', {'intent_id': uuid.uuid4().hex, 'controller_uid': controller_uid,
            'run_id': run_id, 'variant': variant, 'catalog_profile': catalog_profile, 'context_sha256': context_sha256,
            'catalog_id': catalog_id, 'catalog_sha256': catalog_sha256})

    def begin_catalog_resource(self, *, parent_directory, parent_identity, catalog_profile_sha256):
        return self._record('CATALOG_PREPARE_PENDING', {'resource_id': uuid.uuid4().hex,
            'parent_directory': parent_directory, 'parent_identity': list(parent_identity),
            'catalog_profile_sha256': catalog_profile_sha256})

    def ready_catalog_resource(self, resource_id, *, directory_identity, file_identity):
        return self._record('CATALOG_READY', {'resource_id': resource_id,
            'directory_identity': list(directory_identity), 'file_identity': list(file_identity)})

    def releasing_catalog_resource(self, resource_id):
        return self._record('CATALOG_RELEASE_PENDING', {'resource_id': resource_id})

    def released_catalog_resource(self, resource_id):
        return self._record('CATALOG_RELEASED', {'resource_id': resource_id})

    def ack(self, intent_id, container_id):
        return self._record('CREATE_ACK', {'intent_id': intent_id, 'container_id': container_id})

    def starting(self, intent_id):
        return self._record('START_PENDING', {'intent_id': intent_id})

    def activate(self, intent_id):
        return self._record('ACTIVE', {'intent_id': intent_id})

    def closing(self, intent_id):
        return self._record('CLOSE_PENDING', {'intent_id': intent_id})

    def anchor_cgroup(self, intent_id, anchor):
        """Persist the owner-observed node before any room load; never a client path."""
        return self._record('ROOM_CGROUP_ANCHOR', {'intent_id': intent_id, 'anchor': anchor})

    def begin_network_resource(self, intent_id, role):
        return self._record('NETWORK_PENDING', {'intent_id': intent_id, 'role': role})

    def ack_network_resource(self, intent_id, role, resource_id):
        return self._record('NETWORK_ACK', {'intent_id': intent_id, 'role': role, 'resource_id': resource_id})

    def absent_network_resource(self, intent_id, role, resource_id):
        return self._record('NETWORK_ABSENT', {'intent_id': intent_id, 'role': role, 'resource_id': resource_id})

    def requesting_network_actor(self, intent_id):
        return self._record('NETWORK_ACTOR_PENDING', {'intent_id': intent_id})

    def absent_network_actor(self, intent_id, container_id):
        return self._record('NETWORK_ACTOR_ABSENT', {'intent_id': intent_id, 'container_id': container_id})

    def finish(self, intent_id, *, container_id):
        """The owner must prove absence of the recognized container before calling this method."""
        return self._record('FINISH', {'intent_id': intent_id, 'container_id': container_id})


@contextmanager
def open_actor_inventory(directory, *, installation_id, owner_uid, controller_uid, docker_id, docker_root,
                         image_id, profile_sha256, initialize=False):
    if sys.platform != 'linux':
        raise StateError('state_unsupported_platform')
    identity = storage._identity(owner_uid, controller_uid, docker_id, docker_root)
    if (not storage._matches(storage.HEX32, installation_id)
            or not isinstance(image_id, str) or not image_id.startswith('sha256:')
            or not storage._matches(storage.HEX64, image_id[7:])
            or not storage._matches(storage.HEX64, profile_sha256)):
        raise StateError('identity_changed')
    identity += (image_id, profile_sha256)
    db = inventory = dir_fd = lock_fd = db_fd = None
    try:
        path = storage._directory(directory, owner_uid)
        dir_fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        names = set(os.listdir(dir_fd))
        if initialize and names:
            raise StateError('state_initialization_exists')
        if not initialize:
            storage._check_files(path, owner_uid)
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC
        if initialize:
            flags |= os.O_CREAT | os.O_EXCL
        lock_fd = os.open(storage.LOCK, flags, 0o600, dir_fd=dir_fd)
        storage._file(os.fstat(lock_fd), owner_uid)
        try:
            storage.fcntl.flock(lock_fd, storage.fcntl.LOCK_EX | storage.fcntl.LOCK_NB)
        except BlockingIOError:
            raise StateError('state_locked') from None
        db_fd = os.open(storage.DATABASE, flags, 0o600, dir_fd=dir_fd)
        storage._file(os.fstat(db_fd), owner_uid)
        for descriptor, name in ((lock_fd, storage.LOCK), (db_fd, storage.DATABASE)):
            held, named = os.fstat(descriptor), (path / name).lstat()
            if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
                raise StateError('state_file_invalid')
        db = sqlite3.connect((path / storage.DATABASE).as_uri() + '?mode=rw', uri=True, timeout=0)
        if db.execute('PRAGMA journal_mode=DELETE').fetchone() != ('delete',):
            raise StateError('state_unavailable')
        db.execute('PRAGMA synchronous=EXTRA')
        if db.execute('PRAGMA synchronous').fetchone() != (3,):
            raise StateError('state_unavailable')
        page_size = db.execute('PRAGMA page_size').fetchone()[0]
        db.execute(f'PRAGMA max_page_count={storage.MAX_BYTES // page_size}')
        if initialize:
            with db:
                db.execute(INSTALLATION_SQL)
                db.execute(storage.EVENTS_SQL)
                db.execute('INSERT INTO installation VALUES (1,?,?,?,?,?,?,?,?,0)',
                           (SCHEMA, installation_id, *identity))
            os.fsync(lock_fd)
            os.fsync(db_fd)
            os.fsync(dir_fd)
        if db.execute('PRAGMA integrity_check(1)').fetchall() != [('ok',)]:
            raise StateError('state_corrupt')
        inventory = ActorInventory(db, db_fd, dir_fd, installation_id, identity)
        yield inventory
    except (sqlite3.Error, OSError) as exc:
        raise StateError('state_unavailable') from exc
    finally:
        if inventory is not None:
            inventory._closed = True
        if db is not None:
            db.close()
        for descriptor in (db_fd, lock_fd, dir_fd):
            if descriptor is not None:
                os.close(descriptor)
