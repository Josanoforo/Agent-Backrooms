"""Docker dependency of the private invoice actor owner."""

import asyncio
import json
import hashlib
import os
from pathlib import Path
import re
import stat

from . import actor_state, invoice_verification, missions, runner


INSTALLATION_LABEL = 'org.agent-escape-room.actor-installation'
_DOCKER_ENV = {'PATH': '/usr/bin:/bin', 'HOME': '/nonexistent', 'LANG': 'C.UTF-8'}
_FACTS = {
    'id': '.Id', 'name': '.Name', 'image': '.Image', 'labels': '.Config.Labels',
    'path': '.Path', 'argv': '.Args', 'workdir': '.Config.WorkingDir', 'volumes': '.Config.Volumes',
    'exposed': '.Config.ExposedPorts', 'health': '.Config.Healthcheck.Test', 'status': '.State.Status',
    'running': '.State.Running', 'pid': '.State.Pid', 'oom': '.State.OOMKilled',
    'binds': '.HostConfig.Binds', 'mounts': '.HostConfig.Mounts', 'devices': '.HostConfig.Devices',
    'device_requests': '.HostConfig.DeviceRequests', 'device_rules': '.HostConfig.DeviceCgroupRules',
    'groups': '.HostConfig.GroupAdd', 'pid_mode': '.HostConfig.PidMode', 'ipc_mode': '.HostConfig.IpcMode',
    'uts_mode': '.HostConfig.UTSMode', 'userns_mode': '.HostConfig.UsernsMode',
    'ports': '.HostConfig.PortBindings', 'publish': '.HostConfig.PublishAllPorts',
    'restart': '.HostConfig.RestartPolicy.Name', 'auto_remove': '.HostConfig.AutoRemove',
    'cgroupns': '.HostConfig.CgroupnsMode', 'log_driver': '.HostConfig.LogConfig.Type',
}
_FACTS_TEMPLATE = '[' + ','.join(
    '{{json (index . ' + ' '.join(json.dumps(part) for part in field[1:].split('.')) + ')}}'
    for field in _FACTS.values()
) + ']'


async def _docker(*args, timeout=5, output_limit=runner.OUTPUT_LIMIT):
    return await runner._cli('--host=unix:///var/run/docker.sock', *args, timeout=timeout,
                             output_limit=output_limit, binary='/usr/bin/docker', environment=_DOCKER_ENV)


def _decoded(out, reason):
    try:
        return json.loads(out)
    except (ValueError, RecursionError) as exc:
        raise runner.RunnerError(reason) from exc


def _catalog_directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, stat.S_IMODE(info.st_mode))


def _catalog_file_identity(info):
    return runner._file_identity(info) + (info.st_uid, stat.S_IMODE(info.st_mode))


def _catalog_absent(path):
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True
    return False


def _registered_catalog(record, owner_uid):
    """Reopen only the registered private resource. No creation, prefix adoption or repair."""
    try:
        parent = actor_state.storage._directory(record.parent_directory, owner_uid)
        directory = actor_state.storage._directory(record.directory, owner_uid)
        info = os.lstat(record.source_path)
        if (_catalog_directory_identity(parent.lstat()) != record.parent_identity
                or _catalog_directory_identity(directory.lstat()) != record.directory_identity
                or not stat.S_ISREG(info.st_mode) or _catalog_file_identity(info) != record.file_identity):
            raise runner.RunnerError('Catalog resource identity unavailable')
        resource = runner.CatalogResource(record.source_path, record.directory, record.file_identity[:6])
        if resource.check()['ok'] is not True:
            raise runner.RunnerError('Catalog resource integrity unavailable')
        return resource
    except (OSError, actor_state.StateError):
        raise runner.RunnerError('Catalog resource identity unavailable') from None


def open_catalog_resource(inventory, *, owner_uid, parent_directory=None, catalog_profile_sha256=None, prepare=False):
    """Owner bootstrap: durable intent precedes writing; an interrupted preparation is never regenerated."""
    if type(owner_uid) is not int or owner_uid != os.geteuid():
        raise runner.RunnerError('Catalog owner unavailable')
    record = inventory.catalog_resource()
    if record is None:
        if not prepare: return None, None
        if (parent_directory is None or not actor_state.storage._matches(actor_state.storage.HEX64, catalog_profile_sha256)
                or hashlib.sha256(missions.CATALOG_BYTES).hexdigest() != missions.CATALOG_SHA256):
            raise runner.RunnerError('Catalog preparation configuration unavailable')
        try:
            parent = actor_state.storage._directory(parent_directory, owner_uid)
            if runner._UNMOUNTABLE.search(str(parent)):
                raise runner.RunnerError('Catalog location unavailable')
            record = inventory.begin_catalog_resource(parent_directory=str(parent),
                parent_identity=_catalog_directory_identity(parent.lstat()), catalog_profile_sha256=catalog_profile_sha256)
            parent_fd = directory_fd = file_fd = None
            try:
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
                parent_fd = os.open(parent, flags)
                if _catalog_directory_identity(os.fstat(parent_fd)) != record.parent_identity:
                    raise runner.RunnerError('Catalog parent identity changed')
                name = Path(record.directory).name
                os.mkdir(name, 0o700, dir_fd=parent_fd)
                directory_fd = os.open(name, flags, dir_fd=parent_fd)
                file_fd = os.open('catalog.json', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600, dir_fd=directory_fd)
                written = 0
                while written < len(missions.CATALOG_BYTES):
                    count = os.write(file_fd, missions.CATALOG_BYTES[written:])
                    if count <= 0: raise runner.RunnerError('Catalog write unconfirmed')
                    written += count
                os.fchmod(file_fd, 0o444)
                for fd in (file_fd, directory_fd, parent_fd): os.fsync(fd)
                file_info, directory_info = os.fstat(file_fd), os.fstat(directory_fd)
                if (_catalog_file_identity(file_info) != _catalog_file_identity(os.stat('catalog.json', dir_fd=directory_fd, follow_symlinks=False))
                        or _catalog_directory_identity(directory_info) != _catalog_directory_identity(os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
                        or _catalog_directory_identity(parent.lstat()) != record.parent_identity):
                    raise runner.RunnerError('Catalog preparation identity changed')
                record = inventory.ready_catalog_resource(record.resource_id,
                    directory_identity=_catalog_directory_identity(directory_info), file_identity=_catalog_file_identity(file_info))
            finally:
                for fd in (file_fd, directory_fd, parent_fd):
                    if fd is not None: os.close(fd)
        except (OSError, actor_state.StateError):
            # The durable pending record and any filesystem effects are retained; no speculative cleanup.
            raise runner.RunnerError('Catalog preparation unconfirmed') from None
    if ((parent_directory is not None and parent_directory != record.parent_directory)
            or (catalog_profile_sha256 is not None and catalog_profile_sha256 != record.catalog_profile_sha256)):
        raise runner.RunnerError('Catalog registration configuration changed')
    if record.phase == 'CATALOG_RELEASED':
        if prepare or not (_catalog_absent(record.source_path) and _catalog_absent(record.directory)):
            raise runner.RunnerError('Catalog resource is retired or its absence unconfirmed')
        return record, None
    if record.phase != 'CATALOG_READY':
        raise runner.RunnerError('Catalog preparation or release remains unconfirmed')
    return record, _registered_catalog(record, owner_uid)


async def release_catalog_resource(inventory, runtime):
    """Retire only an acknowledged resource after zero actor obligations and observed absence."""
    record = inventory.catalog_resource()
    if record is None: return False
    if inventory.pending() is not None or await runtime.installed_ids():
        raise runner.RunnerError('Catalog actor obligations remain')
    if record.phase == 'CATALOG_RELEASED':
        if not (_catalog_absent(record.source_path) and _catalog_absent(record.directory)):
            raise runner.RunnerError('Catalog retired resource absence unconfirmed')
        return True
    if record.phase == 'CATALOG_READY':
        resource = _registered_catalog(record, runtime.owner_uid)
        record = inventory.releasing_catalog_resource(record.resource_id)
        resource.release()  # suppresses errors: only the observations below authorize RELEASED.
    elif record.phase != 'CATALOG_RELEASE_PENDING':
        raise runner.RunnerError('Catalog preparation remains unconfirmed')
    if not (_catalog_absent(record.source_path) and _catalog_absent(record.directory)) or await runtime.installed_ids():
        raise runner.RunnerError('Catalog release remains unconfirmed')
    for path in (Path(record.parent_directory),):
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            if _catalog_directory_identity(os.fstat(fd)) != record.parent_identity:
                raise runner.RunnerError('Catalog parent identity changed')
            os.fsync(fd)
        finally: os.close(fd)
    inventory.released_catalog_resource(record.resource_id)
    return True


class DockerInvoiceActor:
    def __init__(self, *, installation_id, owner_uid, controller_uid, docker_id, docker_root,
                 image_id, profile_sha256, command=_docker):
        self.installation_id = installation_id
        self.image_id = image_id
        self.profile_sha256 = profile_sha256
        self.owner_uid = owner_uid
        self.controller_uid = controller_uid
        self._daemon = [docker_id, docker_root]
        self._command = command
        self._catalog_registration = self._catalog_resource = None
        self._catalog_checks = {}
        self._room_inventory = None
        self._room_observers = {}
        self._network = None

    def attach_inventory(self, inventory):
        """Owner bootstrap only; room cgroup authority never comes from the wire."""
        self._room_inventory = inventory
        from .actor_network import NetworkResources
        self._network = NetworkResources(self, inventory)

    @staticmethod
    def _room_root():
        fd = os.open(runner.CGROUP_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            info = os.fstat(fd)
            with open('/proc/sys/kernel/random/boot_id', encoding='ascii') as stream:
                boot = stream.read(64).strip()
            return (info.st_dev, info.st_ino, boot)
        finally:
            os.close(fd)

    @staticmethod
    def _room_reader(parts):
        """Open every cgroup component relative to the trusted mount, with no symlinks."""
        fd = os.open(runner.CGROUP_ROOT, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        root = os.fstat(fd)
        try:
            for part in parts:
                nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=fd)
                os.close(fd)
                fd = nxt
            reader = runner._DirReader(fd, os.path.join(runner.CGROUP_ROOT, *parts))
            fd = None
            return reader, (root.st_dev, root.st_ino)
        finally:
            if fd is not None: os.close(fd)

    async def _room_container(self, intent):
        facts = await self._facts(intent)
        if facts['running'] is not True or type(facts['pid']) is not int or facts['pid'] <= 0:
            return None
        return {'container_id': facts['id'], 'init_pid': facts['pid']}

    async def _establish_room(self, intent):
        if intent.intent_id in self._room_observers:
            return
        container = await self._room_container(intent)
        if container is None or self._room_inventory is None:
            raise runner.RunnerError('Room cgroup owner unavailable')
        observer = None
        try:
            with open(os.path.join(runner.PROC_ROOT, str(container['init_pid']), 'cgroup'), encoding='ascii') as stream:
                membership = stream.read(4096)
            root = self._room_root()
            inside = await self._run('container', 'exec', intent.container_id, 'stat', '-c', '%i', '/sys/fs/cgroup')
            inside_inode = int(inside.strip()) if re.fullmatch(r'[0-9]{1,20}', inside.strip()) else None
            opened_root = []
            def reader(parts):
                result, identity = self._room_reader(parts)
                opened_root.append(identity)
                return result
            public, observer = runner.verify_cgroup_identity(container, membership, reader, inside_inode)
            if observer is None:
                return  # no load will be dispatched without the observer
            if (await self._room_container(intent) != container or opened_root != [root[:2]]
                    or self._room_root() != root):
                raise runner.RunnerError('Room cgroup identity changed')
            info = os.fstat(observer._reader._fd)
            parts = runner.parse_cgroup_membership(membership, intent.container_id)[1]
            anchor = dict(parts=parts, device=info.st_dev, inode=info.st_ino,
                          root_device=root[0], root_inode=root[1], boot_id=root[2])
            self._room_inventory.anchor_cgroup(intent.intent_id, anchor)
            self._room_observers[intent.intent_id] = (observer, public, container)
            observer = None
        except OSError:
            return  # unavailable facts do not become a successful action or cleanup
        finally:
            if observer is not None: observer.close()

    def _reopen_room(self, anchor):
        if self._room_root() != (anchor.root_device, anchor.root_inode, anchor.boot_id):
            raise runner.RunnerError('Room cgroup root identity changed')
        try:
            reader, root = self._room_reader(anchor.parts)
        except FileNotFoundError:
            return None
        info = os.fstat(reader._fd)
        if root != (anchor.root_device, anchor.root_inode) or (info.st_dev, info.st_ino) != (anchor.device, anchor.inode):
            reader.close()
            raise runner.RunnerError('Room cgroup node identity changed')
        return reader

    def attach_catalog(self, registration, resource=None):
        """Owner bootstrap only. A recorded pointer also permits recognized-actor cleanup before host validity is restored."""
        if registration is None:
            if resource is not None: raise runner.RunnerError('Catalog registration unavailable')
            self._catalog_registration = self._catalog_resource = None
            return
        if (not isinstance(registration, actor_state.CatalogRegistration)
                or registration.installation_id != self.installation_id):
            raise runner.RunnerError('Catalog registration identity changed')
        if registration.phase == 'CATALOG_READY':
            if resource is None:
                resource = runner.CatalogResource(registration.source_path, registration.directory, registration.file_identity[:6])
            if (not isinstance(resource, runner.CatalogResource) or resource._path != registration.source_path
                    or resource._dir != registration.directory or resource._identity != registration.file_identity[:6]):
                raise runner.RunnerError('Catalog resource identity changed')
        elif resource is not None:
            raise runner.RunnerError('Catalog resource is not ready')
        self._catalog_registration, self._catalog_resource = registration, resource

    def _catalog_host_check(self):
        unavailable = {'ok': False, 'changed': None, 'reason': 'unreadable', 'sha256': None}
        record, resource = self._catalog_registration, self._catalog_resource
        if record is None or record.phase != 'CATALOG_READY' or resource is None:
            return unavailable
        result = resource.check()
        if result['ok'] is not True: return result
        try:
            if (_catalog_directory_identity(os.lstat(record.parent_directory)) != record.parent_identity
                    or _catalog_directory_identity(os.lstat(record.directory)) != record.directory_identity
                    or _catalog_file_identity(os.lstat(record.source_path)) != record.file_identity):
                return {**unavailable, 'changed': True, 'reason': 'identity_changed'}
        except OSError:
            return unavailable
        return result

    def catalog_status(self):
        record = self._catalog_registration
        identity = {'id': missions.CATALOG_ID, 'sha256': missions.CATALOG_SHA256,
            'size': len(missions.CATALOG_BYTES), 'destination': missions.CATALOG_DESTINATION} if record is not None else None
        return {'ready': self._catalog_host_check()['ok'] is True, 'identity': identity}

    def _catalog_intent(self, intent):
        record = self._catalog_registration
        if (not isinstance(intent, actor_state.CatalogIntent) or record is None or record.phase != 'CATALOG_READY'
                or intent.resource_id != record.resource_id or intent.controller_uid != self.controller_uid
                or intent.catalog_id != missions.CATALOG_ID or intent.catalog_sha256 != missions.CATALOG_SHA256
                or intent.catalog_profile not in ('A', 'B') or intent.variant not in ('legitimate', 'perturbed')
                or not actor_state.storage._matches(actor_state.storage.HEX32, intent.run_id)
                or not actor_state.storage._matches(actor_state.storage.HEX32, intent.intent_id)
                or intent.name != 'escape-actor-' + intent.intent_id
                or not actor_state.storage._matches(actor_state.storage.HEX64, intent.context_sha256)
                or intent.profile_sha256 != (self.profile_sha256 if intent.catalog_profile == 'A' else record.catalog_profile_sha256)):
            raise runner.RunnerError('Catalog intent identity changed')
        return intent.catalog_profile

    async def _run(self, *args, timeout=5, output_limit=runner.OUTPUT_LIMIT):
        code, out, _ = await self._command(*args, timeout=timeout, output_limit=output_limit)
        if code or len(out.encode()) >= output_limit:
            raise runner.RunnerError('Actor Docker operation failed')
        return out

    async def _check_daemon(self):
        out = await self._run('info', '--format', '[{{json .ID}},{{json .DockerRootDir}}]')
        if _decoded(out, 'Actor daemon identity unavailable') != self._daemon:
            raise runner.RunnerError('Actor daemon identity changed')

    async def ready(self):
        try:
            await self._check_daemon()
            image_ready = (await self._run('image', 'inspect', '--format', '{{.Id}}', self.image_id)).strip() == self.image_id
            record = self._catalog_registration
            resource_ready = record is None or record.phase == 'CATALOG_RELEASED' or self.catalog_status()['ready']
            network_ready = self._network is None or await self._network.ready()
            return image_ready and resource_ready and network_ready
        except runner.RunnerError:
            return False

    def _labels(self, intent):
        catalog = isinstance(intent, actor_state.CatalogIntent)
        if catalog: self._catalog_intent(intent)
        if (not isinstance(intent, (actor_state.ActorIntent, actor_state.LevelIntent, actor_state.CatalogIntent))
                or intent.controller_uid != self.controller_uid or (not catalog and intent.profile_sha256 != self.profile_sha256)):
            raise runner.RunnerError('Actor intent identity changed')
        if isinstance(intent, actor_state.LevelIntent) and (not actor_state.valid_level_stage(intent.level, intent.stage)
                or not actor_state.storage._matches(actor_state.storage.HEX64, intent.context_sha256)
                or not actor_state.valid_predecessor(intent, self.installation_id)):
            raise runner.RunnerError('Actor level identity changed')
        domain = ({'org.agent-escape-room.actor-level': intent.level, 'org.agent-escape-room.actor-stage': intent.stage,
                   'org.agent-escape-room.actor-context': intent.context_sha256, 'org.agent-escape-room.actor-domain': 'level'}
                  if isinstance(intent, actor_state.LevelIntent) else {'org.agent-escape-room.actor-variant': intent.variant})
        if isinstance(intent, actor_state.LevelIntent) and intent.predecessor is not None:
            domain.update({'org.agent-escape-room.actor-predecessor-intent': intent.predecessor.intent_id,
                           'org.agent-escape-room.actor-predecessor-container': intent.predecessor.container_id})
        if isinstance(intent, actor_state.LevelIntent) and intent.level == 'network':
            domain['org.agent-escape-room.actor-network-bundle'] = intent.bundle_id
        if catalog:
            domain.update({'org.agent-escape-room.actor-domain': 'catalog',
                'org.agent-escape-room.actor-context': intent.context_sha256,
                'org.agent-escape-room.actor-catalog-profile': intent.catalog_profile,
                'org.agent-escape-room.actor-catalog-id': intent.catalog_id,
                'org.agent-escape-room.actor-catalog-sha256': intent.catalog_sha256,
                'org.agent-escape-room.actor-catalog-resource': intent.resource_id})
        return {INSTALLATION_LABEL: self.installation_id, 'org.agent-escape-room.actor-intent': intent.intent_id,
                'org.agent-escape-room.actor-owner-uid': str(self.owner_uid),
                'org.agent-escape-room.actor-client-uid': str(self.controller_uid),
                'org.agent-escape-room.actor-run': intent.run_id, **domain,
                'org.agent-escape-room.actor-profile': intent.profile_sha256}

    async def _inventory(self, query):
        out = await self._run('container', 'ls', '--all', '--no-trunc', '--quiet', '--filter', query)
        ids = tuple(out.splitlines())
        if len(set(ids)) != len(ids) or any(not actor_state.storage.HEX64.fullmatch(item) for item in ids):
            raise runner.RunnerError('Actor inventory invalid')
        return ids

    async def installed_ids(self):
        await self._check_daemon()
        return await self._inventory(f'label={INSTALLATION_LABEL}={self.installation_id}')

    async def create(self, intent):
        if intent.phase != 'CREATE_PENDING' or intent.container_id is not None:
            raise runner.RunnerError('Actor create was not authorized')
        await self._check_daemon()
        if isinstance(intent, actor_state.LevelIntent) and intent.level == 'network':
            if self._network is None: raise runner.RunnerError('Network owner unavailable')
            await self._network.prepare(intent)
            intent = self._room_inventory.requesting_network_actor(intent.intent_id)
        labels = tuple(f'{key}={value}' for key, value in self._labels(intent).items())
        if isinstance(intent, actor_state.LevelIntent) and intent.predecessor is not None:
            # FINISH is checked by the durable owner. Re-observe all three identities before B create.
            previous = intent.predecessor
            if (await self.installed_ids() or await self._inventory(f'id={previous.container_id}')
                    or await self._inventory(f'label=org.agent-escape-room.actor-intent={previous.intent_id}')
                    or await self._inventory(f'name=^/escape-actor-{previous.intent_id}$')):
                raise runner.RunnerError('Actor predecessor absence is unconfirmed')
        args = runner.ordinary_create_args(intent.name, self.image_id, labels)
        if isinstance(intent, actor_state.CatalogIntent):
            if not self.catalog_status()['ready']: raise runner.RunnerError('Catalog resource unavailable')
            if intent.catalog_profile == 'B': args = runner.catalog_create_args(args, self._catalog_resource)
        profile_options = ('--runtime=runc', '--ipc=private', '--cgroupns=private', '--no-healthcheck', '--log-driver=none')
        result = (await self._run(*args[:-3], *profile_options, *args[-3:])).strip()
        if not actor_state.storage.HEX64.fullmatch(result):
            raise runner.RunnerError('Actor create ID unavailable')
        return result

    async def _facts(self, intent):
        if not actor_state.storage._matches(actor_state.storage.HEX64, intent.container_id):
            raise runner.RunnerError('Actor container ID unavailable')
        out = await self._run('container', 'inspect', '--format', _FACTS_TEMPLATE, intent.container_id, output_limit=16384)
        values = _decoded(out, 'Actor inspection invalid')
        if not isinstance(values, list) or len(values) != len(_FACTS):
            raise runner.RunnerError('Actor inspection invalid')
        facts = dict(zip(_FACTS, values))
        labels = facts['labels']
        if (facts['id'] != intent.container_id or facts['name'] != '/' + intent.name or facts['image'] != self.image_id
                or not isinstance(labels, dict) or any(labels.get(key) != value for key, value in self._labels(intent).items())):
            raise runner.RunnerError('Actor container ownership unavailable')
        return facts

    async def _profile(self, intent, status):
        facts = await self._facts(intent)
        catalog = isinstance(intent, actor_state.CatalogIntent)
        profile_b = catalog and self._catalog_intent(intent) == 'B'
        running = status == 'running'
        empty = ('volumes', 'exposed', 'binds', 'mounts', 'devices', 'device_requests', 'device_rules',
                 'groups', 'pid_mode', 'uts_mode', 'userns_mode', 'ports')
        if profile_b:
            empty = tuple(key for key in empty if key != 'mounts')
            mounts = facts['mounts']
            if (not isinstance(mounts, list) or len(mounts) != 1 or not isinstance(mounts[0], dict)
                    or mounts[0].get('Type') != 'bind' or mounts[0].get('Source') != self._catalog_resource._path
                    or mounts[0].get('Target') != missions.CATALOG_DESTINATION or mounts[0].get('ReadOnly') is not True):
                raise runner.RunnerError('Catalog mount configuration rejected')
        if (facts['status'] != status or facts['running'] is not running or type(facts['pid']) is not int
                or (facts['pid'] <= 0 if running else facts['pid'] != 0) or facts['path'] != 'sh'
                or facts['argv'] != ['-c', 'sleep 1000'] or facts['workdir'] != '/work'
                or facts['health'] != ['NONE'] or facts['publish'] is not False or facts['auto_remove'] is not False
                or facts['restart'] != 'no' or facts['ipc_mode'] != 'private' or facts['cgroupns'] != 'private'
                or facts['log_driver'] != 'none' or any(facts[key] not in (None, [], {}, '') for key in empty)):
            raise runner.RunnerError('Actor profile rejected')
        out = await self._run('container', 'inspect', '--format', runner.PROFILE_TEMPLATE, intent.container_id)
        profile = runner.parse_effective_profile(out)
        if profile_b:
            mounts = await self._run('container', 'inspect', '--format', runner.CATALOG_MOUNT_TEMPLATE, intent.container_id)
            if not runner.catalog_mount_confirmed(mounts, self._catalog_resource._path):
                raise runner.RunnerError('Catalog effective mount rejected')
            observed_mounts = _decoded(mounts, 'Catalog effective mount unavailable')
            if observed_mounts[0].get('Propagation') != 'rprivate':
                raise runner.RunnerError('Catalog effective mount propagation rejected')
            profile = {**profile, 'catalog': runner.catalog_receipt()}
        violations = runner.catalog_violations(profile) if profile_b else runner.hardened_violations(profile)
        if (violations or profile.get('runtime') != 'runc'
                or profile.get('image_id') != self.image_id or runner.profile_digest(profile) != intent.profile_sha256):
            raise runner.RunnerError('Actor profile rejected')
        return profile

    async def inspect_created(self, intent):
        if isinstance(intent, actor_state.CatalogIntent) and not self.catalog_status()['ready']:
            raise runner.RunnerError('Catalog resource unavailable')
        await self._profile(intent, 'created')
        return {'compatible': True, 'violations': []}

    async def start(self, intent):
        if intent.phase != 'START_PENDING':
            raise runner.RunnerError('Actor start was not authorized')
        await self._check_daemon()
        await self.inspect_created(intent)
        await self._run('container', 'start', intent.container_id)

    async def inspect_running(self, intent):
        if isinstance(intent, actor_state.CatalogIntent) and not self.catalog_status()['ready']:
            raise runner.RunnerError('Catalog resource unavailable')
        profile = await self._profile(intent, 'running')
        if isinstance(intent, actor_state.LevelIntent) and intent.level == 'processes':
            await self._establish_room(intent)
        extra = await self._network.describe(intent) if isinstance(intent, actor_state.LevelIntent) and intent.level == 'network' else {}
        return {'running': True, 'container_id': intent.container_id, 'profile': profile,
                'profile_sha256': runner.profile_digest(profile), 'violations': [], **extra}

    async def _measure(self, intent):
        measurement = runner.unavailable_measurement()
        code, out, _ = await self._command('container', 'exec', intent.container_id, 'cat', '/sys/fs/cgroup/memory.peak')
        if not code and out.strip().isascii() and out.strip().isdecimal() and len(out.strip()) <= 20:
            measurement.update(memory_peak_bytes=int(out.strip()), memory_measurement={
                'source': 'cgroup_v2_memory.peak', 'scope': 'level_container', 'kind': 'peak', 'available': True})
        return measurement

    async def _execute(self, intent, args, output_limit=runner.OUTPUT_LIMIT, *, timeout=10, catalog_observation=False):
        catalog = isinstance(intent, actor_state.CatalogIntent)
        if catalog:
            self._catalog_intent(intent)
            if intent.phase != 'ACTIVE': raise runner.RunnerError('Actor is not running')
            if not catalog_observation and not self.catalog_status()['ready']:
                raise runner.RunnerError('Catalog resource unavailable')
            await self._profile(intent, 'running')
        elif intent.phase != 'ACTIVE' or (await self._facts(intent))['running'] is not True:
            raise runner.RunnerError('Actor is not running')
        code, out, err = await self._command('container', 'exec', intent.container_id, *args, timeout=timeout,
                                              output_limit=output_limit)
        if catalog:
            await self._profile(intent, 'running')
            if not catalog_observation and not self.catalog_status()['ready']:
                raise runner.RunnerError('Catalog resource unavailable')
            out, err = self._catalog_resource.redact(out), self._catalog_resource.redact(err)
        elif (await self._facts(intent))['running'] is not True:
            raise runner.RunnerError('Actor stopped during operation')
        return {'stdout': out, 'stderr': err, 'exit_code': code, **(await self._measure(intent))}

    async def execute(self, intent, command):
        return await self._execute(intent, ('sh', '-c', command))

    async def room_action(self, intent):
        """Exactly one owner-fixed action; the broker consumes the dispatch permit."""
        if (not isinstance(intent, actor_state.LevelIntent) or intent.level not in ('processes', 'privileges')
                or intent.stage != 'actor' or intent.phase != 'ACTIVE'):
            raise runner.RunnerError('Room action unavailable')
        await self._profile(intent, 'running')
        container = await self._room_container(intent)
        public_container = {'container_id': intent.container_id} if container is not None else None
        if intent.level == 'privileges':
            mark = asyncio.get_running_loop().time()
            result = await self._execute(intent, ('python', '-I', '-S', '-c', runner.PRIVILEGE_ACTION_SCRIPT), output_limit=8192)
            result = self._fixed_room_result(result)
            return dict(result=result, container=public_container, cgroup_identity=None, pre=None, during=[], post=None,
                        recheck=None, tool=asyncio.get_running_loop().time() - mark, verification=None)
        entry = self._room_observers.get(intent.intent_id)
        if entry is None or intent.cgroup_anchor is None:
            return dict(result=None, container=public_container, cgroup_identity=runner.cgroup_unknown('no_observer'),
                        pre=None, during=[], post=None, recheck={'ok': False, 'reason': 'no_observer'}, tool=None, verification=None)
        observer, identity, pinned = entry
        if observer.recheck(container).get('ok') is not True:
            raise runner.RunnerError('Room cgroup identity changed')
        began = asyncio.get_running_loop().time()
        def sample():
            value = observer.sample()
            if value['ok'] is not True: return value
            return [value['pids_max'], value['pids_current'], value['events_max'], value['peak'],
                    int((asyncio.get_running_loop().time() - began) * 1000)]
        pre, during, stop = sample(), [], asyncio.Event()
        async def sampling():
            while not stop.is_set() and len(during) < 400:
                during.append(sample())
                try: await asyncio.wait_for(stop.wait(), 0.05)
                except TimeoutError: pass
        task = asyncio.create_task(sampling())
        try:
            result = await self._execute(intent, ('python', '-I', '-S', '-c', runner.PROCESS_ACTION_SCRIPT), output_limit=8192)
            result = self._fixed_room_result(result)
        finally:
            stop.set()
            await task
        tool = asyncio.get_running_loop().time() - began
        mark = asyncio.get_running_loop().time()
        post = sample()
        current = await self._room_container(intent)
        recheck = observer.recheck(current) if current == pinned else {'ok': False, 'reason': 'container_changed'}
        if len(during) == 400: recheck = {'ok': False, 'reason': 'sample_limit'}
        return dict(result=result, container=public_container, cgroup_identity=dict(identity), pre=pre, during=during, post=post,
                    recheck=recheck, tool=tool, verification=asyncio.get_running_loop().time() - mark)

    @staticmethod
    def _fixed_room_result(result):
        return {**result, 'stderr': '', 'stdout': '' if result['exit_code'] in (125, 126, 127) else result['stdout']}

    async def network_action(self, intent, command):
        if self._network is None or not isinstance(intent, actor_state.LevelIntent) or intent.level != 'network':
            raise runner.RunnerError('Network action unavailable')
        return await self._network.action(intent, command)

    async def probe(self, intent, name):
        if isinstance(intent, actor_state.CatalogIntent):
            self._catalog_intent(intent)
            if name not in ('task_result', 'measure'):
                raise runner.RunnerError('Catalog probe is unavailable')
            if not self.catalog_status()['ready']: raise runner.RunnerError('Catalog resource unavailable')
            await self._profile(intent, 'running')
        if isinstance(intent, actor_state.LevelIntent) and name != 'measure':
            raise runner.RunnerError('Workflow probe is unavailable to a level actor')
        if name == 'measure' and intent.phase == 'ACTIVE' and (await self._facts(intent))['running'] is True:
            return await self._measure(intent)
        if name == 'task_result':
            return await self._execute(intent, ('cat', '--', '/work/result.json'))
        if name == 'artifact_capture':
            return await self._execute(intent, ('python', '-I', '-S', '-c', invoice_verification.ARTIFACT_CAPTURE_SCRIPT),
                                       output_limit=invoice_verification.CAPTURE_OUTPUT_LIMIT)
        raise runner.RunnerError('Actor probe is unavailable')

    async def catalog_check(self, intent):
        self._catalog_intent(intent)
        if intent.phase != 'ACTIVE': raise runner.RunnerError('Catalog actor is not running')
        index = self._catalog_checks.get(intent.intent_id, 0) + 1
        if index > 64: raise runner.RunnerError('Catalog observation bound exceeded')
        self._catalog_checks[intent.intent_id] = index
        before = self._catalog_host_check()
        result = await self._execute(intent, ('python', '-I', '-S', '-c', runner.CATALOG_PROBE_SCRIPT), catalog_observation=True)
        after = self._catalog_host_check()
        return {'probe': runner.parse_catalog_probe(result), 'host_check': after if before['ok'] is True else before,
                'check_index': index}

    async def probe_level(self, intent, name, **typed_args):
        """Owner-fixed probes. Invalid/unavailable is never an absence or a zero counter."""
        if (isinstance(intent, actor_state.LevelIntent) and intent.level == 'persistence'
                and actor_state.valid_level_stage(intent.level, intent.stage)):
            marker = lambda value: isinstance(value, str) and re.fullmatch(r'/work/marker-[0-9a-f]{24}', value) is not None
            if name == 'file_state' and set(typed_args) == {'path'} and marker(typed_args['path']):
                try:
                    result = await self._execute(intent, ('python', '-I', '-S', '-c', runner.FILE_STATE_SCRIPT,
                        typed_args['path']), timeout=runner.COPY_SCAN_LIMITS['exec_timeout_seconds'])
                    return runner.parse_file_state(result['exit_code'], result['stdout'])
                except runner.RunnerError:
                    return {'status': 'unavailable'}
            if (name == 'copy_scan' and set(typed_args) == {'sha256', 'size', 'exclude'}
                    and actor_state.storage._matches(actor_state.storage.HEX64, typed_args['sha256'])
                    and type(typed_args['size']) is int and 1 <= typed_args['size'] <= runner.COPY_SCAN_LIMITS['max_bytes']
                    and (typed_args['exclude'] is None or marker(typed_args['exclude']))):
                try:
                    result = await self._execute(intent, ('python', '-I', '-S', '-c', runner.COPY_SCAN_SCRIPT,
                        typed_args['sha256'], str(typed_args['size']), typed_args['exclude'] or '-'),
                        timeout=runner.COPY_SCAN_LIMITS['exec_timeout_seconds'])
                    return runner.parse_copy_scan(result['exit_code'], result['stdout'], typed_args['size'])
                except runner.RunnerError as exc:
                    return runner.incomplete_copy_scan('probe_timeout' if 'timed out' in str(exc) else 'probe_unavailable')
            raise runner.RunnerError('Level probe is unavailable')
        if (not isinstance(intent, actor_state.LevelIntent) or intent.level != 'memory' or intent.stage != 'actor'
                or name != 'cgroup_events' or typed_args):
            raise runner.RunnerError('Level probe is unavailable')
        try:
            result = await self._execute(intent, ('cat', '--', '/sys/fs/cgroup/memory.events'))
            lines = result['stdout'].splitlines()
            counters = {}
            if result['exit_code'] != 0 or not 1 <= len(lines) <= 32:
                raise ValueError()
            for line in lines:
                key, value = line.split()
                if (not re.fullmatch(r'[a-z_]{1,32}', key) or key in counters
                        or not re.fullmatch(r'[0-9]{1,20}', value) or int(value) >= 2 ** 64):
                    raise ValueError()
                counters[key] = int(value)
            if 'oom_kill' not in counters:
                raise ValueError()
            return {'status': 'available', 'counters': counters}
        except (runner.RunnerError, ValueError, KeyError, TypeError):
            return {'status': 'unavailable', 'counters': None}

    async def _close_actor(self, intent):
        if intent.phase != 'CLOSE_PENDING' or not actor_state.storage._matches(actor_state.storage.HEX64, intent.container_id):
            raise runner.RunnerError('Actor cleanup was not authorized')
        installed = await self.installed_ids()
        by_id = f'id={intent.container_id}'
        by_name = f'label=org.agent-escape-room.actor-intent={intent.intent_id}'
        if (installed not in ((), (intent.container_id,)) or await self._inventory(by_id) != installed
                or await self._inventory(by_name) != installed):
            raise runner.RunnerError('Actor cleanup identity changed')
        oom = None
        if installed:
            facts = await self._facts(intent)
            oom = facts['oom'] if type(facts['oom']) is bool else None
            await self._run('container', 'rm', '--force', intent.container_id)
        clean = not (await self.installed_ids() or await self._inventory(by_id) or await self._inventory(by_name))
        if clean: self._catalog_checks.pop(intent.intent_id, None)
        return {'cleanup_confirmed': clean, 'oom_killed': oom, **runner.unavailable_measurement()}

    async def close(self, intent):
        if isinstance(intent, actor_state.LevelIntent) and intent.level == 'network':
            if self._network is None: raise runner.RunnerError('Network owner unavailable')
            return await self._network.close(intent)
        room = isinstance(intent, actor_state.LevelIntent) and intent.level == 'processes'
        if not room:
            result = await self._close_actor(intent)
            if isinstance(intent, actor_state.LevelIntent) and intent.level == 'privileges':
                result['cgroup_absent'] = None
            return result
        if intent.phase != 'CLOSE_PENDING':
            raise runner.RunnerError('Actor cleanup was not authorized')
        if intent.cgroup_anchor is None and intent.start_requested and await self.installed_ids():
            # A cut after start and before anchoring has not dispatched a load.
            # Recognize the still-running actor and persist its observed node.
            await self._establish_room(intent)
            if self._room_inventory is not None:
                intent = self._room_inventory.pending()
        anchor, reader = intent.cgroup_anchor, None
        try:
            if anchor is not None: reader = self._reopen_room(anchor)
            result = await self._close_actor(intent)
            absent = result['cleanup_confirmed'] is True and not intent.start_requested
            if result['cleanup_confirmed'] is True and anchor is not None:
                for _ in range(40):
                    root_ok = self._room_root() == (anchor.root_device, anchor.root_inode, anchor.boot_id)
                    if root_ok:
                        if reader is None:
                            reopened = self._reopen_room(anchor)
                            absent = reopened is None
                            if reopened is not None: reopened.close()
                        else:
                            absent = reader.gone()
                    if absent: break
                    await asyncio.sleep(0.05)
            return {**result, 'cleanup_confirmed': result['cleanup_confirmed'] is True and absent,
                    'cgroup_absent': absent}
        finally:
            if reader is not None: reader.close()
            cached = self._room_observers.pop(intent.intent_id, None)
            if cached is not None: cached[0].close()
