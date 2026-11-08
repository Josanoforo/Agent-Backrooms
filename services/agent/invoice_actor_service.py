"""Linux entry point for the durable, private invoice actor owner."""

import argparse
import asyncio
import json
import os
import signal
import sys

from . import actor_state, daemon_guard, invoice_actor_broker, invoice_actor_runtime


async def run_owner(args):
    uid = os.geteuid()
    if uid == 0 or args.client_uid in (0, uid):
        raise ValueError('distinct non-root owner and controller required')
    runtime_options = {
        'installation_id': args.installation_id, 'owner_uid': uid, 'controller_uid': args.client_uid,
        'image_id': args.image, 'profile_sha256': args.profile_sha256,
    }
    code, out, _ = await invoice_actor_runtime._docker(
        'info', '--format', '[{{json .ID}},{{json .DockerRootDir}}]')
    if code:
        raise ValueError('actor daemon unavailable')
    daemon_id, docker_root = json.loads(out)
    runtime_options.update(docker_id=daemon_id, docker_root=docker_root)
    runtime = invoice_actor_runtime.DockerInvoiceActor(**runtime_options)
    if not await runtime.ready():
        raise ValueError('actor image or daemon unavailable')
    if args.initialize_state and await runtime.installed_ids():
        raise ValueError('actor installation is occupied')
    path = None
    if not (args.initialize_state or args.recover_only or getattr(args, 'release_catalog', False)):
        path = daemon_guard._trusted_socket_path(args.socket, uid)
    with actor_state.open_actor_inventory(args.state_dir, **runtime_options,
                                          initialize=args.initialize_state) as inventory:
        if callable(getattr(runtime, 'attach_inventory', None)):
            runtime.attach_inventory(inventory)
        if args.initialize_state:
            if getattr(args, 'prepare_catalog', False):
                record, resource = invoice_actor_runtime.open_catalog_resource(inventory, owner_uid=uid,
                    parent_directory=args.catalog_root, catalog_profile_sha256=args.catalog_profile_sha256, prepare=True)
                runtime.attach_catalog(record, resource)
            return 0
        # An acknowledged pointer permits exact-ID recovery even if the source is now damaged.
        # No source is prepared or retired before the outstanding actor has been reconciled.
        registration_reader = getattr(inventory, 'catalog_resource', None)
        catalog_configured = any(getattr(args, key, None) for key in
            ('prepare_catalog', 'release_catalog', 'catalog_root', 'catalog_profile_sha256'))
        if catalog_configured and not callable(registration_reader):
            raise ValueError('catalog inventory interface unavailable')
        record = registration_reader() if callable(registration_reader) else None
        if record is not None: runtime.attach_catalog(record)
        extra = {'allowed_levels': frozenset(args.allow_level)} if getattr(args, 'allow_level', None) else {}
        if getattr(args, 'allow_room_shell', None): extra['allowed_shell_levels'] = frozenset(args.allow_room_shell)
        if getattr(args, 'allow_catalog', False): extra['allowed_catalog'] = True
        broker = invoice_actor_broker.ActorBroker(
            runtime=runtime, inventory=inventory, client_uid=args.client_uid,
            image_id=args.image, socket_path=str(path) if path is not None else None, **extra)
        await broker.reconcile()
        if broker.status()['blocked'] is not None:
            return 2
        if getattr(args, 'release_catalog', False):
            return 0 if await invoice_actor_runtime.release_catalog_resource(inventory, runtime) else 2
        if record is not None or catalog_configured:
            record, resource = invoice_actor_runtime.open_catalog_resource(inventory, owner_uid=uid,
                parent_directory=getattr(args, 'catalog_root', None),
                catalog_profile_sha256=getattr(args, 'catalog_profile_sha256', None),
                prepare=getattr(args, 'prepare_catalog', False) and not args.recover_only)
            runtime.attach_catalog(record, resource)
        if args.recover_only:
            return 0
        task = asyncio.create_task(broker.serve())
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, task.cancel)
        loop.add_signal_handler(signal.SIGINT, task.cancel)
        try:
            await task
        except asyncio.CancelledError:
            pass
        finally:
            loop.remove_signal_handler(signal.SIGTERM)
            loop.remove_signal_handler(signal.SIGINT)
        if inventory.pending() is not None or broker.status()['blocked'] is not None:
            return 2
        # Only this instance's bound pathname is retired after an obligation-free stop.
        if path.is_socket():
            observed = path.stat()
            if observed.st_uid == uid and (observed.st_dev, observed.st_ino) == broker.socket_identity:
                path.unlink()
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--socket')
    parser.add_argument('--client-uid', type=int, required=True)
    parser.add_argument('--installation-id', required=True)
    parser.add_argument('--image', required=True)
    parser.add_argument('--profile-sha256', required=True)
    parser.add_argument('--state-dir', required=True)
    parser.add_argument('--allow-level', choices=('memory', 'secret', 'persistence', 'processes', 'privileges', 'network'), action='append', default=[])
    parser.add_argument('--allow-room-shell', choices=('processes', 'privileges'), action='append', default=[], help='trusted opt-in: shell in existing room leases, twelve total dispatches including fixed observations')
    parser.add_argument('--allow-catalog', action='store_true', help='enable only the fixed catalog domain after owner resource verification')
    parser.add_argument('--catalog-root', help='trusted private owner directory; never a client path')
    parser.add_argument('--catalog-profile-sha256', help='trusted expected digest of the fixed B profile')
    parser.add_argument('--prepare-catalog', action='store_true', help='record preparation before creating the one retained resource')
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--initialize-state', action='store_true')
    mode.add_argument('--recover-only', action='store_true')
    mode.add_argument('--release-catalog', action='store_true', help='retire only the acknowledged resource after actor recovery')
    args = parser.parse_args(argv)
    if args.prepare_catalog and (args.recover_only or args.release_catalog):
        parser.error('recovery or retirement never prepares another catalog')
    if args.prepare_catalog and (args.catalog_root is None or args.catalog_profile_sha256 is None):
        parser.error('catalog preparation requires trusted root and B profile digest')
    if not (args.initialize_state or args.recover_only or args.release_catalog) and args.socket is None:
        parser.error('serving requires --socket')
    try:
        return asyncio.run(run_owner(args))
    except (ValueError, OSError, actor_state.StateError, daemon_guard.GuardError,
            invoice_actor_runtime.runner.RunnerError):
        print('actor_recovery_required', file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
