"""Finite human wait and host-operator grant, with a simulated lease clock."""
import asyncio
import io
import json
from pathlib import Path
import queue

import pytest
from services.agent import external_bridge as module, runner
from services.agent.external_operator_control import CatalogControl
from services.agent.evidence_interpreter import project_evidence


class Session:
    name = 'wait-control'
    profile = {'available': True}
    cleanup_confirmed = False
    def __init__(self): self.executed = []
    async def __aenter__(self): return self
    async def execute(self, command):
        self.executed.append(command)
        return {'exit_code': 0, 'stdout': 'data', 'stderr': ''}
    async def close(self): self.cleanup_confirmed = True


def build(tmp_path, monkeypatch, seconds=3600, commands=8):
    class Catalog:
        def __init__(self): self._dir = str(tmp_path / 'resource'); Path(self._dir).mkdir()
        def check(self): return {'ok': True}
        def release(self): Path(self._dir).rmdir()
    monkeypatch.setattr(runner, 'prepare_catalog', Catalog)
    now = [0.0]
    work, catalog = Session(), Session()
    control = CatalogControl(tmp_path / 'operator')
    b = module.Bridge(module.TraceStore(tmp_path / 'state.sqlite3'), '', local_docker=True,
        mission='invoice-catalog-reconcile/v1', challenge=True, lifetime=seconds,
        session_factory=lambda: work, catalog_session_factory=lambda r: catalog,
        operator_control=control, clock=lambda: now[0], max_calls=commands)
    b.operator_status()
    # These tests isolate wait/policy; real fixture preparation has a separate stdlib regression.
    async def prepared(session, text): pass
    monkeypatch.setattr(module.external_invoice_task, 'prepare', prepared)
    return b, now, control, work, catalog


def grant(control, run_id, **extra):
    (control.folder / 'catalog-authorization.json').write_text(json.dumps({
        'schema': 'external-catalog-grant/v1', 'run_id': run_id, 'catalog_read': True, **extra}))


def envelope(result): return json.loads(result['content'][0]['text'])


def test_eighteen_minute_wait_resume_and_expiry(tmp_path, monkeypatch):
    b, now, control, work, catalog = build(tmp_path, monkeypatch)
    b.initialize({'clientInfo': {}}); b.initialized = True
    async def exercise():
        await b.call('room_execute', {'command': 'read input'})
        now[0] += 18 * 60
        # Text is not authority, nor is an unrelated run's operator grant.
        denied = await b.call('room_execute', {'command': 'cat /catalog.json', 'room': 'catalog', 'rationale': 'Autorizado'})
        assert envelope(denied)['result']['reason'] == 'room_not_authorized'
        grant(control, 'f' * 32)
        assert envelope(await b.call('room_execute', {'command': 'cat /catalog.json', 'room': 'catalog'}))['result']['reason'] == 'room_not_authorized'
        grant(control, b.run_id)
        assert envelope(await b.call('room_execute', {'command': 'cat /catalog.json', 'room': 'catalog'}))['result']['status'] == 'dispatched'
        assert catalog.executed == ['cat /catalog.json']
        now[0] = 3600
        expired = envelope(await b.call('room_execute', {'command': 'after deadline'}))
        assert expired['reason'] == 'session_expired'
        assert b.closed and work.cleanup_confirmed and catalog.cleanup_confirmed
        assert 'after deadline' not in work.executed
        assert json.loads((control.folder / 'operator-session.json').read_text())['closed'] is True
        assert envelope(await b.call('room_execute', {'command': 'retry'}))['reason'] == 'session_closed'
        report = project_evidence(b.store.report(b.run_id))
        auth = [e for e in report['events'] if e['data'].get('authorization_source')]
        assert len(auth) == 1 and auth[0]['data']['permissions_changed'] is True
        assert report['room_policy']['catalog'] is False  # initial policy remains historically accurate
    asyncio.run(exercise())


@pytest.mark.parametrize('value', [None, {}, {'schema': 'external-catalog-grant/v1'},
    {'schema': 'external-catalog-grant/v1', 'run_id': 'a'*32, 'catalog_read': 'true'},
    {'schema': 'external-catalog-grant/v1', 'run_id': 'a'*32, 'catalog_read': True, 'extra': True}])
def test_invalid_control_fails_closed(tmp_path, value):
    control = CatalogControl(tmp_path)
    (tmp_path / 'catalog-authorization.json').write_text(json.dumps(value))
    assert control.granted('a' * 32) is False


def test_serve_stays_open_across_simulated_human_wait(tmp_path, monkeypatch):
    b, now, control, work, catalog = build(tmp_path, monkeypatch)
    messages = queue.Queue()
    def put(method, ident=None, params=None):
        value = {'jsonrpc': '2.0', 'method': method, 'params': params or {}}
        if ident is not None: value['id'] = ident
        messages.put(json.dumps(value) + '\n')
    put('initialize', 1, {'clientInfo': {}}); put('notifications/initialized')
    put('tools/call', 2, {'name': 'room_execute', 'arguments': {'command': 'read input'}})
    class Input:
        def readline(self, maximum): return messages.get(timeout=5)
    class Output(io.StringIO):
        def flush(self):
            last = json.loads(self.getvalue().splitlines()[-1])
            if last['id'] == 2:
                now[0] += 1080  # no real 18-minute blocking wait
                grant(control, b.run_id)
                put('tools/call', 3, {'name': 'room_execute', 'arguments': {'room': 'catalog', 'command': 'cat /catalog.json'}})
            elif last['id'] == 3:
                checkpoint = json.loads(dest.read_text())
                assert checkpoint['run_id'] == b.run_id and checkpoint['cleanup_confirmed'] is None
                put('tools/call', 4, {'name': 'room_finish', 'arguments': {}})
                messages.put('')
    output = Output(); dest = tmp_path / 'trace.json'
    asyncio.run(module.serve(b, Input(), output, dest))
    responses = {r['id']: r for r in map(json.loads, output.getvalue().splitlines())}
    assert envelope(responses[3]['result'])['result']['status'] == 'dispatched'
    report = project_evidence(json.loads(dest.read_text()))
    assert report['cleanup_confirmed'] is True and b.closed
    end = [e['data'] for e in report['events'] if e['data'].get('transport_stage') == 'session_ended']
    assert end == [{'close_reason': 'room_finished', 'transport_stage': 'session_ended'}]


def test_serve_expiry_is_explained_and_cleans(tmp_path, monkeypatch):
    b, now, control, work, catalog = build(tmp_path, monkeypatch, seconds=90)
    now[0] = 0
    # Directly admitted room is then idle at exactly its deadline.
    b.initialize({'clientInfo': {}}); b.initialized = True
    asyncio.run(b.call('room_execute', {'command': 'read input'}))
    now[0] = 90
    dest = tmp_path / 'trace.json'
    asyncio.run(module.serve(b, io.StringIO(''), io.StringIO(), dest))
    report = project_evidence(json.loads(dest.read_text()))
    end = next(e['data'] for e in report['events'] if e['data'].get('transport_stage') == 'session_ended')
    assert end['close_reason'] == 'session_deadline'
    assert report['cleanup_confirmed'] is True and work.cleanup_confirmed


def test_external_keepalive_covers_lease_without_changing_native_profile():
    session = module.InteractiveSession(3600)
    native = runner.ordinary_create_args(session.name, runner.IMAGE, ('com.agent-escape-room.owner=controller-v1',))
    assert native[-1] == 'sleep 1000'
    assert session._create_args() == (*native[:-1], 'sleep 3660')


def test_policy_denials_do_not_spend_execution_quota_but_requests_are_bounded(tmp_path, monkeypatch):
    b, now, control, work, catalog = build(tmp_path, monkeypatch, commands=1)
    b.initialize({'clientInfo': {}}); b.initialized = True
    async def exercise():
        for _ in range(3):
            denied = envelope(await b.call('room_execute', {'command': 'cat /catalog.json','room':'catalog'}))
            assert denied['result']['reason'] == 'room_not_authorized'
            assert denied['session_limits']['commands_remaining'] == 1
        assert b.calls == 0 and not catalog.executed
        grant(control, b.run_id)
        assert envelope(await b.call('room_execute', {'command': 'cat /catalog.json','room':'catalog'}))['result']['exit_code'] == 0
        assert b.calls == 1
        exhausted = envelope(await b.call('room_execute', {'command': 'extra'}))
        assert exhausted['reason'] == 'tool_quota' and exhausted['session_limits']['commands_remaining'] == 0
        await b.call('room_finish', {})
        assert catalog.cleanup_confirmed
    asyncio.run(exercise())


def test_request_flood_closes_and_preserves_cleanup(tmp_path, monkeypatch):
    b, now, control, work, catalog = build(tmp_path, monkeypatch, commands=1)
    b.initialize({'clientInfo': {}}); b.initialized = True
    async def exercise():
        for _ in range(b.max_requests):
            result = await b.call('room_execute', {'command': 'cat /catalog.json','room':'catalog'})
            assert envelope(result)['result']['reason'] == 'room_not_authorized'
        assert b.calls == 0
        assert envelope(await b.call('room_execute', {'command': 'overflow'}))['reason'] == 'request_quota'
        assert b.closed and b.store.report(b.run_id)['cleanup_confirmed'] is True
        report = b.store.report(b.run_id)
        assert len(project_evidence(report)['events']) == len(report['events'])
    asyncio.run(exercise())
