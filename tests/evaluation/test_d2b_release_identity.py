"""Local release-binding tests. SFTP and the candidate helper are doubles."""

import hashlib
import importlib.util
import io
import json
import os
import stat
import sys
from pathlib import Path, PurePosixPath
from types import SimpleNamespace

import pytest


SSHException = pytest.importorskip('paramiko.ssh_exception').SSHException


SCRIPTS = Path(__file__).resolve().parents[2] / 'scripts'
SOURCES = {
    'apps/web/index.html': b'<html>fixture</html>',
    'apps/web/evidence/example.json': b'{"fixture": true}',
    'services/agent/main.py': b'engine',
    'scripts/b_round_candidate.py': b'base',
    'scripts/d2b_candidate.py': b'launcher',
    'scripts/evaluation/aggregate_reports.py': b'aggregator',
    'tests/fixture.py': b'review only',
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def d2b(monkeypatch, tmp_path):
    base = load('b_round_batch')
    monkeypatch.setitem(sys.modules, 'b_round_batch', base)
    monkeypatch.setitem(sys.modules, 'vultr_existing', SimpleNamespace(credentials=lambda: {}))
    module = load('d2b_batch')
    base.ROOT = tmp_path / 'worktree'
    module.configure()
    return module


def write(root, rel, data):
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


@pytest.fixture
def review(d2b, tmp_path):
    root = tmp_path / 'frozen'
    for rel, data in SOURCES.items():
        write(root, rel, data)
    index = tmp_path / 'review.json'
    doc = {'schema': 'd2b-local-review-snapshot/v1', 'scope': 'source and local evidence only',
           'files': {rel: {'sha256': sha(data), 'bytes': len(data), 'role': 'fixture', 'source': 'fixture'}
                     for rel, data in SOURCES.items()}}
    # Preserve exactly the approved bytes, including newline convention.
    index.write_bytes(json.dumps(doc, indent=2).replace('\n', '\r\n').encode() + b'\r\n')
    return SimpleNamespace(root=root, index=index, doc=doc, approved=sha(index.read_bytes()))


class SftpDouble:
    def __init__(self, root):
        self.root = root
        self.redirect = None
        root.mkdir()

    def local(self, path):
        return self.root.joinpath(*PurePosixPath(path).parts[1:])

    def lstat(self, path):
        if path == self.redirect:
            return SimpleNamespace(st_mode=stat.S_IFLNK, st_size=4)
        return self.local(path).lstat()

    def listdir(self, path):
        return [child.name for child in self.local(path).iterdir()]

    def mkdir(self, path, mode):
        self.local(path).mkdir()

    def open(self, path, mode):
        if mode == 'rb':
            return self.local(path).open(mode)
        assert mode == 'wx'
        stream = self.local(path).open('xb')
        stream.chmod = lambda _: None
        return stream

    def close(self):
        pass


@pytest.fixture
def remote(d2b, monkeypatch, tmp_path):
    sftp = SftpDouble(tmp_path / 'sftp')
    calls, connections = [], []

    def ensure(remote):
        def exec_command(command, timeout):
            python, flag, boot, sub, *_ = command.split()
            assert (python, flag) == ('python3', '-B')
            calls.append((sub, boot))
            doc = {'ok': True, 'release': remote.binding['release_id'], 'files_sha256': remote.binding['files_sha256']}
            channel_in = io.StringIO()
            channel_in.channel = SimpleNamespace(shutdown_write=lambda: None)
            channel_out = io.BytesIO(json.dumps(doc).encode())
            channel_out.channel = SimpleNamespace(recv_exit_status=lambda: 0)
            return channel_in, channel_out, io.BytesIO()

        def open_channel(*args, **kwargs):
            response = io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}')
            return SimpleNamespace(settimeout=lambda _: None, sendall=lambda data: calls.append(('tcpip', data)),
                                   recv=response.read, close=response.close)

        remote.client = SimpleNamespace(open_sftp=lambda: sftp, exec_command=exec_command,
                                        get_transport=lambda: SimpleNamespace(open_channel=open_channel))
        connections.append(remote.client)

    monkeypatch.setattr(d2b.Remote, 'ensure', ensure)
    return SimpleNamespace(sftp=sftp, calls=calls, connections=connections)


def test_structured_index_yields_deterministic_aliases_and_exact_bytes(d2b, review):
    binding, data = d2b.snapshot_payload(review.root, review.index, review.approved)
    expected = dict(SOURCES)
    del expected['tests/fixture.py']
    expected[d2b.BASE] = expected[d2b.BOOTSTRAP]
    expected[d2b.BOOTSTRAP] = expected.pop(d2b.LAUNCHER)
    assert data == expected
    assert binding['review_index'].encode() == review.index.read_bytes()
    assert binding['review_index_sha256'] == review.approved
    assert binding['files'][d2b.BASE]['source'] == d2b.BOOTSTRAP
    assert binding['files'][d2b.BOOTSTRAP]['source'] == d2b.LAUNCHER
    assert binding['bootstrap_sha256'] == sha(SOURCES[d2b.LAUNCHER])
    digest = sha(''.join(f'{rel}:{sha(content)}\n' for rel, content in sorted(expected.items())).encode())
    assert binding['files_sha256'] == digest
    assert binding['release_id'] == digest[:16]


@pytest.mark.parametrize('mutation', ['index', 'same-size', 'missing', 'extra', 'hardlink'])
def test_approved_index_and_complete_snapshot_are_required(d2b, review, mutation):
    source = review.root / 'tests/fixture.py'
    if mutation == 'index':
        review.index.write_bytes(review.index.read_bytes() + b'\n')
    elif mutation == 'same-size':
        source.write_bytes(b'x' * source.stat().st_size)
    elif mutation == 'missing':
        source.unlink()
    elif mutation == 'extra':
        write(review.root, 'tests/extra.py', b'extra')
    else:
        os.link(source, review.index.with_name('copy'))
    with pytest.raises(d2b.batch.Refuse):
        d2b.snapshot_payload(review.root, review.index, review.approved)


@pytest.mark.parametrize('bad_path', ['../main.py', 'services\\agent\\main.py', '/etc/main.py',
                                      'services//main.py', 'apps/web/INDEX.html', 'scripts/b_round_base.py'])
def test_index_rejects_ambiguous_paths_and_existing_alias(d2b, review, bad_path):
    review.doc['files'][bad_path] = next(iter(review.doc['files'].values()))
    with pytest.raises(d2b.batch.Refuse):
        d2b.binding_for(json.dumps(review.doc))


def test_duplicate_json_keys_and_legacy_pin_are_refused_before_network(d2b, review, monkeypatch):
    duplicated = review.index.read_text().replace('"files":', '"files": {}, "files":')
    with pytest.raises(d2b.batch.Refuse, match='Duplicate JSON key'):
        d2b.binding_for(duplicated)
    write(d2b.batch.PRIVATE, 'stage.json', b'{"release_id": "aa11111111111111"}')
    monkeypatch.setattr(d2b.Remote, 'ensure', lambda _: pytest.fail('No network permitted'))
    with pytest.raises(d2b.batch.Refuse, match='release binding'):
        d2b.preflight_command(review.approved)


def test_consistent_replacement_pin_still_requires_external_approval(d2b, review, monkeypatch):
    replacement = d2b.binding_for(json.dumps(review.doc))
    assert replacement['review_index_sha256'] != review.approved
    write(d2b.batch.PRIVATE, 'stage.json', json.dumps(replacement).encode())
    monkeypatch.setattr(d2b.Remote, 'ensure', lambda _: pytest.fail('No network permitted'))
    with pytest.raises(d2b.batch.Refuse, match='approved review index'):
        d2b.preflight_command(review.approved)
    with pytest.raises(d2b.batch.Refuse, match='approved review index'):
        d2b.execute(SimpleNamespace(manifest_sha256=review.approved))


def test_dry_run_emits_mapping_without_creating_pin(d2b, review, monkeypatch, capsys):
    monkeypatch.setattr(d2b.Remote, 'ensure', lambda _: pytest.fail('No network permitted'))
    args = SimpleNamespace(root=review.root, manifest=review.index, manifest_sha256=review.approved, dry_run=True)
    assert d2b.stage(args) == 0
    receipt = json.loads(capsys.readouterr().out)
    assert receipt['dry_run'] is True and receipt['review_index_sha256'] == review.approved
    assert receipt['mapping'][d2b.BOOTSTRAP]['source'] == d2b.LAUNCHER
    assert not d2b.batch.PRIVATE.exists()


def test_upload_uses_captured_bytes_and_pin_retains_the_mapping(d2b, review, remote, monkeypatch, capsys):
    scan = d2b.batch.secret_scan

    def mutate_after_capture(files, **kwargs):
        (review.root / d2b.LAUNCHER).write_bytes(b'mutated after approved read')
        return scan(files, **kwargs)

    monkeypatch.setattr(d2b.batch, 'secret_scan', mutate_after_capture)
    args = SimpleNamespace(root=review.root, manifest=review.index, manifest_sha256=review.approved, dry_run=False)
    assert d2b.stage(args) == 0
    pin = d2b.read_pin(review.approved)
    receipt = json.loads(capsys.readouterr().out)
    assert d2b.identity(pin) == {key: receipt[key] for key in d2b.identity(pin)}
    assert [sub for sub, _ in remote.calls] == ['verify', 'link']
    boot = remote.calls[0][1]
    assert remote.sftp.local(boot).read_bytes() == SOURCES[d2b.LAUNCHER]
    connection = d2b.Remote()
    connection.binding = pin
    before = len(remote.connections)
    assert connection.helper('status')['ok'] is True
    assert len(remote.connections) == before + 1

    pin['files'][d2b.BOOTSTRAP]['source'] = d2b.BOOTSTRAP
    d2b.batch.STAGE.write_text(json.dumps(pin), encoding='utf-8')
    with pytest.raises(d2b.batch.Refuse, match='inconsistent'):
        d2b.read_pin(review.approved)


@pytest.mark.parametrize('mutation', ['bootstrap', 'base', 'engine', 'manifest', 'extra', 'missing', 'link'])
def test_helper_reverifies_pinned_bytes_before_executing_candidate(d2b, review, remote, mutation):
    binding, data = d2b.snapshot_payload(review.root, review.index, review.approved)
    write(d2b.batch.PRIVATE, 'stage.json', json.dumps(binding).encode())
    connection = d2b.Remote()
    connection.binding = d2b.read_pin(review.approved)
    d2b.upload(connection, binding, data)
    directory = connection.verify_release()
    connection.helper('status')
    affected = {'bootstrap': d2b.BOOTSTRAP, 'base': d2b.BASE, 'engine': 'services/agent/main.py',
                'manifest': d2b.MANIFEST}.get(mutation)
    if affected:
        path = remote.sftp.local(directory + '/' + affected)
        path.write_bytes(b'x' * path.stat().st_size)
    elif mutation == 'extra':
        write(remote.sftp.local(directory), 'scripts/__pycache__/unlisted.pyc', b'unlisted')
    elif mutation == 'missing':
        remote.sftp.local(directory + '/' + d2b.BOOTSTRAP).unlink()
    else:
        remote.sftp.redirect = directory + '/' + d2b.BOOTSTRAP
    with pytest.raises(d2b.batch.Refuse, match='pinned release'):
        connection.helper('start')
    assert [sub for sub, _ in remote.calls] == ['status']


def test_direct_dispatch_records_refused_drift_as_unsent(d2b, review, remote, monkeypatch):
    binding, data = d2b.snapshot_payload(review.root, review.index, review.approved)
    write(d2b.batch.PRIVATE, 'stage.json', json.dumps(binding).encode())
    connection = d2b.Remote()
    connection.binding = d2b.read_pin(review.approved)
    d2b.upload(connection, binding, data)
    directory = connection.verify_release()
    remote.sftp.local(directory + '/services/agent/main.py').write_bytes(b'xxxxxx')
    day = '2000-01-01'
    monkeypatch.setattr(d2b.batch, 'today_utc', lambda: day)
    guard = {'enabled': True, 'day_utc': day, 'd2b_authorized_day_utc': day, 'limit_usd': '0.50',
             'remaining_usd': '0.50', 'reserved_usd': '0.00',
             'quota_remaining': {'calls_remaining': 2, 'runs_remaining': 2, 'output_tokens_remaining': 2048}}
    events = []

    def halt(reason, **kwargs):
        raise d2b.batch.Halt(reason)

    controller = SimpleNamespace(wait_available=lambda: guard, refresh=lambda: None, halt=halt,
                                 api=d2b.batch.Api(connection, 'fixture', 'auto'),
                                 journal=SimpleNamespace(append=lambda event, **data: events.append({'e': event, **data})))
    controller.post = lambda *args: d2b.batch.Batch.post(controller, *args)
    with pytest.raises(d2b.batch.Halt, match='post_transport_error'):
        d2b.dispatch(controller, d2b.CELLS[0], 0, day)
    assert [event['e'] for event in events] == ['intent', 'transport']
    assert events[-1]['sent'] is False and not remote.calls


@pytest.mark.parametrize('operation, error_type', [
    *[(operation, OSError) for operation in ('open_sftp', 'lstat', 'listdir', 'open', 'read', 'close')],
    ('open_sftp', SSHException), ('read', SSHException),
])
def test_sftp_observation_failure_refuses_post_without_fallback(d2b, review, remote, monkeypatch, operation, error_type):
    binding, data = d2b.snapshot_payload(review.root, review.index, review.approved)
    connection = d2b.Remote()
    connection.binding = binding
    d2b.upload(connection, binding, data)

    def fail(*args):
        raise error_type('sensitive observation details')

    if operation == 'open_sftp':
        ensure = connection.ensure

        def ensure_with_failed_sftp():
            ensure()
            connection.client.open_sftp = fail

        monkeypatch.setattr(connection, 'ensure', ensure_with_failed_sftp)
    elif operation == 'read':
        def open_with_failed_read(*args):
            stream = io.BytesIO()
            stream.read = fail
            return stream

        monkeypatch.setattr(remote.sftp, 'open', open_with_failed_read)
    else:
        monkeypatch.setattr(remote.sftp, operation, fail)

    with pytest.raises(d2b.batch.Refuse) as error:
        connection.verify_release()
    assert str(error.value) == 'Cannot verify the D2B pinned release over SFTP'

    api = d2b.batch.Api(connection, 'fixture', 'auto')
    events = []

    def halt(reason, **kwargs):
        raise d2b.batch.Halt(reason)

    controller = SimpleNamespace(api=api, refresh=lambda: None, halt=halt,
                                 journal=SimpleNamespace(append=lambda event, **data: events.append({'e': event, **data})))
    observed_connections = len(remote.connections)
    with pytest.raises(d2b.batch.Halt, match='post_transport_error'):
        d2b.batch.Batch.post(controller, d2b.CELLS[0], {})
    assert [event['e'] for event in events] == ['intent', 'transport']
    assert events[-1]['sent'] is False and events[-1]['error'] == 'Refuse:'
    assert len(remote.connections) == observed_connections + 1 and not remote.calls


def test_connection_failure_retains_base_channel_open_semantics(d2b, review, monkeypatch):
    binding, _ = d2b.snapshot_payload(review.root, review.index, review.approved)
    connection = d2b.Remote()
    connection.binding = binding

    def fail():
        raise OSError('connection failed')

    monkeypatch.setattr(connection, 'ensure', fail)
    api = d2b.batch.Api(connection, 'fixture', 'tcpip')
    with pytest.raises(d2b.batch.ChannelOpenFailed, match='OSError'):
        api.request('POST', '/api/runs')


@pytest.mark.parametrize('method', ['GET', 'POST'])
def test_direct_http_verifies_on_its_own_connection_and_never_falls_back_on_drift(d2b, review, remote, method):
    binding, data = d2b.snapshot_payload(review.root, review.index, review.approved)
    connection = d2b.Remote()
    connection.binding = binding
    d2b.upload(connection, binding, data)
    api = d2b.batch.Api(connection, 'fixture', 'auto')
    assert api.request(method, '/api/runs').status == 200
    assert len(remote.connections) == 2  # upload and validated HTTP; no second ensure before sending
    assert remote.calls[0][1].startswith(method.encode() + b' /api/runs')
    boot = connection.release_directory() + '/' + d2b.BOOTSTRAP
    remote.sftp.local(boot).write_bytes(b'x' * len(SOURCES[d2b.LAUNCHER]))
    with pytest.raises(d2b.batch.Refuse, match='pinned release bytes'):
        api.request(method, '/api/runs')
    assert len(remote.connections) == 3
    assert len(remote.calls) == 1
