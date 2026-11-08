"""P5 candidate tool: package/manifest/verify/extract and SQLite snapshot/restore.

Everything is local and synthetic: a throw-away source tree and throw-away SQLite databases under tmp_path. No
network, no Docker, no provider, no credentials. The single read of the real repository (``test_real_repository_*``)
only reads files and writes to tmp_path. These tests were written without being run by their author.
"""
import contextlib
import gzip
import hashlib
import importlib.util
import io
import json
import re
import sqlite3
import sys
import tarfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from services.agent import recovery  # noqa: E402

RUN = 'a' * 32
COUNTERS = {'runs': 3, 'calls': 5, 'output_tokens_reserved': 5120}
CLOCK = lambda: '2000-01-01T00:00:00.000+00:00'  # noqa: E731
DDL = ("CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, status TEXT NOT NULL, model TEXT NOT NULL, levels TEXT NOT NULL, summary TEXT NOT NULL); "
       "CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, kind TEXT NOT NULL, data TEXT NOT NULL); "
       "CREATE TABLE IF NOT EXISTS run_config (run_id TEXT PRIMARY KEY, config TEXT NOT NULL); "
       "CREATE TABLE IF NOT EXISTS legacy_experiment (run_id TEXT PRIMARY KEY, experiment TEXT NOT NULL, frozen_at TEXT NOT NULL);")  # same tables as main.init_db


@pytest.fixture(scope='module')
def p5():
    spec = importlib.util.spec_from_file_location('p5_candidate_under_test', REPO / 'scripts' / 'p5_candidate.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha(data):
    return hashlib.sha256(data).hexdigest()


def put(root, rel, data=b'x\n'):
    path = Path(root).joinpath(*rel.split('/'))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data if isinstance(data, bytes) else data.encode('utf-8'))
    return path


@pytest.fixture
def tree(tmp_path, p5):
    """Synthetic repository: every required file with placeholder content, plus the REAL aggregator bytes (read only)."""
    root = tmp_path / 'repo'
    for rel in p5.REQUIRED_FILES:
        put(root, rel, '# SYNTHETIC ' + rel + '\n')
    put(root, p5.AGGREGATOR, (REPO / p5.AGGREGATOR).read_bytes())
    return root


def build(p5, tree, tmp_path, name='cand', **kwargs):
    out = tmp_path / 'out'
    out.mkdir(exist_ok=True)
    pkg, man = out / (name + '.tar.gz'), out / (name + '.json')
    return pkg, man, p5.package(pkg, man, root=tree, clock=CLOCK, **kwargs)


def code_of(call, *args, **kwargs):
    with pytest.raises(Exception) as caught:
        call(*args, **kwargs)
    return getattr(caught.value, 'code', None)


# ---------------------------------------------------------------- policy

@pytest.mark.parametrize('rel', ['services/agent/main.py', 'services/agent/sub/helper.py', 'apps/web/index.html', 'apps/web/assets/app.js', 'infra/Caddyfile',
                                 'infra/agent-escape-room.env.example', 'scripts/evaluation/aggregate_reports.py', 'requirements.txt', 'scripts/backup_state.py'])
def test_allowlisted_paths_are_admitted(p5, rel):
    p5.check_member_path(rel)


@pytest.mark.parametrize('rel,code', [
    ('../evil.py', 'unsafe_path'), ('/abs/evil.py', 'unsafe_path'), ('services/agent/../../evil.py', 'unsafe_path'), ('services\\agent\\evil.py', 'unsafe_path'),
    ('C:evil.py', 'unsafe_path'), ('infra/x.example:stream', 'unsafe_path'), ('.private/key', 'unsafe_path'), ('apps/web/.env', 'unsafe_path'),
    ('services//agent/x.py', 'unsafe_path'), ('services/agent/x.py ', 'unsafe_path'), ('services/agent/x.py\x00', 'unsafe_path'), ('', 'unsafe_path'),
    ('a/' * 200 + 'x.py', 'unsafe_path'), (None, 'unsafe_path'),
    ('services/agent/runs.sqlite3', 'denied_name'), ('infra/credentials.json', 'denied_name'), ('infra/agent.pem', 'denied_name'), ('infra/known_hosts', 'denied_name'),
    ('infra/operator-access.json', 'denied_name'), ('services/agent/secrets.json', 'denied_name'),
    ('docs/evidencia/ola3/report.json', 'denied_segment'), ('apps/web/node_modules/x.js', 'denied_segment'), ('services/agent/__pycache__/m.pyc', 'denied_segment'),
    ('scripts/evaluation/artifacts/r.json', 'denied_segment'),
    ('docs/notes.md', 'not_allowlisted'), ('tablero/index.html', 'not_allowlisted'), ('scripts/deploy_control.py', 'not_allowlisted'),
    ('services/agent/notes.md', 'not_allowlisted'), ('tests/test_x.py', 'not_allowlisted'),
])
def test_forbidden_paths_are_refused_with_a_stable_code(p5, rel, code):
    assert code_of(p5.check_member_path, rel) == code


def test_tests_are_admitted_only_when_requested(p5):
    p5.check_member_path('tests/test_x.py', with_tests=True)
    assert code_of(p5.check_member_path, 'tests/test_x.py', with_tests=False) == 'not_allowlisted'


# ---------------------------------------------------------------- package and manifest

def test_package_manifest_lists_hashes_and_the_imported_aggregator(p5, tree, tmp_path):
    pkg, man, result = build(p5, tree, tmp_path)
    manifest = json.loads(man.read_text(encoding='utf-8'))
    paths = [e['path'] for e in manifest['files']]
    assert manifest['schema'] == 'escape-p5-candidate/v1' and paths == sorted(paths) and set(paths) == set(p5.REQUIRED_FILES)
    for entry in manifest['files']:
        data = (tree / Path(*entry['path'].split('/'))).read_bytes()
        assert entry['sha256'] == sha(data) and entry['size'] == len(data)
    real = (REPO / p5.AGGREGATOR).read_bytes()
    assert manifest['aggregator']['path'] == 'scripts/evaluation/aggregate_reports.py' and manifest['aggregator']['sha256'] == sha(real)
    assert manifest['aggregator']['version'] == re.search(rb'AGGREGATOR_VERSION\s*=\s*"([^"]+)"', real).group(1).decode()
    assert manifest['archive']['sha256'] == sha(pkg.read_bytes()) == result['archive_sha256']
    assert manifest['candidate_id'] == manifest['files_sha256'][:16] and manifest['allowlist']['includes_tests'] is False
    assert 'authenticity' in p5.verify_package(pkg, man)


def test_verify_accepts_a_good_package_and_smokes_the_packaged_aggregator(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    verified = p5.verify_package(pkg, man, smoke=True)
    assert verified['ok'] and verified['files'] == len(p5.REQUIRED_FILES)
    assert verified['aggregator_smoke']['synthetic_hash_check'] == 'verified' and 'aggregator_smoke' in verified['checks']


def test_default_manifest_sits_beside_the_package_and_output_is_deterministic(p5, tree, tmp_path):
    out = tmp_path / 'out'
    out.mkdir()
    first = p5.package(out / 'a.tar.gz', root=tree, clock=CLOCK)
    second = p5.package(out / 'b.tar.gz', root=tree, clock=CLOCK)
    assert (out / 'a.tar.gz.manifest.json').is_file() and p5.verify_package(out / 'a.tar.gz')['ok']
    assert first['archive_sha256'] == second['archive_sha256']  # sorted members, mtime 0, fixed clock


def test_package_excludes_secrets_private_environments_and_user_artifacts(p5, tree, tmp_path):
    junk = {'.env': 'VULTR_INFERENCE_KEY=sentinel-secret-1\n', '.private/demo_ed25519': 'sentinel-key-2', 'services/agent/runs.sqlite3': 'db', 'services/agent/runs.sqlite3-wal': 'wal',
            'apps/web/.env': 'ESCAPE_OPERATOR_TOKEN=sentinel-secret-3\n', 'services/agent/__pycache__/main.cpython-312.pyc': 'pyc', 'infra/operator-access.json': '{"operator_token": "sentinel-secret-4"}',
            'artifacts/out.json': '{}', 'venv/lib/x.py': 'x', 'docs/evidencia/ola3/report.json': '{}', 'tablero/index.html': '<p>x</p>', 'tests/test_x.py': 'x',
            'scripts/other.py': 'x', 'scripts/deploy_control.py': 'x', 'apps/web/node_modules/x.js': 'x', 'infra/known_hosts': 'host', 'services/agent/secrets.json': '{}',
            'scripts/evaluation/artifacts/r.json': '{}', 'services/agent/notes.md': 'x', 'apps/web/uploads/user.html': 'x'}
    for rel, data in junk.items():
        put(tree, rel, data)
    pkg, man, result = build(p5, tree, tmp_path)
    with tarfile.open(fileobj=io.BytesIO(pkg.read_bytes()), mode='r:gz') as tar:
        names = set(tar.getnames())
    assert names == set(p5.REQUIRED_FILES) | {p5.EMBEDDED_MANIFEST}
    raw = gzip.decompress(pkg.read_bytes())
    for marker in (b'sentinel-secret-1', b'sentinel-key-2', b'sentinel-secret-3', b'sentinel-secret-4'):
        assert marker not in raw
    assert result['excluded_total'] > 0 and len(result['excluded_paths']) <= p5.LISTED
    assert 'services/agent/runs.sqlite3' in result['excluded_paths'] and 'apps/web/uploads/' in result['excluded_paths']
    assert not any('__pycache__' in path for path in result['excluded_paths'])  # bytecode caches are skipped silently


def test_tests_directory_is_packaged_only_with_the_flag(p5, tree, tmp_path):
    put(tree, 'tests/test_a.py', '# SYNTHETIC\n')
    _, man, _ = build(p5, tree, tmp_path, name='plain')
    assert 'tests/test_a.py' not in [e['path'] for e in json.loads(man.read_text())['files']]
    pkg2, man2, _ = build(p5, tree, tmp_path, name='tested', with_tests=True)
    manifest = json.loads(man2.read_text())
    assert 'tests/test_a.py' in [e['path'] for e in manifest['files']] and manifest['allowlist']['includes_tests'] is True
    assert p5.verify_package(pkg2, man2)['includes_tests'] is True


def test_optional_files_are_included_when_present(p5, tree, tmp_path):
    put(tree, 'scripts/p5_config_check.py', '# SYNTHETIC\n')
    _, man, _ = build(p5, tree, tmp_path)
    assert 'scripts/p5_config_check.py' in [e['path'] for e in json.loads(man.read_text())['files']]


def test_empty_secret_placeholders_are_not_mistaken_for_secrets(p5, tree, tmp_path):
    put(tree, 'infra/agent-escape-room.env.example', 'VULTR_INFERENCE_KEY=\nESCAPE_MODEL=\nESCAPE_OPERATOR_TOKEN=\nESCAPE_DB=/var/lib/x/runs.sqlite3\n')
    assert build(p5, tree, tmp_path)[2]['ok']


# Build secret-shaped negatives in the temporary tree, so the packaged test source is not itself the fixture.
FAKE_TOKEN = 'abcdef' + '123456'


@pytest.mark.parametrize('rel,content,rule', [
    ('infra/prod.env.example', f'ESCAPE_OPERATOR_TOKEN={FAKE_TOKEN}\n', 'secret_assignment'),
    ('infra/prod.json', json.dumps({'operator_token': FAKE_TOKEN}), 'secret_json_field'),
    ('services/agent/extra.py', f'K = """-----BEGIN {"OPENSSH PRIVATE KEY"}-----"""\n', 'private_key_block'),
    ('infra/h.conf', f'Authorization: Bearer {"abcdefghijklmnopqrstuvwxyz0123"}\n', 'bearer_token'),
])
def test_secret_looking_content_in_an_allowed_file_refuses_packaging(p5, tree, tmp_path, rel, content, rule):
    put(tree, rel, content)
    out = tmp_path / 'out'
    out.mkdir()
    with pytest.raises(p5.CandidateError) as caught:
        p5.package(out / 'c.tar.gz', root=tree, clock=CLOCK)
    assert caught.value.code == 'secret_detected'
    assert caught.value.message.startswith(f'rule {rule} matched')
    assert 'abcdef' not in str(caught.value) and not list(out.iterdir())


def test_symlink_in_an_allowed_tree_is_refused(p5, tree, tmp_path):
    target = put(tree, 'services/agent/real_extra.py', '# SYNTHETIC\n')
    try:
        (tree / 'services' / 'agent' / 'link.py').symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip('symlinks are not available here')
    with pytest.raises(p5.CandidateError) as caught:
        build(p5, tree, tmp_path)
    assert caught.value.code == 'symlink_refused'


def test_missing_required_file_refuses_packaging(p5, tree, tmp_path):
    (tree / 'services' / 'agent' / 'recovery.py').unlink()
    with pytest.raises(p5.CandidateError) as caught:
        build(p5, tree, tmp_path)
    assert caught.value.code == 'missing_required' and 'recovery.py' in str(caught.value)


def test_package_never_overwrites_an_existing_file(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    before = (pkg.read_bytes(), man.read_bytes())
    assert code_of(p5.package, pkg, tmp_path / 'out' / 'other.json', root=tree) == 'exists'
    assert code_of(p5.package, tmp_path / 'out' / 'new.tar.gz', man, root=tree) == 'exists'
    assert (pkg.read_bytes(), man.read_bytes()) == before
    assert not (tmp_path / 'out' / 'new.tar.gz').exists() and not [p for p in (tmp_path / 'out').iterdir() if 'partial' in p.name]


def test_package_output_is_refused_inside_an_evidence_directory(p5, tree, tmp_path):
    evidence = tmp_path / 'docs' / 'evidencia'
    evidence.mkdir(parents=True)
    assert code_of(p5.package, evidence / 'c.tar.gz', root=tree) == 'evidence_dir_refused'
    assert not list(evidence.iterdir())


# ---------------------------------------------------------------- tampering

def test_one_flipped_byte_in_the_archive_is_rejected(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    data = bytearray(pkg.read_bytes())
    data[len(data) // 2] ^= 0xFF
    pkg.write_bytes(bytes(data))
    assert code_of(p5.verify_package, pkg, man) == 'archive_hash_mismatch'
    assert code_of(p5.extract, pkg, tmp_path / 'release', man) == 'archive_hash_mismatch'
    assert not (tmp_path / 'release').exists()


def test_edited_manifest_hash_is_rejected(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    manifest = json.loads(man.read_text())
    manifest['files'][0]['sha256'] = '0' * 64
    man.write_text(json.dumps(manifest))
    assert code_of(p5.verify_package, pkg, man) == 'manifest_hash_mismatch'


def test_coherently_edited_manifest_still_fails_against_the_member_bytes(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    manifest = json.loads(man.read_text())
    manifest['files'][0]['sha256'] = '0' * 64
    manifest['files_sha256'] = p5._combined({e['path']: e for e in manifest['files']})
    man.write_text(json.dumps(manifest))
    assert code_of(p5.verify_package, pkg, man) == 'member_hash_mismatch'


def test_manifest_cannot_list_a_traversal_or_a_forbidden_path(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    for rel, code in (('../evil.py', 'unsafe_path'), ('docs/x.md', 'not_allowlisted'), ('services/agent/x.sqlite3', 'denied_name')):
        manifest = json.loads(man.read_text())
        manifest['files'].append({'path': rel, 'sha256': '0' * 64, 'size': 1})
        edited = tmp_path / ('m-' + code + '.json')
        edited.write_text(json.dumps(manifest))
        assert code_of(p5.verify_package, pkg, edited) == code


def test_manifest_with_wrong_schema_or_missing_is_rejected(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    bad = tmp_path / 'bad.json'
    bad.write_text(json.dumps({'schema': 'something/else'}))
    assert code_of(p5.verify_package, pkg, bad) == 'manifest_unsupported'
    assert code_of(p5.verify_package, pkg, tmp_path / 'absent.json') == 'manifest_unreadable'


def add_member(tar, name, data):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def forge(p5, pkg, man, tmp_path, label, replace=None, drop=(), extras=(), embedded=None):
    """A package whose archive hash IS consistent with its manifest, so only the member-level checks can reject it."""
    manifest, contents = p5.read_package(pkg, man)
    contents = {k: v for k, v in {**contents, **(replace or {})}.items() if k not in drop}
    inner = {k: v for k, v in manifest.items() if k != 'archive'} if embedded is None else embedded
    raw = io.BytesIO()
    with gzip.GzipFile(fileobj=raw, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w') as tar:
            add_member(tar, p5.EMBEDDED_MANIFEST, json.dumps(inner).encode())
            for rel, data in sorted(contents.items()):
                add_member(tar, rel, data)
            for info, data in extras:
                tar.addfile(info, io.BytesIO(data) if data is not None else None)
    archive = raw.getvalue()
    folder = tmp_path / 'forged'
    folder.mkdir(exist_ok=True)
    out_pkg, out_man = folder / (label + '.tar.gz'), folder / (label + '.json')
    out_pkg.write_bytes(archive)
    out_man.write_text(json.dumps({**manifest, 'archive': {'file_name': out_pkg.name, 'sha256': sha(archive), 'size_bytes': len(archive)}}))
    return out_pkg, out_man


def regular(name, data=b'x\n'):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    return info, data


def test_the_forge_helper_itself_yields_a_valid_package(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    assert p5.verify_package(*forge(p5, pkg, man, tmp_path, 'plain'))['ok']


@pytest.mark.parametrize('name,code', [
    ('../evil.py', 'unsafe_path'), ('/abs/evil.py', 'unsafe_path'), ('services/agent/../../evil.py', 'unsafe_path'), ('services\\agent\\evil.py', 'unsafe_path'),
    ('C:evil.py', 'unsafe_path'), ('.private/key', 'unsafe_path'), ('services/agent/runs.sqlite3', 'denied_name'), ('docs/evidencia/ola3/report.json', 'denied_segment'),
    ('services/agent/__pycache__/x.pyc', 'denied_segment'), ('docs/notes.md', 'not_allowlisted'), ('tests/test_x.py', 'not_allowlisted'),
    ('services/agent/extra.py', 'member_not_in_manifest'),
])
def test_extra_or_escaping_archive_members_are_rejected_and_never_extracted(p5, tree, tmp_path, name, code):
    pkg, man, _ = build(p5, tree, tmp_path)
    label = 'extra-' + str(abs(hash(name)))
    forged = forge(p5, pkg, man, tmp_path, label, extras=[regular(name)])
    assert code_of(p5.verify_package, *forged) == code
    assert code_of(p5.extract, forged[0], tmp_path / 'release', forged[1]) == code
    assert not (tmp_path / 'release').exists() and not list(tmp_path.rglob('evil.py'))


@pytest.mark.parametrize('kind', [tarfile.SYMTYPE, tarfile.LNKTYPE])
def test_links_inside_the_archive_are_rejected(p5, tree, tmp_path, kind):
    pkg, man, _ = build(p5, tree, tmp_path)
    info = tarfile.TarInfo('services/agent/link.py')
    info.type, info.linkname = kind, '/etc/passwd'
    assert code_of(p5.verify_package, *forge(p5, pkg, man, tmp_path, 'link-' + str(ord(kind)), extras=[(info, None)])) == 'member_not_regular'


def test_member_content_swapped_with_a_consistent_archive_hash_is_rejected(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    forged = forge(p5, pkg, man, tmp_path, 'swap', replace={'services/agent/main.py': b'# tampered\n'})
    assert code_of(p5.verify_package, *forged) == 'member_hash_mismatch'


def test_missing_member_and_mismatched_embedded_manifest_are_rejected(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    assert code_of(p5.verify_package, *forge(p5, pkg, man, tmp_path, 'drop', drop=('services/agent/usage.py',))) == 'missing_member'
    manifest, _ = p5.read_package(pkg, man)
    inner = {k: v for k, v in manifest.items() if k != 'archive'}
    inner['candidate_id'] = 'tampered'
    assert code_of(p5.verify_package, *forge(p5, pkg, man, tmp_path, 'emb', embedded=inner)) == 'embedded_manifest_mismatch'


def test_aggregator_that_lost_the_api_used_by_the_service_is_rejected(p5, tree, tmp_path):
    put(tree, p5.AGGREGATOR, 'AGGREGATOR_VERSION = "0"\n')
    with pytest.raises(p5.CandidateError) as caught:
        pkg, man, _ = build(p5, tree, tmp_path)
        p5.verify_package(pkg, man)
    assert caught.value.code == 'aggregator_invalid'


# ---------------------------------------------------------------- extract and verify-dir

def test_extract_writes_only_into_a_new_directory(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    release = tmp_path / 'release'
    result = p5.extract(pkg, release, man)
    assert result['files'] == len(p5.REQUIRED_FILES)
    assert sorted(p.name for p in tmp_path.iterdir() if p.name.startswith('release')) == ['release']
    assert (release / p5.EMBEDDED_MANIFEST).is_file()
    assert p5.verify_dir(release, man)['ok'] and p5.verify_dir(release)['ok']
    assert (release / 'scripts' / 'evaluation' / 'aggregate_reports.py').read_bytes() == (REPO / p5.AGGREGATOR).read_bytes()
    marker = release / 'services' / 'agent' / 'main.py'
    before = marker.read_bytes()
    assert code_of(p5.extract, pkg, release, man) == 'exists'
    empty = tmp_path / 'empty'
    empty.mkdir()
    assert code_of(p5.extract, pkg, empty, man) == 'exists' and not list(empty.iterdir())
    sentinel = put(tmp_path, 'sentinel', 'precious')
    assert code_of(p5.extract, pkg, sentinel, man) == 'exists' and sentinel.read_text() == 'precious'
    assert marker.read_bytes() == before


def test_extract_refuses_an_evidence_directory(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    evidence = tmp_path / 'docs' / 'evidencia'
    evidence.mkdir(parents=True)
    assert code_of(p5.extract, pkg, evidence / 'release', man) == 'evidence_dir_refused'
    assert not list(evidence.iterdir())


def test_verify_dir_detects_modified_missing_and_unlisted_files(p5, tree, tmp_path):
    pkg, man, _ = build(p5, tree, tmp_path)
    release = tmp_path / 'release'
    p5.extract(pkg, release, man)
    target = release / 'services' / 'agent' / 'main.py'
    original = target.read_bytes()
    target.write_bytes(original + b'# edited\n')
    with pytest.raises(p5.CandidateError) as caught:
        p5.verify_dir(release, man)
    assert caught.value.code == 'directory_mismatch' and caught.value.detail['modified'] == ['services/agent/main.py']
    target.write_bytes(original)
    (release / 'services' / 'agent' / '__pycache__').mkdir()
    (release / 'services' / 'agent' / '__pycache__' / 'main.cpython-312.pyc').write_bytes(b'pyc')
    assert p5.verify_dir(release, man)['ok']  # bytecode caches are ignored
    extra = put(release, 'services/agent/extra.py', '# not in the manifest\n')
    assert code_of(p5.verify_dir, release, man) == 'directory_mismatch'
    assert p5.verify_dir(release, man, allow_unlisted=True)['unlisted_allowed'] == ['services/agent/extra.py']
    extra.unlink()
    target.unlink()
    with pytest.raises(p5.CandidateError) as caught:
        p5.verify_dir(release, man)
    assert caught.value.detail['missing'] == ['services/agent/main.py']


# ---------------------------------------------------------------- SQLite snapshots

def make_db(path, wal=False):
    from services.agent import budget
    conn = sqlite3.connect(str(path))
    conn.executescript(DDL)
    budget.initialize(conn)
    recovery.ensure_schema(conn)
    conn.commit()
    if wal:
        conn.execute('PRAGMA journal_mode=WAL').fetchone()
    report = {'run': {'id': RUN, 'model': 'synthetic-model', 'summary': {}}, 'synthetic_fixture': True, 'sha256': 'f' * 64}
    conn.execute('INSERT INTO runs VALUES(?,?,?,?,?)', (RUN, 'completed', 'synthetic-model', '["secret"]', json.dumps(report)))
    conn.execute('INSERT INTO run_config VALUES(?,?)', (RUN, '{}'))
    conn.execute('INSERT INTO events(run_id,kind,data) VALUES(?,?,?)', (RUN, 'receipt', json.dumps({'id': 'r1'})))
    conn.execute('INSERT INTO events(run_id,kind,data) VALUES(?,?,?)', (RUN, 'run', json.dumps({'id': RUN, 'status': 'completed'})))
    conn.execute('INSERT INTO run_meta VALUES(?,?,?)', (RUN, 'fixture', '2000-01-01T00:00:00.000+00:00'))
    conn.execute('UPDATE budget SET runs=?, calls=?, output_tokens_reserved=? WHERE id=1', tuple(COUNTERS.values()))
    conn.commit()
    return conn


def file_state(live):
    return {p.name: (sha(p.read_bytes()), p.stat().st_mtime_ns) for p in (live, Path(str(live) + '-wal')) if p.exists()}


def leftovers(folder):
    return [p.name for p in Path(folder).iterdir() if 'partial' in p.name]


@pytest.mark.parametrize('wal', [False, True])
def test_snapshot_does_not_mutate_the_source_and_validates_read_only(p5, tmp_path, wal):
    live, snap = tmp_path / 'live.sqlite', tmp_path / 'snap.sqlite'
    conn = make_db(live, wal)  # in WAL mode the writer stays open, like the running service
    try:
        before = file_state(live)
        result = p5.snapshot(live, snap)
        assert file_state(live) == before
        assert result['counters_at_snapshot'] == COUNTERS and result['quotas_monotonic'] is True and 'warning' not in result
        assert result['validation'] == {'read_only': True, 'integrity': True, 'hash_matches_manifest': True}
        assert result['sha256'] == sha(snap.read_bytes()) and result['content_digests']['runs']['rows'] == 1
        assert not any(Path(str(snap) + s).exists() for s in ('-wal', '-shm', '-journal')) and not leftovers(tmp_path)
        with contextlib.closing(sqlite3.connect(snap.resolve().as_uri() + '?mode=ro', uri=True)) as copy:
            assert copy.execute('SELECT COUNT(*) FROM events').fetchone()[0] == 2
    finally:
        conn.close()


def test_verify_snapshot_is_read_only(p5, tmp_path):
    live, snap = tmp_path / 'live.sqlite', tmp_path / 'snap.sqlite'
    make_db(live).close()
    p5.snapshot(live, snap)
    before = sorted((p.name, sha(p.read_bytes())) for p in tmp_path.iterdir())
    assert p5.verify_snapshot(snap)['ok'] is True
    assert sorted((p.name, sha(p.read_bytes())) for p in tmp_path.iterdir()) == before  # no file created or changed


def test_restore_preserves_quotas_reports_and_blocks_admission(p5, tmp_path):
    live, snap, restored = tmp_path / 'live.sqlite', tmp_path / 'snap.sqlite', tmp_path / 'restored.sqlite'
    make_db(live).close()
    taken = p5.snapshot(live, snap)
    live_before, snap_before = sha(live.read_bytes()), sha(snap.read_bytes())
    result = p5.restore_snapshot(snap, restored)
    assert result['quotas_preserved'] and result['backup_unchanged'] and result['reports_and_tables_identical']
    assert recovery.counters_of_database(restored) == COUNTERS == recovery.counters_of_database(live)  # never reset to zero
    digests = p5.content_digests(restored)
    for table, value in taken['content_digests'].items():
        if value is not None:
            assert digests[table] == value, table
    with contextlib.closing(sqlite3.connect(restored.resolve().as_uri() + '?mode=ro', uri=True)) as conn:
        stored = json.loads(conn.execute('SELECT summary FROM runs WHERE id=?', (RUN,)).fetchone()[0])
    assert stored['sha256'] == 'f' * 64 and stored['synthetic_fixture'] is True  # the stored report is byte-for-byte what was saved
    status = recovery.database_status(restored)
    assert status['admission_block']['reason'] == 'restored_state_unreconciled' and status['restored_block']['block_id'] == result['block_id']
    with pytest.raises(recovery.RecoveryError):  # quotas cannot be lowered by reconciliation either
        recovery.reconcile_restored(restored, result['block_id'], {'runs': 0, 'calls': 0, 'output_tokens_reserved': 0}, 'synthetic test evidence')
    assert recovery.counters_of_database(restored) == COUNTERS
    assert sha(live.read_bytes()) == live_before and sha(snap.read_bytes()) == snap_before and not leftovers(tmp_path)


def test_a_modified_snapshot_is_rejected_and_nothing_is_restored(p5, tmp_path):
    live, snap, flipped = tmp_path / 'live.sqlite', tmp_path / 'snap.sqlite', tmp_path / 'flipped.sqlite'
    make_db(live).close()
    p5.snapshot(live, snap)
    p5.snapshot(live, flipped)
    with contextlib.closing(sqlite3.connect(str(snap))) as conn:  # an attempt to reset the quotas inside the copy
        conn.execute('UPDATE budget SET runs=0, calls=0, output_tokens_reserved=0')
        conn.commit()
    data = bytearray(flipped.read_bytes())
    data[len(data) // 2] ^= 0xFF
    flipped.write_bytes(bytes(data))
    for bad in (snap, flipped):
        dest = tmp_path / ('restored-' + bad.name)
        with pytest.raises(recovery.RecoveryError):
            p5.verify_snapshot(bad)
        with pytest.raises(recovery.RecoveryError):
            p5.restore_snapshot(bad, dest)
        assert not dest.exists() and not leftovers(tmp_path)
    assert recovery.counters_of_database(live) == COUNTERS


def test_a_missing_or_foreign_manifest_blocks_restore(p5, tmp_path):
    live, snap, other = tmp_path / 'live.sqlite', tmp_path / 'snap.sqlite', tmp_path / 'other.sqlite'
    make_db(live).close()
    p5.snapshot(live, snap)
    (tmp_path / 'snap.sqlite.manifest.json').unlink()
    with pytest.raises(recovery.RecoveryError):
        p5.restore_snapshot(snap, tmp_path / 'restored.sqlite')
    assert not (tmp_path / 'restored.sqlite').exists() and not other.exists()


def test_restore_and_snapshot_never_overwrite(p5, tmp_path):
    live, snap = tmp_path / 'live.sqlite', tmp_path / 'snap.sqlite'
    make_db(live).close()
    p5.snapshot(live, snap)
    existing = put(tmp_path, 'restored.sqlite', 'precious')
    with pytest.raises(recovery.RecoveryError):
        p5.restore_snapshot(snap, existing)
    assert existing.read_text() == 'precious'
    with pytest.raises(recovery.RecoveryError):
        p5.restore_snapshot(snap, snap)
    dest = tmp_path / 'new.sqlite'
    put(tmp_path, 'new.sqlite-wal', 'stale wal')
    with pytest.raises(recovery.RecoveryError):
        p5.restore_snapshot(snap, dest)
    assert not dest.exists()
    snap_before = snap.read_bytes()
    with pytest.raises(recovery.RecoveryError):
        p5.snapshot(live, snap)  # the destination is an existing snapshot
    with pytest.raises(recovery.RecoveryError):
        p5.snapshot(live, tmp_path / 'snap2.sqlite', tmp_path / 'snap.sqlite.manifest.json')  # the manifest already exists
    assert snap.read_bytes() == snap_before and not (tmp_path / 'snap2.sqlite').exists() and not leftovers(tmp_path)


def test_snapshot_and_restore_refuse_evidence_directories_and_remote_locations(p5, tmp_path):
    live, snap = tmp_path / 'live.sqlite', tmp_path / 'snap.sqlite'
    make_db(live).close()
    evidence = tmp_path / 'docs' / 'evidencia'
    evidence.mkdir(parents=True)
    assert code_of(p5.snapshot, live, evidence / 's.sqlite') == 'evidence_dir_refused'
    p5.snapshot(live, snap)
    assert code_of(p5.restore_snapshot, snap, evidence / 'r.sqlite') == 'evidence_dir_refused'
    assert not list(evidence.iterdir())
    assert code_of(p5.restore_snapshot, snap, 'https://example.invalid/restored.sqlite') == 'not_local_path'
    assert code_of(p5.snapshot, live, '//server/share/s.sqlite') == 'not_local_path'


# ---------------------------------------------------------------- CLI

def test_cli_exit_codes_and_json(p5, tree, tmp_path, capsys):
    pkg, man = tmp_path / 'c.tar.gz', tmp_path / 'c.json'
    assert p5.main(['package', '--out', str(pkg), '--manifest', str(man), '--root', str(tree)]) == 0
    assert json.loads(capsys.readouterr().out)['ok'] is True
    assert p5.main(['verify', '--package', str(pkg), '--manifest', str(man), '--smoke-aggregator']) == 0
    assert json.loads(capsys.readouterr().out)['aggregator_smoke']['ok'] is True
    assert p5.main(['extract', '--package', str(pkg), '--to', str(tmp_path / 'rel'), '--manifest', str(man)]) == 0
    capsys.readouterr()
    assert p5.main(['verify-dir', '--dir', str(tmp_path / 'rel'), '--manifest', str(man)]) == 0
    capsys.readouterr()
    data = bytearray(pkg.read_bytes())
    data[len(data) // 2] ^= 0xFF
    pkg.write_bytes(bytes(data))
    assert p5.main(['verify', '--package', str(pkg), '--manifest', str(man)]) == 2
    body = json.loads(capsys.readouterr().out)
    assert body['ok'] is False and body['code'] == 'archive_hash_mismatch'


def test_cli_snapshot_verify_restore(p5, tmp_path, capsys):
    live, snap, restored = tmp_path / 'live.sqlite', tmp_path / 'snap.sqlite', tmp_path / 'restored.sqlite'
    make_db(live).close()
    assert p5.main(['snapshot', '--db', str(live), '--out', str(snap)]) == 0
    capsys.readouterr()
    assert p5.main(['verify-snapshot', '--backup', str(snap)]) == 0
    capsys.readouterr()
    assert p5.main(['restore', '--backup', str(snap), '--to', str(restored)]) == 0
    assert json.loads(capsys.readouterr().out)['admission'] == 'blocked_until_reconciled'
    assert p5.main(['restore', '--backup', str(snap), '--to', str(restored)]) == 2  # never overwritten
    assert json.loads(capsys.readouterr().out)['ok'] is False


# ---------------------------------------------------------------- the real repository (read only)

def test_real_repository_package_contains_the_service_and_the_imported_aggregator(p5, tmp_path):
    out = tmp_path / 'out'
    out.mkdir()
    result = p5.package(out / 'c.tar.gz', out / 'c.json', root=REPO, clock=CLOCK)
    verified = p5.verify_package(out / 'c.tar.gz', out / 'c.json', smoke=True)
    names = {e['path'] for e in json.loads((out / 'c.json').read_text())['files']}
    for needed in ('scripts/evaluation/aggregate_reports.py', 'services/agent/operator.py', 'services/agent/recovery.py', 'apps/web/index.html',
                   'scripts/backup_state.py', 'scripts/p5_candidate.py', 'infra/agent-escape-room.env.example'):
        assert needed in names
    for module in sorted((REPO / 'services' / 'agent').glob('*.py')):
        assert 'services/agent/' + module.name in names
    assert not any(name.startswith(('docs/', 'tests/', 'tablero/')) for name in names)
    assert result['ok'] and verified['aggregator_smoke']['ok']
    from services.agent import operator as service_operator
    assert service_operator.AGGREGATOR_FILE.resolve().relative_to(REPO.resolve()).as_posix() == p5.AGGREGATOR


def test_real_repository_protocol_hash_matches_the_services_own_formula(p5, tmp_path):
    experiment = pytest.importorskip('services.agent.experiment')
    out = tmp_path / 'out'
    out.mkdir()
    p5.package(out / 'c.tar.gz', out / 'c.json', root=REPO, clock=CLOCK)
    protocol = json.loads((out / 'c.json').read_text())['protocol_sources']
    sources = experiment.protocol()['sources']
    assert protocol['files'] == sources['files'] and protocol['sha256'] == sources['sha256']
