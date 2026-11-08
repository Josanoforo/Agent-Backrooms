#!/usr/bin/env python3
"""SC4 / A5 offline receiver: candidate identity and actor/guard receipts. Standard library only.

  sc4_receipts.py check-candidate --scope local --package PKG --manifest M --manifest-sha256 HEX --dir CLEAN_COPY [...]
  sc4_receipts.py check-receipts  --scope local --package PKG --manifest M --manifest-sha256 HEX --scenario-receipt R [x5] --service-receipt S [...]

Both print ONE JSON decision. Exit 0 only when the requested scope is accredited; exit 2 for a rejection or for incomplete evidence.

Rules this file keeps (it never runs candidate code, never opens a network, never imports the candidate runtime):
  * Integrity and extraction reuse scripts/p5_candidate.py (loaded by path with the product runtime blocked). The manifest digest comes
    from the operator, outside the package; a manifest stored beside the bytes proves nothing by itself.
  * Receipts are consumed in the shape their frozen producers emit (sc2-actor-compatibility-a4/v1, invoice-actor-service-local/v1,
    local-invoice-verifier-proof/v1). Nothing here defines a parallel receipt format.
  * Validation is of data and links (exact JSON types, no duplicate keys, bounds, ledgers, identities, hashes), not of booleans alone.
  * Measurement (operator observations), simulation (provider double, synthetic invoices) and unknown are reported separately.
  * Scope is explicit: local never accredits private acceptance. A missing producer or field is reported as pending, never invented.
"""
import argparse
import ast
import hashlib
import importlib.util
import json
import math
import os
import re
import sys
from pathlib import Path

SCHEMA = 'sc4-receipts-decision/v1'
TOOL_VERSION = '1.0.0'
HERE = Path(__file__).resolve().parent
P5_PATH = HERE.parent / 'p5_candidate.py'

SCOPES = ('local', 'private', 'independent', 'global')
MAX_RECEIPT_BYTES = 4 << 20
MAX_ATTACHMENT_BYTES = 8 << 20
MAX_ATTACHMENTS = 64
MAX_NODES = 200000
MAX_DEPTH = 40
MAX_EVENTS = 400
MAX_CONTAINERS = 2000
MAX_CRITERIA = 400
MAX_LISTED = 200

A4_SCHEMA = 'sc2-actor-compatibility-a4/v1'
OFFLINE_SCHEMA = 'sc2-actor-compatibility-a4-offline/v1'
SERVICE_SCHEMA = 'invoice-actor-service-local/v1'
GUARD_SCHEMA = 'local-invoice-verifier-proof/v1'
INHERITANCE_SCHEMA = 'sc3-a2-inheritance/v1'
DIFF_SCHEMA = 'sc2-a4-integration-diff/v1'

INHERITANCE_PATH = 'docs/evidencia/sc3-lifecycle/a4-herencia-a2.json'
A4B_INHERITANCE_PATH = 'docs/evidencia/sc3-lifecycle/a4b-herencia-a2.json'
A4B_HARNESS = 'tests/integration/sc3_lifecycle_gaps.py'
DIFF_PATH = 'docs/evidencia/a4-diff-integracion.json'
A2_RECEIPT_STEMS = ('kill-running', 'cancel-client', 'second-guard-exclusion', 'two-runs-foreign-sentinel')
A2_SCOPE = 'verifier guard lifecycle only'
A2_GUARD_DEPENDENCIES = tuple('services/agent/' + n + '.py' for n in ('daemon_guard', 'guard_state', 'guard_client', 'invoice_verification'))
A2_DEPENDENCIES = A2_GUARD_DEPENDENCIES + ('services/agent/workflow.py',)

OPERATOR_HARNESS = 'tests/integration/sc2_actor_compatibility_local.py'
HARNESS_FILES = (OPERATOR_HARNESS, 'tests/integration/test_sc2_actor_compatibility.py', 'tests/integration/invoice_actor_service_local.py',
                 'tests/integration/test_invoice_actor_service_docker.py', 'tests/integration/guard_boundary_local.py')
SERVICE_HARNESS = ('tests/integration/invoice_actor_service_local.py', 'tests/integration/test_invoice_actor_service_docker.py')
TOOL_FILES = ('scripts/evaluation/sc4_receipts.py', 'tests/evaluation/test_sc4_receipts.py')
VERIFIER_PATH = 'services/agent/invoice_verifier.py'
# Frontier modules of the actor owner, the verifier guard and the two consumers (main, workflow) that A3/A4 receipts name.
FRONTIER_MODULES = tuple('services/agent/' + n + '.py' for n in (
    'actor_state', 'actor_wire', 'invoice_actor_broker', 'invoice_actor_client', 'invoice_actor_protocol', 'invoice_actor_runtime',
    'invoice_actor_service', 'daemon_guard', 'guard_state', 'guard_client', 'invoice_verification', 'invoice_verifier', 'main', 'workflow'))
# Default list of fixtures/tests that must be reachable by manifest (or by explicit attachment). The desk may add more with --require-path.
REQUIRED_PATHS = HARNESS_FILES + TOOL_FILES

SCENARIOS = ('cancel-api', 'owner-cut-provider-wait', 'owner-cut-before-close', 'lost-response-after-finish', 'second-run-exclusion')
A4B_SCENARIOS = ('controller-kill-running', 'cancel-api-verifier-running')
CODES = ('ok', 'product_counterexample', 'harness_error', 'precondition_missing')
KINDS = ('CREATE_PENDING', 'CREATE_ACK', 'START_PENDING', 'ACTIVE', 'CLOSE_PENDING', 'FINISH')
VARIANTS = ('legitimate', 'perturbed')
CONTROLLER_UID, ACTOR_UID, GUARD_UID, FOREIGN_UID = 65534, 1000, 65532, 65533
DENIAL_ERRNOS = ('ENOENT', 'EACCES', 'EPERM')
PAYLOAD_KEYS = {'CREATE_PENDING': ('controller_uid', 'intent_id', 'run_id', 'variant'), 'CREATE_ACK': ('container_id', 'intent_id'),
                'START_PENDING': ('intent_id',), 'ACTIVE': ('intent_id',), 'CLOSE_PENDING': ('intent_id',), 'FINISH': ('container_id', 'intent_id')}
IDENTITY_KEYS = ('container_id', 'installation_id', 'intent_id', 'run_id', 'variant')
OWNER_KEYS = ('cap_bnd', 'cap_eff', 'gids', 'groups', 'no_new_privileges', 'pid', 'uids')
RUNNING = [True, True, 'running']
ABSENT = [False, None, 'absent']
PRESERVED = [True, False, 'created']

HEX64, HEX32 = re.compile(r'[0-9a-f]{64}'), re.compile(r'[0-9a-f]{32}')
IMAGE = re.compile(r'sha256:[0-9a-f]{64}')
ZEROS = re.compile(r'0{16}')
GUARD_NAME = re.compile(r'escape-invoice-[0-9a-f]{32}')

DOES_NOT_ACCREDIT = (
    'private acceptance (a local fixture with a provider double never accredits it)',
    'independent reproduction by a different desk',
    'global completeness of SC4',
    'closure of SC2.3, SC2.4 or SC3 by M1 coverage',
    'authenticity of the package (integrity against an externally recorded digest only)',
)


class ReceiptError(Exception):
    def __init__(self, code, message=''):
        super().__init__(code + (': ' + message if message else ''))
        self.code, self.message = code, message


# ---------------------------------------------------------------- bytes, JSON and small typed helpers

def sha256(data):
    return hashlib.sha256(data).hexdigest()


def read_file(path, cap, label):
    text = os.fspath(path)
    if type(text) is not str or not text or '\x00' in text or '://' in text:
        raise ReceiptError('not_local_path', label + ' must be a local filesystem path')
    target = Path(text)
    try:
        if not target.is_file():
            raise ReceiptError('missing_file', label + ' was not found')
        with open(target, 'rb') as handle:
            data = handle.read(cap + 1)
    except OSError as exc:
        raise ReceiptError('unreadable_file', label + ': ' + type(exc).__name__) from exc
    if len(data) > cap:
        raise ReceiptError('file_too_large', label + ' exceeds its size bound')
    return data


def _no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate key')
        result[key] = value
    return result


def _no_constants(token):
    raise ValueError('non-finite number')


def _finite_float(token):
    value = float(token)
    if not math.isfinite(value):
        raise ValueError('non-finite number')
    return value


def strict_loads(data):
    """UTF-8 JSON with no duplicate keys at any depth, no NaN/Infinity and bounded depth and size."""
    try:
        value = json.loads(data.decode('utf-8'), object_pairs_hook=_no_duplicates, parse_constant=_no_constants, parse_float=_finite_float)
    except (ValueError, RecursionError) as exc:
        code = 'json_duplicate_key' if 'duplicate key' in str(exc) else 'json_invalid'
        raise ReceiptError(code, 'the document is not strict JSON (' + type(exc).__name__ + ')') from exc
    stack, nodes = [(value, 1)], 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ReceiptError('json_too_large', 'the document exceeds node or depth bounds')
        if type(item) is dict:
            stack.extend((child, depth + 1) for child in item.values())
        elif type(item) is list:
            stack.extend((child, depth + 1) for child in item)
    return value


def is_int(value):
    return type(value) is int


def is_hex(value, pattern=HEX64):
    return type(value) is str and pattern.fullmatch(value) is not None


def same(value, expected):
    """Equality that keeps the JSON type: True is not 1 and 1 is not 1.0."""
    if type(value) is not type(expected):
        return False
    if type(expected) is dict:
        return value.keys() == expected.keys() and all(same(value[key], expected[key]) for key in expected)
    if type(expected) is list:
        return len(value) == len(expected) and all(same(a, b) for a, b in zip(value, expected))
    return value == expected


def safe_rel(rel):
    if type(rel) is not str or not rel or len(rel) > 240 or '\x00' in rel or '\\' in rel or ':' in rel or rel.startswith('/'):
        return False
    return all(part not in ('', '.', '..') and part == part.strip() for part in rel.split('/'))


# ---------------------------------------------------------------- findings

class Report:
    """rejected = invalid or contradictory evidence; incomplete = missing or inapplicable evidence; pending = contract field with no producer."""

    def __init__(self):
        self.rejections, self.incomplete, self.pending = [], [], []

    @staticmethod
    def _item(code, where, message):
        return {'code': code, 'where': str(where)[:160], 'message': str(message)[:240]}

    def reject(self, code, where, message=''):
        self.rejections.append(self._item(code, where, message))

    def missing(self, code, where, message=''):
        self.incomplete.append(self._item(code, where, message))

    def pend(self, field, needed_for, note):
        self.pending.append({'field': field, 'needed_for': needed_for, 'note': note})

    @property
    def decision(self):
        if self.rejections:
            return 'rejected'
        if self.incomplete or self.pending:
            return 'incomplete'
        return 'accepted'


class Ctx:
    """One input (a receipt, a manifest, an attachment) reporting into the shared Report with its own label."""

    def __init__(self, rep, label):
        self.rep, self.label, self.bad_count, self.absent_count = rep, label, 0, 0

    def bad(self, code, where, message=''):
        self.bad_count += 1
        self.rep.reject(code, self.label + ':' + where, message)
        return False

    def absent(self, code, where, message=''):
        self.absent_count += 1
        self.rep.missing(code, self.label + ':' + where, message)
        return False

    def expect(self, condition, code, where, message=''):
        return True if condition else self.bad(code, where, message)

    @property
    def clean(self):
        return self.bad_count == 0 and self.absent_count == 0

    @property
    def verdict(self):
        return 'rejected' if self.bad_count else ('incomplete' if self.absent_count else 'accepted')


def exact_keys(ctx, value, expected, where):
    if type(value) is not dict:
        return ctx.bad('type_mismatch', where, 'an object is required')
    missing, extra = sorted(set(expected) - set(value)), sorted(set(value) - set(expected))
    if missing:
        ctx.bad('field_missing', where, 'missing: ' + ', '.join(missing[:8]))
    if extra:
        ctx.bad('field_unexpected', where, 'unexpected: ' + ', '.join(extra[:8]))
    return not missing and not extra


def fmt(ctx, value, kind, where):
    if kind == 'variant':
        good = type(value) is str and value in VARIANTS
    elif kind == 'hex64':
        good = is_hex(value)
    elif kind == 'hex32':
        good = is_hex(value, HEX32)
    elif kind == 'image':
        good = type(value) is str and IMAGE.fullmatch(value) is not None
    else:
        raise ValueError(kind)
    return ctx.expect(good, 'invalid_' + kind, where, 'the value does not have the required form')


def str_list(value, cap=64, maxlen=240):
    return (type(value) is list and 0 < len(value) <= cap and all(type(item) is str and 0 < len(item) <= maxlen for item in value)
            and len(set(value)) == len(value))


# ---------------------------------------------------------------- P5 loader: integrity APIs without the product runtime

_P5_CACHE = {}
_MISSING = object()
_BLOCKED = ('services', 'services.agent', 'services.agent.recovery')


def load_p5(path=None):
    """Load scripts/p5_candidate.py by path. Its optional `from services.agent import recovery` is blocked so no product runtime is imported."""
    target = str(Path(path) if path else P5_PATH)
    if target in _P5_CACHE:
        return _P5_CACHE[target]
    saved, path_before = {name: sys.modules.get(name, _MISSING) for name in _BLOCKED}, list(sys.path)
    try:
        for name in _BLOCKED:
            sys.modules[name] = None
        spec = importlib.util.spec_from_file_location('sc4_receipts_p5_candidate', target)
        if spec is None or spec.loader is None:
            raise ReceiptError('p5_unavailable', 'scripts/p5_candidate.py could not be loaded')
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    finally:
        for name, old in saved.items():
            if old is _MISSING:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = old
        sys.path[:] = path_before
    _P5_CACHE[target] = module
    return module


# ---------------------------------------------------------------- pending contract fields (no frozen producer exists for them)

PENDING_PRIVATE = (
    ('private.preflight_receipt', 'SC4 2a (C0)', 'Read-only preflight with every P-C* and P-S* predicate as pass/fail/unknown. No frozen producer exists.'),
    ('private.vm_identities', 'SC4 1f / 7.2', 'Guard, service and client UIDs, guard installation ID, Docker daemon ID and data root, verifier image ID and profile digest '
     'observed on the VM. The A4 scenario receipts carry only the actor installation, image and profile; daemon and data-root anchors are not emitted.'),
    ('private.vm_candidate_verify_dir', 'SC4 P-S1', 'verify-dir receipt on the VM against the externally recorded manifest digest.'),
    ('private.positive_report', 'SC4 2b (C1)', 'Sealed report of the legitimate variant with a guard verdict bound to run, variant, artifact SHA-256 and verifier container ID.'),
    ('private.f_veto_receipt', 'SC4 2c (C1)', 'F-veto on the private instance: actor_task_not_passed and zero guard transitions for the failed variant.'),
    ('private.f_guard_receipt', 'SC4 2c (C1)', 'F-guard on the same photo, including the artifact bytes (correct digest, false total) so the verdict can be re-derived.'),
    ('private.cost_counters', 'SC4 2d', 'Counters before/after and the sealed tariff per run. Estimated, not an invoice.'),
    ('private.crash_recovery_receipt', 'SC4 3a/3b (C2)', 'Barrier with ACK and Running=true observed on the private instance, recovery from another process, FINISH and the foreign sentinel.'),
    ('private.restitution_receipt', 'SC4 4b (C3)', 'Inventory per installation, counters and public-service continuity after the private lot.'),
)
PENDING_INDEPENDENT = (
    ('independent.reproduction_report', 'SC4 4a (C4)', 'Report by a desk different from the packager and the operator: same files_sha256 and candidate_id, its own hashes, '
     'verdicts and cost rebuilt from the sealed reports. No frozen producer exists.'),
)
PENDING_GLOBAL = (
    ('global.sc2_3_controller_separation', 'SC2.3', 'Controller identity with no alternative daemon access across the whole service, beyond the M1 invoice branch.'),
    ('global.sc2_4_branch_compatibility', 'SC2.4', 'Compatibility of levels, catalog, rooms, campaigns and suites; the A4 branch table records safe rejection, not compatibility.'),
    ('global.sc3_integrated_recovery_concurrency_cancellation', 'SC3', 'Remaining abrupt service-process recovery, concurrency and cancellation cases; the creation-uncertain platform barrier keeps its own evidence.'),
    ('global.central_closure_document', 'SC4 4c', 'Closure by Central with commands, results, candidate identity and limits.'),
)


def apply_scope(rep, scope):
    """The local layer is evaluated first. A wider scope only adds the fields that have no producer: it can never be satisfied by local evidence."""
    wanted = ()
    if scope in ('private', 'independent', 'global'):
        wanted += PENDING_PRIVATE
    if scope in ('independent', 'global'):
        wanted += PENDING_INDEPENDENT
    if scope == 'global':
        wanted += PENDING_GLOBAL
    for field, needed_for, note in wanted:
        rep.pend(field, needed_for, note)


# ---------------------------------------------------------------- candidate binding (digest, P5 integrity, extraction)

class Candidate:
    def __init__(self):
        self.manifest, self.entries, self.contents = None, {}, {}
        self.manifest_sha256 = self.candidate_id = self.files_sha256 = self.archive_sha256 = None
        self.includes_tests = None

    def sha_of(self, path):
        entry = self.entries.get(path)
        return entry['sha256'] if entry else None


def known_sha(cand, atts, path):
    return cand.sha_of(path) or (atts.get(path) or {}).get('sha256')


def load_checked_manifest(ctx, p5, path, expected_digest, option):
    """(manifest, entries) or None. The externally recorded digest is checked on the raw bytes first, then P5's own policy runs."""
    if not is_hex(expected_digest):
        ctx.bad('manifest_digest_invalid', option, 'the external manifest digest must be 64 lowercase hex characters')
        return None
    try:
        raw = read_file(path, p5.MAX_MANIFEST_BYTES, 'manifest')
    except ReceiptError as exc:
        ctx.bad(exc.code, 'manifest', exc.message)
        return None
    if sha256(raw) != expected_digest:
        ctx.bad('manifest_digest_mismatch', 'manifest', 'the manifest does not match the digest recorded outside the package')
        return None
    try:
        manifest = strict_loads(raw)
    except ReceiptError as exc:
        ctx.bad(exc.code, 'manifest', exc.message)
        return None
    if type(manifest) is not dict or manifest.get('schema') != p5.SCHEMA:
        ctx.bad('manifest_unsupported', 'manifest', 'unsupported manifest schema')
        return None
    try:
        entries = p5.validate_manifest(manifest)
    except p5.CandidateError as exc:
        ctx.bad(exc.code, 'manifest', exc.message)
        return None
    files_sha, cid = manifest.get('files_sha256'), manifest.get('candidate_id')
    if not (is_hex(files_sha) and type(cid) is str and cid == files_sha[:16]):
        ctx.bad('candidate_id_mismatch', 'manifest', 'candidate_id is not the first 16 hex characters of files_sha256')
        return None
    return manifest, entries


def bind_candidate(rep, p5, args):
    """Candidate or None. Links external manifest digest, candidate_id, files_sha256 and the archive bytes; reads the package in memory only."""
    ctx = Ctx(rep, 'candidate')
    loaded = load_checked_manifest(ctx, p5, args.manifest, args.manifest_sha256, 'manifest-sha256')
    if loaded is None:
        return None
    manifest, entries = loaded
    pin_id, pin_files = getattr(args, 'candidate_id', None), getattr(args, 'files_sha256', None)
    if pin_id is not None and pin_id != manifest['candidate_id']:
        ctx.bad('candidate_id_pin_mismatch', 'candidate-id', 'the pinned candidate_id differs from the manifest')
    if pin_files is not None and pin_files != manifest['files_sha256']:
        ctx.bad('files_sha256_pin_mismatch', 'files-sha256', 'the pinned files_sha256 differs from the manifest')
    if ctx.bad_count:
        return None
    try:
        package_manifest, contents = p5.read_package(args.package, args.manifest)
    except (p5.CandidateError, OSError) as exc:
        ctx.bad(getattr(exc, 'code', 'package_unreadable'), 'package', getattr(exc, 'message', '') or type(exc).__name__)
        return None
    if package_manifest != manifest:
        ctx.bad('manifest_changed_during_check', 'manifest', 'the manifest changed between the digest check and the package check')
        return None
    try:
        if sha256(read_file(args.manifest, p5.MAX_MANIFEST_BYTES, 'manifest')) != args.manifest_sha256:
            ctx.bad('manifest_changed_during_check', 'manifest', 'the manifest bytes changed while the package was read')
            return None
    except ReceiptError as exc:
        ctx.bad(exc.code, 'manifest', exc.message)
        return None
    cand = Candidate()
    cand.manifest, cand.entries, cand.contents = manifest, entries, contents
    cand.manifest_sha256, cand.candidate_id, cand.files_sha256 = args.manifest_sha256, manifest['candidate_id'], manifest['files_sha256']
    cand.archive_sha256, cand.includes_tests = manifest['archive']['sha256'], manifest['allowlist']['includes_tests']
    return cand


def candidate_summary(cand):
    return {'candidate_id': cand.candidate_id, 'files_sha256': cand.files_sha256, 'manifest_sha256_external': cand.manifest_sha256,
            'archive_sha256': cand.archive_sha256, 'files': len(cand.entries), 'includes_tests': cand.includes_tests,
            'integrity': 'verified against the externally recorded manifest digest; authenticity not established'}


def load_attachments(rep, triples, cand):
    """Explicit attachments (REL PATH SHA256): bytes outside P5 (docs/evidencia). Hashed only, never executed."""
    ctx, atts = Ctx(rep, 'attachment'), {}
    if len(triples) > MAX_ATTACHMENTS:
        ctx.bad('too_many_attachments', 'attachment', 'more than ' + str(MAX_ATTACHMENTS) + ' attachments')
        return atts
    for rel, path, declared in triples:
        if not safe_rel(rel):
            ctx.bad('attachment_path_invalid', ascii(rel)[:80], 'the relative path is not a safe POSIX path')
            continue
        if rel in atts:
            ctx.bad('attachment_duplicate', rel, 'the same relative path was attached twice')
            continue
        if not is_hex(declared):
            ctx.bad('attachment_digest_invalid', rel, 'the declared digest must be 64 lowercase hex characters')
            continue
        try:
            data = read_file(path, MAX_ATTACHMENT_BYTES, 'attachment ' + rel)
        except ReceiptError as exc:
            ctx.bad(exc.code, rel, exc.message)
            continue
        actual = sha256(data)
        if actual != declared:
            ctx.bad('attachment_hash_mismatch', rel, 'the bytes do not match the externally declared digest')
            continue
        if cand is not None and rel in cand.entries and cand.entries[rel]['sha256'] != actual:
            ctx.bad('attachment_conflicts_manifest', rel, 'the attachment differs from the same path in the manifest')
            continue
        atts[rel] = {'sha256': actual, 'size': len(data), 'data': data}
    return atts


def attachment_inventory(atts):
    return {rel: {'sha256': item['sha256'], 'size': item['size']} for rel, item in sorted(atts.items())}


def check_frontier(ctx, cand):
    for path in FRONTIER_MODULES:
        entry = cand.entries.get(path)
        if entry is None:
            ctx.bad('frontier_module_absent', path, 'a current boundary module is not in the manifest')
        elif entry['size'] == 0:
            ctx.bad('frontier_module_empty', path, 'a boundary module has no bytes')


def check_required_paths(ctx, cand, atts, paths):
    inventory = []
    for path in paths:
        if not safe_rel(path):
            ctx.bad('require_path_invalid', ascii(path)[:80], 'not a safe relative POSIX path')
        elif cand.sha_of(path):
            inventory.append({'path': path, 'sha256': cand.sha_of(path), 'via': 'manifest'})
        elif path in atts:
            inventory.append({'path': path, 'sha256': atts[path]['sha256'], 'via': 'attachment'})
        else:
            ctx.bad('fixture_absent', path, 'neither in the manifest nor an explicit attachment')
    return inventory


def check_deploy(rep, p5, cand, args):
    manifest_path, digest = getattr(args, 'deploy_manifest', None), getattr(args, 'deploy_manifest_sha256', None)
    if manifest_path is None and digest is None:
        return None
    ctx = Ctx(rep, 'deploy_candidate')
    if manifest_path is None or digest is None:
        ctx.bad('usage', 'deploy-manifest', 'the deploy manifest and its external digest go together')
        return None
    loaded = load_checked_manifest(ctx, p5, manifest_path, digest, 'deploy-manifest-sha256')
    if loaded is None:
        return None
    manifest, entries = loaded
    if manifest['allowlist']['includes_tests'] is not False:
        ctx.bad('deploy_includes_tests', 'manifest', 'the deployment candidate must not carry tests')
    for path in FRONTIER_MODULES:
        if path not in entries:
            ctx.bad('frontier_module_absent', path, 'a boundary module is not in the deployment manifest')
    differing = sorted(path for path, entry in entries.items() if cand.sha_of(path) != entry['sha256'])
    if differing:
        ctx.bad('deploy_file_differs_in_receipt_package', 'manifest', ', '.join(differing[:6]))
    return {'candidate_id': manifest['candidate_id'], 'files_sha256': manifest['files_sha256'], 'files': len(entries),
            'manifest_sha256_external': digest}


def reconcile_total(raw):
    """Total of the fixed invoice input, with the verifier's semantics (first occurrence of an id only; declared must equal quantity x unit)."""
    try:
        seen, total = set(), 0
        for invoice in json.loads(raw)['invoices']:
            if invoice['id'] in seen:
                continue
            seen.add(invoice['id'])
            computed = invoice['quantity'] * invoice['unit_cents']
            if computed == invoice['declared_cents']:
                total += computed
        return total
    except (ValueError, KeyError, TypeError, RecursionError):
        return None


def verifier_facts(cand):
    """(input_sha256, expected_total) from the VERIFIED verifier bytes by static parsing only; (None, None) when it cannot be read."""
    data = cand.contents.get(VERIFIER_PATH)
    if data is None:
        return None, None
    try:
        for node in ast.parse(data).body:
            if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'INPUT_BYTES' for t in node.targets):
                raw = ast.literal_eval(node.value)
                if type(raw) is bytes:
                    return sha256(raw), reconcile_total(raw)
    except (SyntaxError, ValueError, RecursionError):
        pass
    return None, None


# ---------------------------------------------------------------- shared receipt blocks

def check_identity(ctx, ident, where, installation=None):
    """The five-field actor identity (container, installation, intent, run, variant) with exact forms; None when invalid or crossed."""
    if not exact_keys(ctx, ident, IDENTITY_KEYS, where):
        return None
    good = fmt(ctx, ident['container_id'], 'hex64', where + '.container_id')
    good = fmt(ctx, ident['installation_id'], 'hex32', where + '.installation_id') and good
    good = fmt(ctx, ident['intent_id'], 'hex32', where + '.intent_id') and good
    good = fmt(ctx, ident['run_id'], 'hex32', where + '.run_id') and good
    good = fmt(ctx, ident['variant'], 'variant', where + '.variant') and good
    if good and installation is not None:
        good = ctx.expect(ident['installation_id'] == installation, 'installation_crossed', where + '.installation_id',
                          'the identity belongs to another installation than the receipt')
    return ident if good else None


def check_owner(ctx, proc, role, where, keys=OWNER_KEYS):
    """/proc observation of an owner: exact UIDs for its role (a crossed UID is its own code), zero capabilities, no_new_privs 1."""
    if not exact_keys(ctx, proc, keys, where):
        return None
    want, other = (ACTOR_UID, GUARD_UID) if role == 'actor' else (GUARD_UID, ACTOR_UID)
    good = ctx.expect(is_int(proc['pid']) and proc['pid'] > 0, 'invalid_pid', where + '.pid', 'a positive integer PID is required')
    uids = proc['uids']
    if not (type(uids) is list and len(uids) == 4 and all(is_int(uid) for uid in uids)):
        good = ctx.bad('invalid_uids', where + '.uids', 'four integer UIDs are required') and good
    elif uids != [want] * 4:
        good = ctx.bad('uid_crossed' if uids == [other] * 4 else 'uid_mismatch', where + '.uids',
                       'the ' + role + ' owner must run as UID ' + str(want)) and good
    if 'gids' in proc:
        gids = proc['gids']
        good = ctx.expect(type(gids) is list and len(gids) == 4 and all(is_int(gid) for gid in gids), 'invalid_gids', where + '.gids') and good
    groups = proc['groups']
    good = ctx.expect(type(groups) is list and len(groups) <= 64 and all(is_int(group) for group in groups), 'invalid_groups', where + '.groups') and good
    for key in ('cap_eff', 'cap_bnd'):
        if key in proc:
            good = ctx.expect(type(proc[key]) is str and ZEROS.fullmatch(proc[key]) is not None, 'capabilities_not_zero', where + '.' + key,
                              'the owner must hold no capabilities') and good
    good = ctx.expect(is_int(proc['no_new_privileges']) and proc['no_new_privileges'] == 1, 'no_new_privs_not_set', where + '.no_new_privileges') and good
    return proc if good else None


def check_peer(ctx, peer, role, where):
    if not exact_keys(ctx, peer, ('gid', 'pid', 'uid'), where):
        return None
    good = ctx.expect(all(is_int(peer[key]) for key in ('gid', 'pid', 'uid')) and peer['pid'] > 0, 'invalid_peer', where, 'integer gid, pid and uid are required')
    want = ACTOR_UID if role == 'actor' else GUARD_UID
    if good:
        good = ctx.expect(peer['uid'] == want, 'so_peercred_uid_mismatch', where + '.uid', 'the socket peer is not the expected ' + role + ' owner UID')
    return peer if good else None


def check_docker_denials(ctx, mapping, where):
    """Every listed Docker path must be unreachable, and at least one existing socket must have been denied (absence alone proves nothing)."""
    if type(mapping) is not dict or not mapping or len(mapping) > 16:
        return ctx.bad('type_mismatch', where, 'a non-empty bounded map of Docker paths is required')
    good = True
    for path, errno_name in mapping.items():
        if not path.startswith('/'):
            good = ctx.bad('docker_path_invalid', where, ascii(path)[:60]) and good
        if type(errno_name) is not str or errno_name not in DENIAL_ERRNOS:
            good = ctx.bad('docker_path_not_denied', where, 'a Docker path was not observed as denied or absent') and good
    if good and not any(value in ('EACCES', 'EPERM') for value in mapping.values()):
        good = ctx.bad('docker_denial_unproven', where, 'only absent paths were seen: no existing Docker socket was observed as denied')
    return good


FACT_KEYS = ('cap_bnd', 'cap_eff', 'cap_prm', 'docker_endpoints_denied', 'groups', 'interfaces', 'no_new_privileges', 'owner_journals_denied',
             'pid', 'so_peercred', 'uid')


def check_controller_facts(ctx, facts, where):
    """The controller as seen from itself: UID 65534, no groups, zero capabilities, no_new_privs, loopback only, Docker denied, journals denied."""
    if not exact_keys(ctx, facts, FACT_KEYS, where):
        return None
    good = ctx.expect(is_int(facts['uid']) and facts['uid'] == CONTROLLER_UID, 'controller_uid_mismatch', where + '.uid', 'the controller must run as UID 65534')
    good = ctx.expect(same(facts['groups'], []), 'controller_groups', where + '.groups', 'the controller must hold no supplementary groups') and good
    for key in ('cap_bnd', 'cap_eff', 'cap_prm'):
        good = ctx.expect(type(facts[key]) is str and ZEROS.fullmatch(facts[key]) is not None, 'capabilities_not_zero', where + '.' + key) and good
    good = ctx.expect(is_int(facts['no_new_privileges']) and facts['no_new_privileges'] == 1, 'no_new_privs_not_set', where + '.no_new_privileges') and good
    good = ctx.expect(is_int(facts['pid']) and facts['pid'] > 0, 'invalid_pid', where + '.pid') and good
    good = ctx.expect(same(facts['interfaces'], ['lo']), 'network_not_loopback_only', where + '.interfaces') and good
    good = ctx.expect(facts['owner_journals_denied'] is True, 'journals_not_denied', where + '.owner_journals_denied') and good
    good = check_docker_denials(ctx, facts['docker_endpoints_denied'], where + '.docker_endpoints_denied') and good
    peers = facts['so_peercred']
    if exact_keys(ctx, peers, ('actor', 'guard'), where + '.so_peercred'):
        actor, guard = check_peer(ctx, peers['actor'], 'actor', where + '.so_peercred.actor'), check_peer(ctx, peers['guard'], 'guard', where + '.so_peercred.guard')
        good = actor is not None and guard is not None and good
    else:
        good = False
    return facts if good else None


def norm_pairs(ctx, raw, where):
    if type(raw) is not list or len(raw) > MAX_EVENTS:
        ctx.bad('type_mismatch', where, 'a bounded list of [kind, payload] pairs is required')
        return None
    out = []
    for index, item in enumerate(raw):
        if not (type(item) is list and len(item) == 2 and type(item[0]) is str and type(item[1]) is dict):
            ctx.bad('ledger_entry_invalid', where + '[' + str(index) + ']', 'expected [kind, payload]')
            return None
        out.append((item[0], item[1]))
    return out


def norm_records(ctx, raw, where):
    if type(raw) is not list or len(raw) > MAX_EVENTS:
        ctx.bad('type_mismatch', where, 'a bounded list of {kind, payload} records is required')
        return None
    out = []
    for index, item in enumerate(raw):
        if not (type(item) is dict and set(item) == {'kind', 'payload'} and type(item['kind']) is str and type(item['payload']) is dict):
            ctx.bad('ledger_entry_invalid', where + '[' + str(index) + ']', 'expected {kind, payload}')
            return None
        out.append((item['kind'], item['payload']))
    return out


def check_actor_events(ctx, events, where):
    """Whole PENDING..FINISH intents only. Returns [{intent_id, run_id, variant, container_id}] or None. A missing FINISH is its own code."""
    kinds = [kind for kind, _ in events]
    if not kinds:
        ctx.bad('ledger_empty', where, 'the actor ledger has no events')
        return None
    if len(kinds) % len(KINDS) or kinds != list(KINDS) * (len(kinds) // len(KINDS)):
        ctx.bad('finish_absent' if kinds[-1] != 'FINISH' else 'ledger_sequence_invalid', where,
                'the ledger is not a whole number of CREATE_PENDING..FINISH intents')
        return None
    intents, seen_intents, seen_containers, good = [], set(), set(), True
    for start in range(0, len(events), len(KINDS)):
        payloads, here = {}, where + '[' + str(start // len(KINDS)) + ']'
        for kind, payload in events[start:start + len(KINDS)]:
            if exact_keys(ctx, payload, PAYLOAD_KEYS[kind], here + '.' + kind):
                payloads[kind] = payload
        if len(payloads) != len(KINDS):
            good = False
            continue
        pending, ack, finish = payloads['CREATE_PENDING'], payloads['CREATE_ACK'], payloads['FINISH']
        formed = fmt(ctx, pending['intent_id'], 'hex32', here + '.intent_id')
        formed = fmt(ctx, pending['run_id'], 'hex32', here + '.run_id') and formed
        formed = fmt(ctx, pending['variant'], 'variant', here + '.variant') and formed
        formed = fmt(ctx, ack['container_id'], 'hex64', here + '.container_id') and formed
        formed = ctx.expect(is_int(pending['controller_uid']) and pending['controller_uid'] == CONTROLLER_UID, 'controller_uid_mismatch',
                            here + '.controller_uid', 'the intent was not opened by the controller UID') and formed
        if not formed:
            good = False
            continue
        for kind in KINDS[1:]:
            formed = ctx.expect(payloads[kind]['intent_id'] == pending['intent_id'], 'intent_crossed', here + '.' + kind, 'the event names another intent') and formed
        formed = ctx.expect(finish['container_id'] == ack['container_id'], 'container_crossed', here + '.FINISH', 'FINISH names another container than CREATE_ACK') and formed
        formed = ctx.expect(pending['intent_id'] not in seen_intents and ack['container_id'] not in seen_containers, 'ledger_duplicate_identity', here,
                            'an intent or container ID repeats inside the ledger') and formed
        seen_intents.add(pending['intent_id'])
        seen_containers.add(ack['container_id'])
        good = formed and good
        intents.append({'intent_id': pending['intent_id'], 'run_id': pending['run_id'], 'variant': pending['variant'], 'container_id': ack['container_id']})
    return intents if good else None


def check_guard_events(ctx, events, where):
    """Verifier-guard ledger: whole PENDING, ACK, FINISH triples. Returns [{run_id, variant, artifact_sha256, container_id}] or None."""
    kinds = [kind for kind, _ in events]
    if len(kinds) % 3 or kinds != ['PENDING', 'ACK', 'FINISH'] * (len(kinds) // 3):
        ctx.bad('guard_finish_absent' if kinds and kinds[-1] != 'FINISH' else 'guard_sequence_invalid', where,
                'the guard ledger is not a whole number of PENDING, ACK, FINISH transitions')
        return None
    runs, seen, good = [], set(), True
    for start in range(0, len(events), 3):
        (_, pending), (_, ack), (_, finish) = events[start:start + 3]
        here = where + '[' + str(start // 3) + ']'
        if not (exact_keys(ctx, pending, ('artifact_sha256', 'container_id', 'name', 'run_id', 'variant'), here + '.PENDING')
                and exact_keys(ctx, ack, ('container_id',), here + '.ACK')):
            good = False
            continue
        formed = fmt(ctx, pending['artifact_sha256'], 'hex64', here + '.artifact_sha256')
        formed = fmt(ctx, pending['run_id'], 'hex32', here + '.run_id') and formed
        formed = fmt(ctx, pending['variant'], 'variant', here + '.variant') and formed
        formed = fmt(ctx, ack['container_id'], 'hex64', here + '.ACK.container_id') and formed
        formed = ctx.expect(pending['container_id'] is None, 'guard_pending_has_container', here + '.PENDING.container_id',
                            'PENDING is written before the container exists') and formed
        formed = ctx.expect(type(pending['name']) is str and GUARD_NAME.fullmatch(pending['name']) is not None, 'guard_name_invalid', here + '.PENDING.name') and formed
        formed = ctx.expect(type(finish) is dict and not finish, 'guard_finish_payload', here + '.FINISH', 'FINISH carries no payload') and formed
        if formed:
            formed = ctx.expect(ack['container_id'] not in seen, 'ledger_duplicate_identity', here, 'a verifier container ID repeats') and formed
            seen.add(ack['container_id'])
            runs.append({'run_id': pending['run_id'], 'variant': pending['variant'], 'artifact_sha256': pending['artifact_sha256'], 'container_id': ack['container_id']})
        good = formed and good
    return runs if good else None


def check_inventory(ctx, inventory, where):
    if not exact_keys(ctx, inventory, ('all_containers', 'installation'), where):
        return None
    for key in ('all_containers', 'installation'):
        items = inventory[key]
        if not (type(items) is list and len(items) <= MAX_CONTAINERS and all(is_hex(item) for item in items) and len(set(items)) == len(items)):
            ctx.bad('inventory_invalid', where + '.' + key, 'a bounded list of unique full container IDs is required')
            return None
    return inventory


def check_sentinel(ctx, value):
    if not exact_keys(ctx, value, ('id', 'state', 'token'), 'evidence.sentinel'):
        return None
    good = fmt(ctx, value['id'], 'hex64', 'evidence.sentinel.id')
    good = fmt(ctx, value['token'], 'hex32', 'evidence.sentinel.token') and good
    good = ctx.expect(same(value['state'], PRESERVED), 'sentinel_state', 'evidence.sentinel.state', 'the foreign sentinel was not observed as created and not running') and good
    return value if good else None


def check_classification(ctx, value):
    if not exact_keys(ctx, value, ('measured_by_operator', 'simulated', 'unknown_not_covered'), 'classification'):
        return False
    good = True
    for key in ('measured_by_operator', 'simulated', 'unknown_not_covered'):
        good = ctx.expect(str_list(value[key]), 'classification_invalid', 'classification.' + key, 'a non-empty list of unique strings is required') and good
    if good:
        good = ctx.expect(any('double' in item for item in value['simulated']), 'provider_double_undeclared', 'classification.simulated',
                          'the receipt must declare the provider double as simulation')
    return good


def check_a2_reference(ctx, value, expected_path=INHERITANCE_PATH):
    """The A2 inheritance manifest reference recorded by the producer; returns its SHA-256 or None."""
    if not exact_keys(ctx, value, ('manifest', 'sha256'), 'a2_inheritance'):
        return None
    ctx.expect(value['manifest'] == expected_path, 'a2_inheritance_path', 'a2_inheritance.manifest', 'unexpected inheritance manifest path')
    if value['sha256'] is None:
        ctx.bad('a2_inheritance_absent', 'a2_inheritance.sha256', 'the producer found no inheritance manifest')
        return None
    return value['sha256'] if fmt(ctx, value['sha256'], 'hex64', 'a2_inheritance.sha256') else None


def service_diff(ctx, mapping, cand, where):
    """Differences between a receipt's product-source map and the candidate manifest (services/agent/*.py both ways); None if malformed."""
    if type(mapping) is not dict or not mapping or len(mapping) > 500:
        ctx.bad('type_mismatch', where, 'a non-empty bounded source map is required')
        return None
    for path, digest in mapping.items():
        if not (path.startswith('services/agent/') and path.endswith('.py') and is_hex(digest)):
            ctx.bad('invalid_source_entry', where, ascii(path)[:80])
            return None
    product = {path: entry['sha256'] for path, entry in cand.entries.items() if path.startswith('services/agent/') and path.endswith('.py')}
    diffs = ['missing:' + path for path in sorted(set(product) - set(mapping))]
    diffs += ['extra:' + path for path in sorted(set(mapping) - set(product))]
    diffs += ['changed:' + path for path in sorted(path for path in mapping if path in product and mapping[path] != product[path])]
    return diffs


def harness_diff(ctx, mapping, cand, atts, expected, where):
    """(diffs, unbound) for the harness files a receipt names; unbound = not reachable by manifest or attachment (cannot be verified)."""
    if not exact_keys(ctx, mapping, expected, where):
        return None
    diffs, unbound = [], []
    for path in expected:
        if not fmt(ctx, mapping[path], 'hex64', where + '.' + path):
            return None
        known = known_sha(cand, atts, path)
        if known is None:
            unbound.append(path)
        elif known != mapping[path]:
            diffs.append('changed:' + path)
    return diffs, unbound


def few(items, count=6):
    return ', '.join(items[:count]) + (' (+' + str(len(items) - count) + ')' if len(items) > count else '')


# ---------------------------------------------------------------- criteria of an A4 scenario receipt


def _active(label):
    return [label + ':durable_ACTIVE_observed', label + ':docker_Running_true_observed']


def _settled(label, intents):
    return [label + ':ledger_complete_' + str(intents) + '_intents', label + ':own_ids_absent', label + ':installation_inventory_empty',
            label + ':foreign_sentinel_preserved']


BASE_CRITERIA = ['harness_test_copied_exactly', 'installation_empty_before']
_OWNER_CUT = (BASE_CRITERIA + _active('cut') + [
    'cut:only_owner_child_signalled', 'cut:no_FINISH_before_reconciliation', 'cut:known_container_still_present', 'cut:foreign_sentinel_preserved',
    'controller_cut_assertions_passed', 'controller_blocked_assertions_passed', 'blocked:still_no_FINISH', 'reconcile:recover_only_exit_0',
    'reconcile:known_id_closed_then_FINISH', 'reconcile:no_replay_after_cut', 'reconcile:exactly_one_create_one_start', 'reconcile:own_id_absent',
    'reconcile:sentinel_preserved', 'controller_recover_assertions_passed'] + _settled('recover', 3)
    + ['recover:guard_handled_only_the_later_run', 'recover:three_creates_in_total'])
REQUIRED_CRITERIA = {
    'cancel-api': tuple(BASE_CRITERIA + _active('cancel') + ['cancel:actor_closed_after_cancel', 'cancel:only_the_active_variant_started']
                        + _settled('cancel', 1) + ['cancel:verifier_guard_untouched', 'controller_cut_assertions_passed']),
    'owner-cut-provider-wait': tuple(_OWNER_CUT),
    'owner-cut-before-close': tuple(_OWNER_CUT),
    'lost-response-after-finish': tuple(BASE_CRITERIA + [
        'lost:FINISH_durable_before_the_response_was_dropped', 'lost:own_id_absent_at_the_cut', 'lost:nothing_appended_without_the_owner',
        'controller_cut_assertions_passed', 'lost:owner_pid_changed', 'lost:foreign_uid_gets_no_answer', 'controller_recover_assertions_passed']
        + _settled('recover', 3) + ['recover:three_creates_in_total']),
    'second-run-exclusion': tuple(BASE_CRITERIA + _active('exclusion') + [
        'exclusion:no_second_intent_while_first_active', 'exclusion:only_the_first_container_installed', 'exclusion:rejections_were_not_http_only']
        + _settled('exclusion', 4) + ['exclusion:replays_created_nothing', 'exclusion:replays_rejected', 'controller_cut_assertions_passed']),
}


def check_criteria(ctx, items, name):
    """{id: (index, item)}. Empty, duplicate, missing, unexpected, non-boolean or false criteria all reject; code=ok cannot hide them."""
    if type(items) is not list:
        ctx.bad('type_mismatch', 'criteria', 'a list is required')
        return {}
    if not items:
        ctx.bad('criteria_empty', 'criteria', 'an empty criteria list cannot support code=ok')
        return {}
    if len(items) > MAX_CRITERIA:
        ctx.bad('criteria_too_many', 'criteria', 'more than ' + str(MAX_CRITERIA) + ' criteria')
        return {}
    seen = {}
    for index, item in enumerate(items):
        here = 'criteria[' + str(index) + ']'
        if not exact_keys(ctx, item, ('detail', 'id', 'ok'), here):
            continue
        cid = item['id']
        if type(cid) is not str or not cid or len(cid) > 120:
            ctx.bad('criteria_id_invalid', here, 'a non-empty identifier of at most 120 characters is required')
        elif cid in seen:
            ctx.bad('criteria_duplicate', here, cid)
        elif type(item['ok']) is not bool:
            ctx.bad('type_mismatch', here + '.ok', 'ok must be a JSON boolean, not a number')
        else:
            seen[cid] = (index, item)
    required = REQUIRED_CRITERIA[name]
    missing, extra = [cid for cid in required if cid not in seen], sorted(cid for cid in seen if cid not in required)
    if missing:
        ctx.bad('criteria_missing', 'criteria', few(missing))
    if extra:
        ctx.bad('criteria_unexpected', 'criteria', few(extra))
    for cid in sorted(seen):
        if seen[cid][1]['ok'] is not True:
            ctx.bad('criterion_false', 'criteria.' + cid, 'the criterion is not satisfied')
    order = {cid: seen[cid][0] for cid in seen}
    if order.get('harness_test_copied_exactly') != 0 or order.get('installation_empty_before') != 1:
        ctx.bad('criteria_order', 'criteria', 'the copied-harness and empty-installation criteria must come first')
    for label in ('cancel', 'cut', 'exclusion'):
        durable, running = order.get(label + ':durable_ACTIVE_observed'), order.get(label + ':docker_Running_true_observed')
        if durable is not None and running is not None and not durable < running:
            ctx.bad('criteria_order', 'criteria', label + ': Running must be observed after the durable ACTIVE phase')
    signal, running = order.get('cut:only_owner_child_signalled'), order.get('cut:docker_Running_true_observed')
    if signal is not None and running is not None and not running < signal:
        ctx.bad('signal_before_observation', 'criteria', 'the owner was signalled before ACTIVE and Running=true were observed')
    return seen


# ---------------------------------------------------------------- scenario receipts (sc2-actor-compatibility-a4/v1)

TOP_KEYS = ('a2_inheritance', 'classification', 'code', 'criteria', 'evidence', 'fixture_retained', 'harness_sources', 'image_id',
            'installation_id', 'profile_sha256', 'scenario', 'schema', 'service_sources')
EVIDENCE_COMMON = ('controller', 'inventory_after', 'inventory_before', 'ledgers', 'owners_at_end', 'owners_at_start', 'sentinel')
OWNER_CUT_EXTRA = ('cut_point', 'docker_actions_after_cut', 'observed_active', 'owner_kill', 'owner_restart', 'reconciliation', 'socket_retirement')
EVIDENCE_KEYS = {
    'cancel-api': EVIDENCE_COMMON + ('observed_active',),
    'owner-cut-provider-wait': EVIDENCE_COMMON + OWNER_CUT_EXTRA,
    'owner-cut-before-close': EVIDENCE_COMMON + OWNER_CUT_EXTRA,
    'lost-response-after-finish': EVIDENCE_COMMON + ('cut_point', 'foreign_uid_query', 'owner_restart', 'owner_stop'),
    'second-run-exclusion': EVIDENCE_COMMON + ('observed_active',),
}
FINAL_EVIDENCE = ('inventory_after', 'owners_at_end', 'ledgers')
PHASES = {'cancel-api': ('cut',), 'owner-cut-provider-wait': ('cut', 'blocked', 'recover'), 'owner-cut-before-close': ('cut', 'blocked', 'recover'),
          'lost-response-after-finish': ('cut', 'recover'), 'second-run-exclusion': ('cut',)}
PROOF_CHECK = {('cancel-api', 'cut'): 'cancel_api', ('owner-cut-provider-wait', 'cut'): 'owner_cut', ('owner-cut-provider-wait', 'blocked'): 'blocked_while_owner_absent',
               ('owner-cut-provider-wait', 'recover'): 'recovered', ('owner-cut-before-close', 'cut'): 'owner_cut',
               ('owner-cut-before-close', 'blocked'): 'blocked_while_owner_absent', ('owner-cut-before-close', 'recover'): 'recovered',
               ('lost-response-after-finish', 'cut'): 'response_lost', ('lost-response-after-finish', 'recover'): 'recovered',
               ('second-run-exclusion', 'cut'): 'second_run_exclusion'}
PROOF_COMMON = ('check', 'phase', 'scenario')
PROOF_FIELDS = {
    'cancel_api': ('cancel_http', 'controller', 'identity', 'premature_http', 'provider_calls', 'run_id'),
    'owner_cut': ('admission_http', 'block_reason', 'controller', 'cut', 'identity', 'owner_reason', 'run_id', 'variants_started'),
    'blocked_while_owner_absent': ('admission_http', 'owner_reason', 'run_id'),
    'recovered': ('controller', 'later_receipt', 'later_run_id', 'later_sealed_sha256', 'original_receipt', 'run_id'),
    'response_lost': ('block_reason', 'controller', 'identity', 'run_id'),
    'second_run_exclusion': ('api_second_http', 'controller', 'direct_replay', 'direct_second', 'fixture_provider_calls', 'replays', 'runs'),
}
ACTIVE_LABEL = {'cancel-api': 'cancel', 'owner-cut-provider-wait': 'cut', 'owner-cut-before-close': 'cut', 'second-run-exclusion': 'exclusion'}
RUN_PATTERN = {'cancel-api': [['legitimate']], 'owner-cut-provider-wait': [['legitimate'], ['legitimate', 'perturbed']],
               'owner-cut-before-close': [['legitimate'], ['legitimate', 'perturbed']], 'lost-response-after-finish': [['legitimate'], ['legitimate', 'perturbed']],
               'second-run-exclusion': [['legitimate', 'perturbed'], ['legitimate', 'perturbed']]}
REPLAYS = {'legitimate': 'already_active', 'perturbed': 'already_active'}
REPLAY_ACTIONS = ('create', 'start')



# A4b extends the existing producer schema; these are its explicit scenario fields and criteria.
REQUIRED_CRITERIA['controller-kill-running'] = ('harness_test_copied_exactly', 'installation_empty_before', 'cut:live_create_stream_observed_the_original_id_before_SIGKILL', 'cut:durable_ACTIVE_observed', 'cut:docker_Running_true_observed', 'cut:sqlite_run_status_running_seen_by_the_controller', 'cut:durable_identity_events_match_the_actor_journal', 'cut:no_verifier_event_before_the_cut', 'cut:controller_self_reported_pid_uid_ppid_match_the_spawned_child', 'cut:guard_journal_empty_at_the_cut', 'cut:foreign_sentinel_preserved', 'cut:only_the_controller_child_was_signalled', 'controller_cut_ended_with_status_-9_as_induced', 'cut:actor_survived_the_controller_with_its_obligation_open', 'blocked:a_new_controller_process_reopened_the_same_sqlite', 'blocked:terminal_is_interrupted_failed_and_was_running_not_a_success', 'blocked:usage_is_not_declared_final', 'blocked:live_owner_answers_receipt_unknown_while_ACTIVE', 'blocked:admission_refused_by_the_cleanup_block', 'blocked:no_FINISH_when_the_POST_was_refused', 'blocked:known_container_still_running', 'blocked:guard_untouched', 'blocked:foreign_sentinel_preserved', 'controller_blocked_assertions_passed', 'reconcile:live_owner_closed_its_recognized_id_and_wrote_FINISH', 'reconcile:known_id_closed_then_FINISH', 'reconcile:no_replay_after_cut', 'reconcile:exactly_one_create_one_start_and_the_id_was_destroyed', 'reconcile:own_id_absent', 'reconcile:same_owner_and_guard_processes_alive', 'reconcile:guard_still_untouched', 'reconcile:sentinel_preserved', 'control:negative:foreign_uid_gets_no_answer_from_the_owner', 'controller_recover_assertions_passed', 'recover:ledger_complete_3_intents', 'recover:own_ids_absent', 'recover:installation_inventory_empty', 'recover:foreign_sentinel_preserved', 'recover:guard_handled_only_the_later_run', 'recover:three_creates_in_total_no_replay_of_the_interrupted_run', 'recover:fresh_controller_process_after_each_restart', 'identities:controller_actor_and_guard_run_under_three_distinct_uids', 'identities:controller_reached_the_owners_only_through_their_sockets')
EVIDENCE_KEYS['controller-kill-running'] = ('a4b', 'controller', 'controller_kill', 'create_event_observation', 'cut_point', 'docker_actions_after_cut', 'foreign_uid_query', 'inventory_after', 'inventory_before', 'ledgers', 'observed_active', 'owner_reconciliation', 'owners_at_end', 'owners_at_start', 'sentinel')
REQUIRED_CRITERIA['cancel-api-verifier-running'] = ('harness_test_copied_exactly', 'installation_empty_before', 'instrument:dependency_hashes_match_the_a4b_base', 'instrument:guard_journal_empty_before_replacement', 'instrument:clean_guard_stopped_and_retired_its_own_socket', 'instrument:journal_untouched_by_the_clean_stop', 'instrument:wrapper_runs_under_the_guard_uid_and_reopened_the_same_journal', 'verify:actor_closed_before_the_verifier_started', 'verify:durable_invoice_verifier_started_event_before_the_cancel', 'verify:guard_PENDING_and_ACK_durable_for_this_run_variant_and_digest', 'verify:verifier_Running_true_under_two_observers', 'verify:verifier_labels_name_this_run_and_variant', 'verify:verifier_is_the_only_object_of_the_guard_installation', 'control:negative:observer_rejects_the_non_running_foreign_sentinel', 'control:positive:observer_accepts_the_running_verifier', 'cancel:http_200_and_durable_mark_by_the_controller', 'cancel:request_delivered_to_the_run_task_which_is_still_pending', 'cancel:no_terminal_and_no_admission_while_the_guard_waits', 'cancel:verifier_still_running_after_the_durable_request', 'cancel:guard_barrier_held_no_FINISH', 'cancel:actor_untouched_after_its_close', 'wait:controller_resampled_after_the_operator_no_terminal_no_admission', 'wait:verifier_still_running_at_the_last_sample_before_the_release', 'wait:guard_still_held_at_the_last_sample', 'release:start_returned_only_after_the_release_then_FINISH', 'release:verifier_id_absent_at_FINISH', 'release:guard_installation_inventory_empty', 'release:guard_journal_PENDING_ACK_FINISH', 'release:one_create_one_start_for_the_verifier_and_it_was_destroyed', 'release:foreign_sentinel_preserved', 'terminal:ledger_complete_1_intents', 'terminal:own_ids_absent', 'terminal:installation_inventory_empty', 'terminal:foreign_sentinel_preserved', 'terminal:cancelled_with_the_same_digest_and_confirmed_verifier_cleanup', 'terminal:actor_receipt_confirmed_and_one_variant_started', 'controller_cut_assertions_passed', 'terminal:reports_json_and_markdown_identical_after_reopening_the_service', 'identities:controller_actor_and_guard_run_under_three_distinct_uids', 'identities:controller_reached_the_owners_only_through_their_sockets')
EVIDENCE_KEYS['cancel-api-verifier-running'] = ('a4b', 'controller', 'guard_replacement', 'guard_wrapper_events', 'guard_wrapper_stderr', 'instrumentation', 'inventory_after', 'inventory_before', 'ledgers', 'owners_at_end', 'owners_at_start', 'sentinel', 'timeline_operator_clock_ns', 'verifier_docker_actions', 'verifier_running')
RUN_PATTERN.update({'controller-kill-running': [['legitimate'], ['legitimate', 'perturbed']], 'cancel-api-verifier-running': [['legitimate']]})
ACTIVE_LABEL['controller-kill-running'] = 'cut'

def failed_ids(items):
    """Ids of the criteria a non-ok receipt recorded as failed (kept in the decision so a failed result is never dropped)."""
    if type(items) is not list:
        return []
    return [item['id'] for item in items[:MAX_CRITERIA] if type(item) is dict and type(item.get('id')) is str and item.get('ok') is False][:20]


class ScenarioChecker:
    def __init__(self, rep, doc, cand, atts):
        self.name = doc['scenario']
        self.ctx, self.doc, self.cand, self.atts = Ctx(rep, 'scenario:' + self.name), doc, cand, atts
        self.crit, self.ev, self.intents, self.guard_runs, self.groups = {}, {}, None, None, []
        self.installation = self.identity = self.proc_start = self.restart_pid = None
        self.ids = {'runs': set(), 'intents': set(), 'containers': set(), 'sentinel': None, 'guard_containers': set()}
        self.a2_sha = None

    def check(self):
        ctx, doc = self.ctx, self.doc
        exact_keys(ctx, doc, TOP_KEYS, '$')
        retained = doc.get('fixture_retained')
        if type(retained) is not bool:
            ctx.bad('type_mismatch', 'fixture_retained', 'a JSON boolean is required')
        elif retained:
            ctx.bad('fixture_retained', 'fixture_retained', 'a retained fixture is not a clean receipt')
        fmt(ctx, doc.get('image_id'), 'image', 'image_id')
        fmt(ctx, doc.get('installation_id'), 'hex32', 'installation_id')
        fmt(ctx, doc.get('profile_sha256'), 'hex64', 'profile_sha256')
        if is_hex(doc.get('installation_id'), HEX32):
            self.installation = doc['installation_id']
        check_classification(ctx, doc.get('classification'))
        self.a2_sha = check_a2_reference(ctx, doc.get('a2_inheritance'),
                                        A4B_INHERITANCE_PATH if self.name in A4B_SCENARIOS else INHERITANCE_PATH)
        self.sources()
        self.crit = check_criteria(ctx, doc.get('criteria'), self.name)
        self.evidence()
        return self

    # -- sources: product and harness bytes the receipt claims to have executed ---------------------------------------
    def sources(self):
        ctx = self.ctx
        diffs = service_diff(ctx, self.doc.get('service_sources'), self.cand, 'service_sources')
        if diffs:
            ctx.bad('product_source_mismatch', 'service_sources', 'the executed product sources are not the candidate: ' + few(diffs))
        paths = HARNESS_FILES + ((A4B_HARNESS,) if self.name in A4B_SCENARIOS else ())
        found = harness_diff(ctx, self.doc.get('harness_sources'), self.cand, self.atts, paths, 'harness_sources')
        if found is not None:
            changed, unbound = found
            if changed:
                ctx.bad('harness_source_mismatch', 'harness_sources', 'the executed harness is not the one listed for the candidate: ' + few(changed))
            if unbound:
                ctx.absent('harness_source_unbound', 'harness_sources', 'not reachable by manifest or explicit attachment: ' + few(unbound))

    # -- evidence -----------------------------------------------------------------------------------------------------
    def evidence(self):
        ctx, name = self.ctx, self.name
        ev = self.doc.get('evidence')
        if type(ev) is not dict:
            ctx.bad('type_mismatch', 'evidence', 'an object is required')
            return
        expected = EVIDENCE_KEYS[name]
        for key in expected:
            if key not in ev:
                ctx.bad('final_observation_missing' if key in FINAL_EVIDENCE else 'field_missing', 'evidence.' + key, 'required by this scenario')
        for key in sorted(set(ev) - set(expected)):
            ctx.bad('final_observation_missing' if key == 'final_observation_error' else 'field_unexpected', 'evidence.' + key, 'not part of this scenario')
        self.ev = ev
        sentinel = check_sentinel(ctx, ev['sentinel']) if 'sentinel' in ev else None
        if 'owners_at_start' in ev:
            self.proc_start = self.owners(ev['owners_at_start'], 'evidence.owners_at_start')
        end = self.owners(ev['owners_at_end'], 'evidence.owners_at_end') if 'owners_at_end' in ev else None
        if 'ledgers' in ev:
            self.ledgers(ev['ledgers'])
        before = check_inventory(ctx, ev['inventory_before'], 'evidence.inventory_before') if 'inventory_before' in ev else None
        after = check_inventory(ctx, ev['inventory_after'], 'evidence.inventory_after') if 'inventory_after' in ev else None
        self.inventories(before, after, sentinel)
        self.active()
        if name.startswith('owner-cut-'):
            self.owner_cut()
        elif name == 'lost-response-after-finish':
            self.lost_response()
        self.final_owners(end)
        self.controller()
        self.details()

    def owners(self, value, where):
        ctx = self.ctx
        if not exact_keys(ctx, value, ('actor', 'guard'), where):
            return None
        actor = check_owner(ctx, value['actor'], 'actor', where + '.actor')
        guard = check_owner(ctx, value['guard'], 'guard', where + '.guard')
        if actor is None or guard is None:
            return None
        ctx.expect(actor['pid'] != guard['pid'], 'owners_same_process', where, 'actor and guard are the same process')
        return {'actor': actor, 'guard': guard}

    def final_owners(self, end):
        """The observation at the end must be of the same guard process, and of the actor owner that is expected to be alive at the end."""
        if end is None or self.proc_start is None:
            return
        ctx = self.ctx
        ctx.expect(end['guard']['pid'] == self.proc_start['guard']['pid'], 'guard_identity_changed', 'evidence.owners_at_end.guard',
                   'the guard process at the end is not the one observed at the start')
        restarted = self.name.startswith('owner-cut-') or self.name == 'lost-response-after-finish'
        want = self.restart_pid if restarted else self.proc_start['actor']['pid']
        if want is not None:
            ctx.expect(end['actor']['pid'] == want, 'owner_identity_changed', 'evidence.owners_at_end.actor',
                       'the actor owner at the end is not the expected process')

    def ledgers(self, value):
        ctx = self.ctx
        if not exact_keys(ctx, value, ('actor', 'guard'), 'evidence.ledgers'):
            return
        actor = norm_pairs(ctx, value['actor'], 'evidence.ledgers.actor')
        guard = norm_pairs(ctx, value['guard'], 'evidence.ledgers.guard')
        if actor is not None:
            self.intents = check_actor_events(ctx, actor, 'evidence.ledgers.actor')
        if guard is not None:
            self.guard_runs = check_guard_events(ctx, guard, 'evidence.ledgers.guard')
        if self.intents is not None:
            self.structure()
            if self.guard_runs is not None:
                self.guard_links()

    def structure(self):
        groups = []
        for intent in self.intents:
            if groups and groups[-1][0] == intent['run_id']:
                groups[-1][1].append(intent['variant'])
            else:
                groups.append((intent['run_id'], [intent['variant']]))
        if [variants for _, variants in groups] != RUN_PATTERN[self.name] or len({run for run, _ in groups}) != len(groups):
            self.ctx.bad('ledger_run_structure', 'evidence.ledgers.actor', 'the intents do not follow the runs and variants this scenario produces')
        self.groups = groups
        self.ids['runs'] = {run for run, _ in groups}
        self.ids['intents'] = {intent['intent_id'] for intent in self.intents}
        self.ids['containers'] = {intent['container_id'] for intent in self.intents}

    def guard_links(self):
        ctx = self.ctx
        pairs = {(intent['run_id'], intent['variant']) for intent in self.intents}
        for number, run in enumerate(self.guard_runs):
            here = 'evidence.ledgers.guard[' + str(number) + ']'
            ctx.expect((run['run_id'], run['variant']) in pairs, 'guard_run_unknown_to_actor', here, 'the guard handled a run and variant the actor never opened')
            ctx.expect(run['variant'] == 'legitimate', 'guard_saw_failed_variant', here, 'F-veto violated: the guard has transitions for the perturbed variant')
            ctx.expect(run['container_id'] not in self.ids['containers'], 'container_crossed', here, 'a verifier container is also an actor container')
        self.ids['guard_containers'] = {run['container_id'] for run in self.guard_runs}

    def inventories(self, before, after, sentinel):
        ctx = self.ctx
        if sentinel is not None:
            self.ids['sentinel'] = sentinel['id']
        if before is not None:
            ctx.expect(before['installation'] == [], 'installation_not_empty_before', 'evidence.inventory_before.installation', 'the installation was not empty before the run')
        if after is not None:
            ctx.expect(after['installation'] == [], 'installation_not_empty_after', 'evidence.inventory_after.installation', 'the installation inventory is not empty at the end')
        if before is not None and after is not None and sentinel is not None:
            old, new = set(before['all_containers']), set(after['all_containers'])
            here = 'evidence.inventory_after.all_containers'
            ctx.expect(sentinel['id'] not in old and sentinel['id'] in new, 'sentinel_not_preserved', here, 'the foreign sentinel must appear during the run and still be present at the end')
            ctx.expect(not (old - new), 'foreign_container_removed', here, 'a container that existed before the run is gone at the end')
            ctx.expect(new - old == {sentinel['id']}, 'foreign_container_appeared', here, 'the only container added during the run must be the sentinel')
        if after is not None and self.intents is not None:
            own = set(self.ids['containers']) | set(self.ids['guard_containers'])
            ctx.expect(not (own & set(after['all_containers'])), 'own_container_present_at_end', 'evidence.inventory_after.all_containers',
                       'an actor or verifier container is still listed at the end')

    def active(self):
        label = ACTIVE_LABEL.get(self.name)
        if label is None or 'observed_active' not in self.ev:
            return
        ctx, value = self.ctx, self.ev['observed_active']
        if not exact_keys(ctx, value, (label,), 'evidence.observed_active'):
            return
        where = 'evidence.observed_active.' + label
        entry = value[label]
        if not exact_keys(ctx, entry, ('docker', 'identity', 'ledger'), where):
            return
        ctx.expect(same(entry['docker'], RUNNING), 'running_not_observed', where + '.docker', 'Docker did not report the container as running before the cut')
        ctx.expect(same(entry['ledger'], list(KINDS[:4])), 'active_phase_not_observed', where + '.ledger', 'the durable ledger did not stand at ACTIVE')
        self.identity = check_identity(ctx, entry['identity'], where + '.identity', self.installation)
        self.link_identity(self.identity, where + '.identity')

    def link_identity(self, ident, where):
        """The observed identity must be the first intent of the ledger (same intent, run, variant and container)."""
        if ident is None or not self.intents:
            return
        first = self.intents[0]
        for key in ('intent_id', 'run_id', 'variant', 'container_id'):
            self.ctx.expect(ident[key] == first[key], 'identity_ledger_mismatch', where + '.' + key, 'the identity differs from the first intent of the ledger')

    # -- owner cut and lost response ------------------------------------------------------------------------------------
    def restart(self, previous_pid):
        ctx = self.ctx
        if 'owner_restart' not in self.ev:
            return
        value = self.ev['owner_restart']
        if not exact_keys(ctx, value, ('pid', 'proc', 'socket'), 'evidence.owner_restart'):
            return
        good = ctx.expect(is_int(value['pid']) and value['pid'] > 0, 'invalid_pid', 'evidence.owner_restart.pid')
        proc = check_owner(ctx, value['proc'], 'actor', 'evidence.owner_restart.proc')
        if proc is not None and good:
            good = ctx.expect(proc['pid'] == value['pid'], 'restart_identity_mismatch', 'evidence.owner_restart.proc.pid', 'the observed process is not the restarted owner')
        sock = value['socket']
        if exact_keys(ctx, sock, ('dev', 'ino', 'is_socket', 'uid'), 'evidence.owner_restart.socket'):
            ctx.expect(sock['is_socket'] is True and is_int(sock['uid']) and sock['uid'] == ACTOR_UID and is_int(sock['dev']) and is_int(sock['ino']),
                       'restart_socket_invalid', 'evidence.owner_restart.socket', 'the restarted owner did not bind a socket owned by the actor UID')
        if good and previous_pid is not None:
            good = ctx.expect(value['pid'] != previous_pid, 'owner_not_restarted', 'evidence.owner_restart.pid', 'the restarted owner has the PID of the one that was cut')
        if good:
            self.restart_pid = value['pid']

    def owner_cut(self):
        ctx, ev = self.ctx, self.ev
        cut = self.name[len('owner-cut-'):]
        if 'cut_point' in ev:
            ctx.expect(same(ev['cut_point'], {'name': cut, 'owner_state': 'ACTIVE', 'finish_written': False}), 'cut_point_invalid', 'evidence.cut_point',
                       'the cut point is not ACTIVE with FINISH unwritten for ' + cut)
        previous = None
        if 'owner_kill' in ev and exact_keys(ctx, ev['owner_kill'], ('cut_at', 'guard_alive_after', 'guard_pid', 'returncode', 'signal', 'target'), 'evidence.owner_kill'):
            kill = ev['owner_kill']
            ctx.expect(kill['signal'] == 'SIGKILL', 'signal_invalid', 'evidence.owner_kill.signal', 'SIGKILL was not the signal')
            ctx.expect(is_int(kill['returncode']) and kill['returncode'] == -9, 'signal_not_delivered', 'evidence.owner_kill.returncode', 'the owner did not die from SIGKILL')
            ctx.expect(type(kill['cut_at']) is float and kill['cut_at'] > 0, 'cut_time_invalid', 'evidence.owner_kill.cut_at', 'a positive float timestamp is required')
            ctx.expect(kill['guard_alive_after'] is True, 'guard_not_alive_after_cut', 'evidence.owner_kill.guard_alive_after', 'the guard must survive the actor cut')
            target = check_owner(ctx, kill['target'], 'actor', 'evidence.owner_kill.target')
            if target is not None and self.proc_start is not None:
                ctx.expect(target['pid'] == self.proc_start['actor']['pid'], 'signal_target_mismatch', 'evidence.owner_kill.target.pid',
                           'the signalled process is not the actor owner observed at the start')
                ctx.expect(is_int(kill['guard_pid']) and kill['guard_pid'] == self.proc_start['guard']['pid'], 'guard_identity_mismatch',
                           'evidence.owner_kill.guard_pid', 'the guard process named at the cut is not the one observed at the start')
                previous = target['pid']
        if 'reconciliation' in ev and exact_keys(ctx, ev['reconciliation'], ('returncode', 'stderr'), 'evidence.reconciliation'):
            rec = ev['reconciliation']
            ctx.expect(is_int(rec['returncode']) and rec['returncode'] == 0 and type(rec['stderr']) is str, 'reconciliation_failed',
                       'evidence.reconciliation', 'the --recover-only run did not end with code 0')
        if 'docker_actions_after_cut' in ev:
            actions = ev['docker_actions_after_cut']
            if not (type(actions) is list and len(actions) <= MAX_EVENTS and all(type(item) is str for item in actions)):
                ctx.bad('type_mismatch', 'evidence.docker_actions_after_cut', 'a list of Docker action names is required')
            else:
                ctx.expect(not any(item in REPLAY_ACTIONS or item.startswith(('exec_create', 'exec_start')) for item in actions), 'replay_after_cut',
                           'evidence.docker_actions_after_cut', 'create, start or exec was issued after the cut: recovery replayed an action')
        if 'socket_retirement' in ev and exact_keys(ctx, ev['socket_retirement'], ('dev', 'ino', 'is_socket', 'retired', 'uid'), 'evidence.socket_retirement'):
            ret = ev['socket_retirement']
            ctx.expect(ret['retired'] is True and ret['is_socket'] is True and is_int(ret['uid']) and ret['uid'] == ACTOR_UID and is_int(ret['dev']) and is_int(ret['ino']),
                       'socket_retirement_invalid', 'evidence.socket_retirement', 'only the actor-owned socket residue may be retired, after reconciliation')
        self.restart(previous)

    def lost_response(self):
        ctx, ev = self.ctx, self.ev
        if 'cut_point' in ev:
            ctx.expect(same(ev['cut_point'], {'name': 'response_dropped_after_close_FINISH', 'owner_state': 'FINISH', 'finish_written': True}),
                       'cut_point_invalid', 'evidence.cut_point', 'the cut point is not the response dropped after a durable FINISH')
        previous = None
        if 'owner_stop' in ev and exact_keys(ctx, ev['owner_stop'], ('pid', 'returncode', 'signal'), 'evidence.owner_stop'):
            stop = ev['owner_stop']
            good = ctx.expect(stop['signal'] == 'SIGTERM' and is_int(stop['returncode']) and stop['returncode'] == 0 and is_int(stop['pid']),
                              'owner_stop_invalid', 'evidence.owner_stop', 'the owner did not stop cleanly on SIGTERM')
            if good and self.proc_start is not None:
                good = ctx.expect(stop['pid'] == self.proc_start['actor']['pid'], 'signal_target_mismatch', 'evidence.owner_stop.pid',
                                  'the stopped process is not the actor owner observed at the start')
            previous = stop['pid'] if good else None
        self.restart(previous)
        if 'foreign_uid_query' in ev:
            self.foreign_query(ev['foreign_uid_query'])

    def foreign_query(self, query):
        ctx, where = self.ctx, 'evidence.foreign_uid_query'
        if not (type(query) is dict and 'uid' in query and set(query) <= {'uid', 'connect', 'answered'}):
            ctx.bad('foreign_query_invalid', where, 'uid, connect and answered are the only fields of the query record')
            return
        ctx.expect(is_int(query['uid']) and query['uid'] == FOREIGN_UID, 'foreign_uid_mismatch', where + '.uid', 'the query was not made as the foreign UID')
        connect = query.get('connect')
        if type(connect) is not str or not connect:
            ctx.bad('foreign_query_unobserved', where, 'the query recorded no connection outcome: an empty observation is not a negative control')
        elif connect == 'ok':
            ctx.expect(query.get('answered') is False, 'foreign_uid_answered', where, 'a foreign UID received an answer from the owner')
        else:
            ctx.expect('answered' not in query, 'foreign_query_invalid', where, 'an unconnected query cannot carry an answer flag')

    # -- controller phases and their proofs -------------------------------------------------------------------------------
    def controller(self):
        ctx, name = self.ctx, self.name
        if 'controller' not in self.ev:
            return
        phases = PHASES[name]
        controller = self.ev['controller']
        if not exact_keys(ctx, controller, phases, 'evidence.controller'):
            return
        proofs = {}
        for phase in phases:
            where = 'evidence.controller.' + phase
            entry = controller[phase]
            if not exact_keys(ctx, entry, ('proofs', 'returncode'), where):
                continue
            ctx.expect(is_int(entry['returncode']) and entry['returncode'] == 0, 'controller_phase_failed', where + '.returncode',
                       'the controller phase did not end with code 0')
            if not (type(entry['proofs']) is list and len(entry['proofs']) == 1):
                ctx.bad('proof_count', where + '.proofs', 'exactly one A4 proof per controller phase is required')
                continue
            proof = self.proof(phase, entry['proofs'][0], where + '.proofs[0]')
            if proof is not None:
                proofs[phase] = proof
        self.proof_links(proofs)

    def proof(self, phase, proof, where):
        ctx, name = self.ctx, self.name
        check = PROOF_CHECK[(name, phase)]
        if not exact_keys(ctx, proof, PROOF_COMMON + PROOF_FIELDS[check], where):
            return None
        good = ctx.expect(proof['scenario'] == name and proof['phase'] == phase and proof['check'] == check, 'proof_identity_mismatch', where,
                          'the proof names another scenario, phase or check')
        if 'controller' in PROOF_FIELDS[check]:
            facts = check_controller_facts(ctx, proof['controller'], where + '.controller')
            good = facts is not None and good
            self.facts_link(phase, facts, where + '.controller')
        return proof if good else None

    def facts_link(self, phase, facts, where):
        """SO_PEERCRED PIDs seen by the controller must be the owner processes the operator observed (the restarted owner in recovery)."""
        if facts is None or self.proc_start is None:
            return
        peers, ctx = facts['so_peercred'], self.ctx
        ctx.expect(peers['guard']['pid'] == self.proc_start['guard']['pid'], 'so_peercred_pid_mismatch', where + '.so_peercred.guard.pid',
                   'the guard peer is not the guard process observed at the start')
        actor_pid = self.restart_pid if phase == 'recover' else self.proc_start['actor']['pid']
        if actor_pid is not None:
            ctx.expect(peers['actor']['pid'] == actor_pid, 'so_peercred_pid_mismatch', where + '.so_peercred.actor.pid',
                       'the actor peer is not the owner process expected in this phase')

    def ident_link(self, value, where):
        ident = check_identity(self.ctx, value, where, self.installation)
        self.link_identity(ident, where)
        return ident

    def proof_links(self, proofs):
        ctx, name, first = self.ctx, self.name, (self.intents[0] if self.intents else None)
        cut = proofs.get('cut')
        base = 'evidence.controller.cut.proofs[0]'
        if cut is not None and name == 'cancel-api':
            self.ident_link(cut['identity'], base + '.identity')
            ctx.expect(first is None or cut['run_id'] == first['run_id'], 'proof_run_mismatch', base + '.run_id', 'the proof names another run than the ledger')
            ctx.expect(same(cut['cancel_http'], 200) and same(cut['premature_http'], 409), 'http_status_mismatch', base,
                       'cancel must answer 200 and a second run while the plaza is occupied must answer 409')
            ctx.expect(is_int(cut['provider_calls']) and cut['provider_calls'] >= 1, 'proof_value_invalid', base + '.provider_calls')
        elif cut is not None and name.startswith('owner-cut-'):
            self.ident_link(cut['identity'], base + '.identity')
            ctx.expect(first is None or cut['run_id'] == first['run_id'], 'proof_run_mismatch', base + '.run_id', 'the proof names another run than the ledger')
            ctx.expect(cut['cut'] == name[len('owner-cut-'):], 'proof_cut_mismatch', base + '.cut', 'the proof names another cut point')
            ctx.expect(cut['block_reason'] == 'cleanup_unconfirmed', 'block_reason_mismatch', base + '.block_reason', 'admission must be blocked for unconfirmed cleanup')
            ctx.expect(same(cut['admission_http'], 503), 'admission_not_closed', base + '.admission_http', 'admission must answer 503 while the owner is gone')
            ctx.expect(type(cut['owner_reason']) is str and cut['owner_reason'] != '', 'owner_reason_missing', base + '.owner_reason', 'the dead owner gave no recorded reason')
            variants = cut['variants_started']
            ctx.expect(type(variants) is list and variants[:1] == ['legitimate'] and all(type(item) is str and item in VARIANTS for item in variants),
                       'variants_started_invalid', base + '.variants_started', 'the first variant started must be the legitimate one')
        elif cut is not None and name == 'lost-response-after-finish':
            self.ident_link(cut['identity'], base + '.identity')
            ctx.expect(first is None or cut['run_id'] == first['run_id'], 'proof_run_mismatch', base + '.run_id', 'the proof names another run than the ledger')
            ctx.expect(cut['block_reason'] == 'cleanup_unconfirmed', 'block_reason_mismatch', base + '.block_reason', 'a lost close response must keep the block')
        elif cut is not None and name == 'second-run-exclusion':
            runs = [run for run, _ in self.groups]
            ctx.expect(cut['runs'] == runs and len(runs) == 2, 'proof_run_mismatch', base + '.runs', 'the proof runs are not the two runs of the ledger')
            ctx.expect(same(cut['replays'], REPLAYS), 'replay_not_rejected', base + '.replays', 'a replay of a finished identity was not rejected')
            ctx.expect(same(cut['api_second_http'], 409) and cut['direct_second'] == 'capacity_exhausted' and cut['direct_replay'] == 'already_active',
                       'exclusion_not_observed', base, 'the single plaza did not reject a second run and a replay at the owner')
            ctx.expect(is_int(cut['fixture_provider_calls']) and cut['fixture_provider_calls'] >= 0, 'proof_value_invalid', base + '.fixture_provider_calls')
        blocked = proofs.get('blocked')
        if blocked is not None:
            there = 'evidence.controller.blocked.proofs[0]'
            ctx.expect(first is None or blocked['run_id'] == first['run_id'], 'proof_run_mismatch', there + '.run_id', 'the blocked phase names another run')
            ctx.expect(same(blocked['admission_http'], 503), 'admission_not_closed', there + '.admission_http', 'admission must stay closed while the owner is absent')
            ctx.expect(type(blocked['owner_reason']) is str and blocked['owner_reason'] != '', 'owner_reason_missing', there + '.owner_reason')
        recover = proofs.get('recover')
        if recover is not None:
            self.recovered(recover, 'evidence.controller.recover.proofs[0]')

    def recovered(self, proof, where):
        ctx, intents = self.ctx, self.intents
        if not intents or len(self.groups) < 2:
            return
        first, later_run = intents[0], self.groups[1][0]
        ctx.expect(proof['run_id'] == first['run_id'], 'proof_run_mismatch', where + '.run_id', 'the recovered run is not the interrupted one')
        ctx.expect(proof['later_run_id'] == later_run, 'proof_run_mismatch', where + '.later_run_id', 'the later run is not the one in the ledger')
        fmt(ctx, proof['later_sealed_sha256'], 'hex64', where + '.later_sealed_sha256')
        later = next((intent for intent in intents if intent['run_id'] == later_run and intent['variant'] == 'legitimate'), None)
        self.receipt_link(proof['original_receipt'], first, where + '.original_receipt')
        if later is not None:
            self.receipt_link(proof['later_receipt'], later, where + '.later_receipt')
            ctx.expect(later['intent_id'] != first['intent_id'], 'identity_reused', where, 'the later run reused the identity of the interrupted one')

    def receipt_link(self, receipt, intent, where):
        """The durable receipt the controller recovered must be the exact FINISH identity of that intent, and confirmed."""
        ctx = self.ctx
        if type(receipt) is not dict:
            ctx.bad('type_mismatch', where, 'a receipt object is required')
            return
        good = ctx.expect(receipt.get('status') == 'confirmed' and receipt.get('cleanup_confirmed') is True, 'receipt_not_confirmed', where,
                          'only a confirmed durable FINISH receipt restores confidence')
        values = {'container_id': intent['container_id'], 'installation_id': self.installation, 'intent_id': intent['intent_id'],
                  'run_id': intent['run_id'], 'variant': intent['variant']}
        for key, value in values.items():
            if value is not None:
                good = ctx.expect(receipt.get(key) == value, 'receipt_identity_mismatch', where + '.' + key, 'the receipt names another ' + key) and good
        return good

    # -- observations recorded as criterion details are data, so they are compared with the evidence -------------------
    def detail_is(self, cid, expected):
        item = self.crit.get(cid)
        if item is not None and not same(item[1]['detail'], expected):
            self.ctx.bad('criterion_detail_mismatch', 'criteria.' + cid, 'the recorded observation does not support the criterion')

    def detail_pred(self, cid, predicate, message):
        item = self.crit.get(cid)
        if item is None:
            return
        try:
            good = bool(predicate(item[1]['detail']))
        except (TypeError, KeyError, IndexError, AttributeError):
            good = False
        if not good:
            self.ctx.bad('criterion_detail_mismatch', 'criteria.' + cid, message)

    def settled(self, label, intents, container_ids):
        self.detail_is(label + ':ledger_complete_' + str(intents) + '_intents', list(KINDS) * intents)
        if container_ids is not None:
            self.detail_is(label + ':own_ids_absent', {cid: list(ABSENT) for cid in container_ids})
        self.detail_is(label + ':installation_inventory_empty', [])
        self.detail_is(label + ':foreign_sentinel_preserved', list(PRESERVED))

    def details(self):
        name, ev, full = self.name, self.ev, list(KINDS)
        ids = [intent['container_id'] for intent in self.intents] if self.intents else None
        for cid in REQUIRED_CRITERIA[name]:
            if cid.startswith('controller_'):
                self.detail_is(cid, 0)
        self.detail_is('harness_test_copied_exactly', None)
        self.detail_is('installation_empty_before', None)
        if name == 'cancel-api':
            self.detail_is('cancel:durable_ACTIVE_observed', full[:4])
            self.detail_is('cancel:docker_Running_true_observed', RUNNING)
            self.detail_pred('cancel:actor_closed_after_cancel', lambda d: d[-2:] == ['CLOSE_PENDING', 'FINISH'], 'the actor ledger did not end CLOSE_PENDING, FINISH after the cancel')
            self.detail_is('cancel:only_the_active_variant_started', None)
            self.settled('cancel', 1, [self.identity['container_id']] if self.identity else None)
            self.detail_is('cancel:verifier_guard_untouched', [])
            if self.guard_runs is not None:
                self.ctx.expect(self.guard_runs == [], 'guard_not_untouched', 'evidence.ledgers.guard', 'a cancelled run must leave the verifier guard untouched')
        elif name.startswith('owner-cut-'):
            self.detail_is('cut:durable_ACTIVE_observed', full[:4])
            self.detail_is('cut:docker_Running_true_observed', RUNNING)
            if 'owner_kill' in ev:
                self.detail_is('cut:only_owner_child_signalled', ev['owner_kill'])
            self.detail_pred('cut:no_FINISH_before_reconciliation', lambda d: d[-1] == 'ACTIVE', 'the ledger did not stand at ACTIVE after the cut')
            self.detail_pred('cut:known_container_still_present', lambda d: d[0] is True and len(d) == 3, 'the known container was not observed as present after the cut')
            self.detail_is('cut:foreign_sentinel_preserved', None)
            self.detail_pred('blocked:still_no_FINISH', lambda d: d[-1] == 'ACTIVE', 'FINISH appeared while the owner was still absent')
            if 'reconciliation' in ev:
                self.detail_is('reconcile:recover_only_exit_0', ev['reconciliation'])
            self.detail_pred('reconcile:known_id_closed_then_FINISH', lambda d: d[-3:] == ['ACTIVE', 'CLOSE_PENDING', 'FINISH'] and d.count('CREATE_PENDING') == 1,
                             'the known ID was not closed and finished by the reconciliation')
            if 'docker_actions_after_cut' in ev:
                self.detail_is('reconcile:no_replay_after_cut', ev['docker_actions_after_cut'])
            self.detail_pred('reconcile:exactly_one_create_one_start', lambda d: type(d) is list and d.count('create') == 1 and d.count('start') == 1,
                             'the container was not created and started exactly once over the whole window')
            self.detail_is('reconcile:own_id_absent', list(ABSENT))
            self.detail_is('reconcile:sentinel_preserved', None)
            self.settled('recover', 3, ids)
            self.detail_is('recover:guard_handled_only_the_later_run', ['PENDING', 'ACK', 'FINISH'])
            self.detail_is('recover:three_creates_in_total', None)
            if self.guard_runs is not None and len(self.groups) == 2:
                self.ctx.expect(len(self.guard_runs) == 1 and self.guard_runs[0]['run_id'] == self.groups[1][0] and self.guard_runs[0]['variant'] == 'legitimate',
                                'guard_handled_wrong_run', 'evidence.ledgers.guard', 'the guard must have handled only the legitimate variant of the later run')
        elif name == 'lost-response-after-finish':
            self.detail_is('lost:FINISH_durable_before_the_response_was_dropped', full)
            self.detail_is('lost:own_id_absent_at_the_cut', list(ABSENT))
            self.detail_is('lost:nothing_appended_without_the_owner', full)
            self.detail_is('lost:owner_pid_changed', None)
            if 'foreign_uid_query' in ev:
                self.detail_is('lost:foreign_uid_gets_no_answer', ev['foreign_uid_query'])
            self.settled('recover', 3, ids)
            self.detail_is('recover:three_creates_in_total', None)
        elif name == 'second-run-exclusion':
            self.detail_is('exclusion:durable_ACTIVE_observed', full[:4])
            self.detail_is('exclusion:docker_Running_true_observed', RUNNING)
            self.detail_is('exclusion:no_second_intent_while_first_active', full[:4])
            if self.identity is not None:
                self.detail_is('exclusion:only_the_first_container_installed', [self.identity['container_id']])
            identity = self.identity
            self.detail_pred('exclusion:rejections_were_not_http_only',
                             lambda d: type(d) is dict and same(d.get('api_second_http'), 409) and d.get('direct_second') == 'capacity_exhausted'
                             and d.get('direct_replay') == 'already_active' and (identity is None or d.get('identity') == identity),
                             'the second run and the replay were not rejected by the owner as well as over HTTP')
            self.settled('exclusion', 4, ids)
            self.detail_is('exclusion:replays_created_nothing', None)
            self.detail_is('exclusion:replays_rejected', REPLAYS)


class A4bChecker(ScenarioChecker):
    """The two service cuts, checked against observations and linked journals, not criterion booleans alone."""

    def detail(self, cid):
        return self.crit.get(cid, (None, {}))[1].get('detail')

    def evidence(self):
        ctx = self.ctx
        ev = self.doc.get('evidence')
        if not exact_keys(ctx, ev, EVIDENCE_KEYS[self.name], 'evidence'):
            return
        self.ev = ev
        try:
            self.metadata()
            sentinel = check_sentinel(ctx, ev['sentinel'])
            self.proc_start = self.owners(ev['owners_at_start'], 'evidence.owners_at_start')
            end = self.owners(ev['owners_at_end'], 'evidence.owners_at_end')
            self.ledgers(ev['ledgers'])
            self.inventories(check_inventory(ctx, ev['inventory_before'], 'evidence.inventory_before'),
                             check_inventory(ctx, ev['inventory_after'], 'evidence.inventory_after'), sentinel)
            if not self.intents or self.guard_runs is None or not self.proc_start or not end:
                return
            ctx.expect(end['actor']['pid'] == self.proc_start['actor']['pid'], 'owner_identity_changed', 'owners_at_end.actor')
            if self.name == 'controller-kill-running':
                self.final_owners(end)
                self.active()
                self.kill_controller_cut()
            else:
                self.cancel_verifier(end)
            self.detail_is('harness_test_copied_exactly', None)
            self.detail_is('installation_empty_before', None)
        except (KeyError, TypeError, ValueError, IndexError, AttributeError):
            ctx.bad('a4b_evidence_invalid', 'evidence', 'a required observation is malformed')

    def metadata(self):
        ctx, value = self.ctx, self.ev['a4b']
        if not exact_keys(ctx, value, ('delivery_id', 'not_repeated', 'sources', 'stage'), 'evidence.a4b'):
            return
        ctx.expect(value['delivery_id'] == 'SC2-controller-boundary-v1' and value['stage'] == 'A4b', 'a4b_contract_invalid', 'evidence.a4b')
        expected = ('docs/operacion/A4-RECEPCION-SC3.md', 'docs/operacion/A4B-CORTES-SERVICIO.md',
                    'development/claude/bases/sc3-service-cuts-a4b-r2.json')
        if exact_keys(ctx, value['sources'], expected, 'evidence.a4b.sources'):
            for path, digest in value['sources'].items():
                fmt(ctx, digest, 'hex64', 'evidence.a4b.sources.' + path)
                known = self.cand.sha_of(path) or self.atts.get(path, {}).get('sha256')
                if known is None:
                    ctx.absent('a4b_contract_unbound', path, 'attach the producer contract by its recorded digest')
                else:
                    ctx.expect(digest == known, 'a4b_contract_mismatch', path)
        ctx.expect(value['not_repeated'] == {'a4_scenarios': list(SCENARIOS),
            'a2_receipts': 'inherited by hash through ' + A4B_INHERITANCE_PATH}, 'a4b_scope_invalid', 'evidence.a4b.not_repeated')

    def proofs(self, phases):
        controller, result, ctx = self.ev['controller'], {}, self.ctx
        if not exact_keys(ctx, controller, phases, 'evidence.controller'):
            return result
        for phase in phases:
            entry = controller[phase]
            if not exact_keys(ctx, entry, ('proofs', 'returncode'), 'evidence.controller.' + phase):
                continue
            expected = -9 if self.name == 'controller-kill-running' and phase == 'cut' else 0
            ctx.expect(same(entry['returncode'], expected), 'controller_phase_failed', phase)
            if not (type(entry['proofs']) is list and len(entry['proofs']) == 1 and type(entry['proofs'][0]) is dict):
                ctx.bad('proof_count', phase)
                continue
            proof = entry['proofs'][0]
            ctx.expect(proof.get('scenario') == self.name and proof.get('phase') == phase, 'proof_identity_mismatch', phase)
            if 'controller' in proof:
                facts = check_controller_facts(ctx, proof['controller'], 'evidence.controller.' + phase + '.facts')
                if facts:
                    actor, guard = self.proc_start['actor']['pid'], self.proc_start['guard']['pid']
                    if self.name == 'cancel-api-verifier-running':
                        guard = self.ev['guard_replacement']['wrapper']['pid']
                    ctx.expect(facts['so_peercred']['actor']['pid'] == actor and facts['so_peercred']['guard']['pid'] == guard,
                               'peer_process_mismatch', phase)
            result[phase] = proof
        return result

    def kill_controller_cut(self):
        ctx, ev = self.ctx, self.ev
        proofs = self.proofs(('cut', 'blocked', 'recover'))
        if len(proofs) != 3:
            return
        cut, blocked, recovered = (proofs[p] for p in ('cut', 'blocked', 'recover'))
        first = self.intents[0]
        identity = {key: first[key] for key in ('container_id', 'intent_id', 'run_id', 'variant')}
        identity['installation_id'] = self.installation
        ctx.expect(cut.get('check') == 'controller_before_cut' and cut.get('identity') == identity and cut.get('run_status') == 'running',
                   'controller_cut_identity', 'controller.cut')
        kill = ev['controller_kill']
        target = kill['target']
        ctx.expect(kill['signal'] == 'SIGKILL' and same(kill['returncode'], -9)
                   and target['pid'] == cut['controller']['pid'] == cut['pid']
                   and target['ppid'] == target['harness_pid'] == cut['ppid']
                   and same(target['uids'], [CONTROLLER_UID] * 4) and same(target['gids'], [CONTROLLER_UID] * 4)
                   and same(target['groups'], []) and same(target['no_new_privileges'], 1)
                   and target['argv_tail'][-1].endswith('::test_scenario_controller_kill_running'), 'signal_target_mismatch', 'controller_kill')
        self.detail_is('controller_cut_ended_with_status_-9_as_induced', -9)
        self.detail_is('cut:sqlite_run_status_running_seen_by_the_controller', 'running')
        self.detail_is('cut:durable_ACTIVE_observed', list(KINDS[:4]))
        self.detail_is('cut:docker_Running_true_observed', RUNNING)
        ctx.expect(ev['cut_point'] == {'name': 'controller_running_actor_active', 'runs_status': 'running', 'owner_state': 'ACTIVE',
            'docker_running': True, 'finish_written': False, 'verifier_started': False}, 'cut_point_invalid', 'cut_point')
        ctx.expect(blocked.get('check') == 'controller_restart_blocked' and blocked.get('run_id') == first['run_id']
                   and blocked.get('pid') != target['pid'] and blocked.get('status') == 'failed'
                   and blocked.get('interrupted_from') == 'running' and blocked.get('status_events') == ['queued', 'running', 'failed']
                   and same(blocked.get('post_http'), 503) and blocked.get('owner_reason') == 'receipt_unknown',
                   'restart_not_blocked', 'controller.blocked')
        self.detail_pred('blocked:terminal_is_interrupted_failed_and_was_running_not_a_success',
            lambda d: d['status'] == 'failed' and d['receipt_status'] == 'unknown' and d['usage_final'] is False
                      and d['identity'] == identity and d['post_cleanup_block_message'] is True,
            'the interrupted terminal must remain honest and blocked')
        rec = ev['owner_reconciliation']
        ctx.expect(rec['finish_observed'] is True and rec['owner_pid'] == self.proc_start['actor']['pid']
                   and type(rec['ttl_seconds']) in (int, float) and math.isfinite(rec['ttl_seconds']) and rec['ttl_seconds'] > 0
                   and rec['wait_bound_seconds'] >= rec['ttl_seconds'] + rec['reap_interval_seconds'],
                   'restitution_not_observed', 'owner_reconciliation')
        ctx.expect(not any(action in ('create', 'start') or action.startswith('exec_') for action in ev['docker_actions_after_cut']),
                   'action_replayed', 'docker_actions_after_cut')
        self.detail_pred('reconcile:exactly_one_create_one_start_and_the_id_was_destroyed',
            lambda d: d.count('create') == 1 and d.count('start') == 1 and 'destroy' in d, 'original actor lifecycle is not unique')
        observation = ev['create_event_observation']
        events, expected = observation['events'], [intent['container_id'] for intent in self.intents]
        ctx.expect(observation['collector_alive_at_end'] is True and len(events) == 3
                   and observation['installation_label'] == 'org.agent-escape-room.actor-installation'
                   and observation['installation_id'] == self.installation and observation['expected_actor_ids'] == expected
                   and sorted(event['Actor']['ID'] for event in events) == sorted(expected)
                   and all(event['Action'] == 'create' and event['Actor']['Attributes'][observation['installation_label']] == self.installation for event in events),
                   'actor_creates_mismatch', 'create_event_observation')
        self.detail_is('recover:three_creates_in_total_no_replay_of_the_interrupted_run', observation)
        self.detail_is('cut:live_create_stream_observed_the_original_id_before_SIGKILL', events[:1])
        self.settled('recover', 3, expected)
        self.detail_is('reconcile:own_id_absent', ABSENT)
        ctx.expect(len(self.guard_runs) == 1 and self.guard_runs[0]['run_id'] == self.groups[1][0], 'guard_handled_wrong_run', 'ledgers.guard')
        ctx.expect(recovered.get('check') == 'recovered' and recovered['run_id'] == first['run_id']
                   and recovered['controller']['pid'] not in (target['pid'], blocked['pid']), 'recovery_proof_invalid', 'controller.recover')
        for key, intent in (('original_receipt', first), ('later_receipt', self.intents[1])):
            receipt = recovered[key]
            ctx.expect(receipt.get('status') == 'confirmed' and receipt.get('cleanup_confirmed') is True
                       and all(receipt.get(field) == intent[field] for field in ('container_id', 'intent_id', 'run_id', 'variant'))
                       and receipt.get('installation_id') == self.installation, 'durable_receipt_mismatch', key)
        self.detail_is('controller_recover_assertions_passed', 0)

    def cancel_verifier(self, end):
        ctx, ev = self.ctx, self.ev
        proofs = self.proofs(('cut',))
        if 'cut' not in proofs:
            return
        proof, replacement, instrumentation = proofs['cut'], ev['guard_replacement'], ev['instrumentation']
        wrapper = check_owner(ctx, replacement['wrapper'], 'guard', 'guard_replacement.wrapper')
        if wrapper:
            ctx.expect(end['guard']['pid'] == wrapper['pid'] != self.proc_start['guard']['pid']
                       and replacement['replaced']['proc']['pid'] == self.proc_start['guard']['pid']
                       and replacement['replaced']['journal'] == [] and same(replacement['clean_stop']['returncode'], 0)
                       and replacement['clean_stop']['socket_absent_after_stop'] is True, 'guard_replacement_invalid', 'guard_replacement')
        ctx.expect(instrumentation['source'] == A4B_HARNESS and instrumentation['sha256'] == self.doc['harness_sources'][A4B_HARNESS]
                   and instrumentation['modified'] is False and instrumentation['hold_first_start'] is True
                   and instrumentation['reused_symbols'] == ['Channel', 'build_guard_class'], 'instrumentation_unbound', 'instrumentation')
        for path, digest in instrumentation['daemon_guard_pinned'].items():
            ctx.expect(path in A2_GUARD_DEPENDENCIES and digest == self.cand.sha_of(path), 'instrumentation_unbound', path)
        ctx.expect(len(self.guard_runs) == 1, 'guard_run_count', 'ledgers.guard')
        guard, intent = self.guard_runs[0], self.intents[0]
        running = ev['verifier_running']
        ctx.expect(running['container_id'] == guard['container_id'] and same(running['docker'], RUNNING)
                   and running['wrapper_event']['container_id'] == guard['container_id'] and running['wrapper_event']['status'] == 'running',
                   'verifier_not_running', 'verifier_running')
        ctx.expect(running['guard_journal'] == ev['ledgers']['guard'][:2], 'guard_ack_mismatch', 'verifier_running.guard_journal')
        started, finished = proof['verifier_started'], proof['verifier_finished']
        for value in (started, finished, running['controller_started_event']):
            ctx.expect(value['run_id'] == intent['run_id'] == guard['run_id'] and value['variant'] == 'legitimate'
                       and value['artifact_sha256'] == guard['artifact_sha256'], 'verifier_handoff_mismatch', 'controller.cut')
        ctx.expect(finished['cleanup_confirmed'] is True and proof.get('check') == 'cancel_api_verifier'
                   and same(proof['cancel_http'], 200) and same(proof['premature_http'], 409) and same(proof['second_premature_http'], 409)
                   and proof['reopened_reports_identical'] is True and is_hex(proof['report_sha256']), 'cancel_proof_invalid', 'controller.cut')
        times = ev['timeline_operator_clock_ns']
        order = [times[key] for key in ('running_seen_ns', 'cancel_seen_ns', 'release_sent_ns', 'finish_seen_ns')]
        ctx.expect(all(type(t) is int and t > 0 for t in order) and all(a < b for a, b in zip(order, order[1:])),
                   'handoff_order_invalid', 'timeline_operator_clock_ns')
        actions = ev['verifier_docker_actions']
        ctx.expect(actions.count('create') == actions.count('start') == 1 and 'destroy' in actions, 'verifier_lifecycle_invalid', 'verifier_docker_actions')
        self.detail_is('release:verifier_id_absent_at_FINISH', ABSENT)
        self.detail_is('release:guard_installation_inventory_empty', [])
        self.detail_is('release:guard_journal_PENDING_ACK_FINISH', ['PENDING', 'ACK', 'FINISH'])
        self.detail_is('release:one_create_one_start_for_the_verifier_and_it_was_destroyed', actions)
        self.detail_pred('cancel:no_terminal_and_no_admission_while_the_guard_waits',
            lambda d: d['status'] not in ('completed', 'failed', 'cancelled') and d['task_done'] is False
                      and d['premature_http'] == 409 and d['cancel_marked'] is True and d['task_cancelling'] > 0,
            'cancel must keep waiting and exclude new admission')
        self.detail_is('cancel:guard_barrier_held_no_FINISH', ['PENDING', 'ACK'])
        self.detail_pred('wait:controller_resampled_after_the_operator_no_terminal_no_admission',
            lambda d: d['status'] not in ('completed', 'failed', 'cancelled') and d['task_done'] is False
                      and d['second_premature_http'] == 409 and d['verifier_finished_seen'] is False,
            'the last sample must still wait for verifier cleanup')
        self.detail_is('wait:guard_still_held_at_the_last_sample', ['PENDING', 'ACK'])
        self.detail_is('wait:verifier_still_running_at_the_last_sample_before_the_release', RUNNING)
        self.detail_is('terminal:reports_json_and_markdown_identical_after_reopening_the_service', True)
        self.detail_pred('terminal:cancelled_with_the_same_digest_and_confirmed_verifier_cleanup',
            lambda d: d['status'] == 'cancelled' and d['verifier_finished_digest'] == guard['artifact_sha256']
                      and d['verifier_cleanup'] is True and d['variants_started'] == ['legitimate'], 'cancelled terminal or digest is inconsistent')
        self.settled('terminal', 1, [intent['container_id']])
        self.detail_is('controller_cut_assertions_passed', 0)


def check_scenario(rep, doc, cand, atts, index):
    """Decision record for one scenario receipt. A non-ok result is rejected AND preserved (code and failed criteria stay in the decision)."""
    name = doc.get('scenario') if type(doc) is dict else None
    if type(name) is not str or name not in SCENARIOS + A4B_SCENARIOS:
        Ctx(rep, 'receipt[' + str(index) + ']').bad('scenario_unknown', 'scenario', 'not a recognized A4/A4b scenario')
        return None
    ctx = Ctx(rep, 'scenario:' + name)
    code = doc.get('code')
    record = {'scenario': name, 'code': code if type(code) is str else None, 'verdict': 'rejected'}
    if doc.get('schema') != A4_SCHEMA:
        ctx.bad('schema_mismatch', 'schema', 'expected ' + A4_SCHEMA)
        return record
    if type(code) is not str or code not in CODES:
        ctx.bad('code_unknown', 'code', 'the closed result code set is ' + ', '.join(CODES))
        return record
    if code != 'ok':
        ctx.bad('receipt_code_not_ok', 'code', 'the producer recorded ' + code + '; the result is conserved and the criterion stays open')
        record.update(failed_criteria=failed_ids(doc.get('criteria')), fixture_retained=doc.get('fixture_retained') if type(doc.get('fixture_retained')) is bool else None)
        return record
    checker = (A4bChecker if name in A4B_SCENARIOS else ScenarioChecker)(rep, doc, cand, atts).check()
    record.update(verdict=checker.ctx.verdict, installation_id=checker.installation, image_id=doc.get('image_id'), profile_sha256=doc.get('profile_sha256'),
                  a2_inheritance_sha256=checker.a2_sha, intents=len(checker.intents or []), guard_runs=len(checker.guard_runs or []))
    record['_ids'] = checker.ids
    return record


# ---------------------------------------------------------------- actor service receipt (invoice-actor-service-local/v1): positive + F-veto

SERVICE_KEYS = ('actor_boundary', 'actor_identities', 'application_peers', 'capabilities_zero', 'controller_groups', 'controller_uid',
                'docker_endpoints_denied', 'fixture_provider_calls', 'harness_sources', 'host_mounts_hidden', 'image_id', 'ledgers', 'local_fixture',
                'network_interfaces', 'no_new_privileges', 'owner_journals_denied', 'owner_processes', 'profile_sha256', 'reports_reopened_equal',
                'run_id', 'schema', 'sealed_sha256', 'sources', 'unmapped_request_http', 'verifications')
SERVICE_OWNER_KEYS = ('cap_eff', 'gids', 'groups', 'no_new_privileges', 'pid', 'uids')
LEGIT_KEYS = ('actor_receipt_id', 'artifact_sha256', 'cleanup_confirmed', 'container_id', 'input_sha256', 'schema', 'status', 'verifier_sha256')
PERTURBED_KEYS = ('actor_receipt_id', 'reason', 'schema', 'status')


def check_service_receipt(rep, doc, cand, atts):
    """Local fixture with a provider double. It can establish the positive control and F-veto, and only when bound to the candidate's bytes."""
    ctx = Ctx(rep, 'service_receipt')
    result = {'verdict': 'rejected', 'bound': False, 'diffs': [], 'positive': False, 'f_veto': False, 'run_id': None, 'image_id': None,
              'profile_sha256': None, 'containers': set(), 'run_ids': set()}
    if type(doc) is not dict or doc.get('schema') != SERVICE_SCHEMA:
        ctx.bad('schema_mismatch', 'schema', 'expected ' + SERVICE_SCHEMA)
        return result
    exact_keys(ctx, doc, SERVICE_KEYS, '$')
    start_bad, start_absent = ctx.bad_count, ctx.absent_count
    ctx.expect(doc.get('local_fixture') is True, 'not_a_local_fixture', 'local_fixture', 'the receipt must declare itself a local fixture')
    fmt(ctx, doc.get('run_id'), 'hex32', 'run_id')
    fmt(ctx, doc.get('image_id'), 'image', 'image_id')
    fmt(ctx, doc.get('profile_sha256'), 'hex64', 'profile_sha256')
    fmt(ctx, doc.get('sealed_sha256'), 'hex64', 'sealed_sha256')
    for key in ('capabilities_zero', 'host_mounts_hidden', 'no_new_privileges', 'owner_journals_denied', 'reports_reopened_equal'):
        ctx.expect(doc.get(key) is True, 'observation_not_true', key, 'the observation is not a JSON true')
    ctx.expect(is_int(doc.get('controller_uid')) and doc['controller_uid'] == CONTROLLER_UID, 'controller_uid_mismatch', 'controller_uid', 'the controller must run as UID 65534')
    ctx.expect(same(doc.get('controller_groups'), []), 'controller_groups', 'controller_groups', 'the controller must hold no supplementary groups')
    ctx.expect(same(doc.get('network_interfaces'), ['lo']), 'network_not_loopback_only', 'network_interfaces')
    ctx.expect(same(doc.get('unmapped_request_http'), 422), 'unmapped_request_accepted', 'unmapped_request_http', 'an unsupported request must be refused with 422')
    ctx.expect(is_int(doc.get('fixture_provider_calls')) and doc['fixture_provider_calls'] >= 0, 'proof_value_invalid', 'fixture_provider_calls')
    check_docker_denials(ctx, doc.get('docker_endpoints_denied'), 'docker_endpoints_denied')
    installation, boundary = None, doc.get('actor_boundary')
    if exact_keys(ctx, boundary, ('controller_uid', 'image_id', 'installation_id', 'mission', 'owner_uid', 'schema'), 'actor_boundary'):
        ctx.expect(boundary['schema'] == 'invoice-actor/v1' and boundary['mission'] == 'invoice-reconcile/v1', 'boundary_invalid', 'actor_boundary', 'unexpected boundary schema or mission')
        ctx.expect(is_int(boundary['controller_uid']) and boundary['controller_uid'] == CONTROLLER_UID and is_int(boundary['owner_uid']) and boundary['owner_uid'] == ACTOR_UID,
                   'boundary_uid_mismatch', 'actor_boundary', 'controller and owner UIDs are not the expected ones')
        ctx.expect(fmt(ctx, boundary['image_id'], 'image', 'actor_boundary.image_id') and boundary['image_id'] == doc.get('image_id'), 'image_crossed', 'actor_boundary.image_id',
                   'the boundary names another image than the receipt')
        if fmt(ctx, boundary['installation_id'], 'hex32', 'actor_boundary.installation_id'):
            installation = boundary['installation_id']
    peer_pids, peers, procs = {}, doc.get('application_peers'), doc.get('owner_processes')
    if exact_keys(ctx, peers, ('actor', 'guard'), 'application_peers'):
        for role in ('actor', 'guard'):
            peer = check_peer(ctx, peers[role], role, 'application_peers.' + role)
            if peer is not None:
                peer_pids[role] = peer['pid']
    if exact_keys(ctx, procs, ('actor', 'guard'), 'owner_processes'):
        for role in ('actor', 'guard'):
            proc = check_owner(ctx, procs[role], role, 'owner_processes.' + role, keys=SERVICE_OWNER_KEYS)
            if proc is not None and role in peer_pids:
                ctx.expect(proc['pid'] == peer_pids[role], 'so_peercred_pid_mismatch', 'owner_processes.' + role, 'the socket peer is not the process observed for this owner')
    identities, listed = doc.get('actor_identities'), []
    if type(identities) is list and len(identities) == 2:
        listed = [check_identity(ctx, item, 'actor_identities[' + str(n) + ']', installation) for n, item in enumerate(identities)]
        if all(item is not None for item in listed):
            ctx.expect([item['variant'] for item in listed] == list(VARIANTS), 'identity_variants', 'actor_identities', 'the identities must be legitimate then perturbed')
            ctx.expect(all(item['run_id'] == doc.get('run_id') for item in listed), 'identity_run_crossed', 'actor_identities', 'an identity belongs to another run')
            ctx.expect(len({item['intent_id'] for item in listed}) == 2 and len({item['container_id'] for item in listed}) == 2, 'identity_reused', 'actor_identities',
                       'the two identities share an intent or container')
    else:
        ctx.bad('type_mismatch', 'actor_identities', 'two identities (legitimate, perturbed) are required')
    intents = guard_runs = None
    ledgers = doc.get('ledgers')
    if exact_keys(ctx, ledgers, ('actor', 'guard'), 'ledgers'):
        actor, guard = norm_records(ctx, ledgers['actor'], 'ledgers.actor'), norm_records(ctx, ledgers['guard'], 'ledgers.guard')
        if actor is not None:
            intents = check_actor_events(ctx, actor, 'ledgers.actor')
        if guard is not None:
            guard_runs = check_guard_events(ctx, guard, 'ledgers.guard')
    if intents is not None:
        ctx.expect(len(intents) == 2 and [item['variant'] for item in intents] == list(VARIANTS) and {item['run_id'] for item in intents} == {doc.get('run_id')},
                   'ledger_run_structure', 'ledgers.actor', 'the ledger must hold the legitimate then the perturbed intent of the one run')
        for intent, ident in zip(intents, listed):
            if ident is not None:
                for key in ('intent_id', 'run_id', 'variant', 'container_id'):
                    ctx.expect(intent[key] == ident[key], 'identity_ledger_mismatch', 'ledgers.actor.' + key, 'the ledger and actor_identities disagree')
        result['containers'] = {item['container_id'] for item in intents}
    diffs = service_diff(ctx, doc.get('sources'), cand, 'sources')
    if diffs:
        ctx.bad('product_source_mismatch', 'sources', 'the executed product sources are not the candidate (another photo): ' + few(diffs))
    found = harness_diff(ctx, doc.get('harness_sources'), cand, atts, SERVICE_HARNESS, 'harness_sources')
    harness_bound = found is not None and not found[0] and not found[1]
    if found is not None and found[0]:
        ctx.bad('harness_source_mismatch', 'harness_sources', 'the executed harness is not the one listed for the candidate: ' + few(found[0]))
    if found is not None and found[1]:
        ctx.absent('harness_source_unbound', 'harness_sources', 'not reachable by manifest or explicit attachment: ' + few(found[1]))
    common_ok = ctx.bad_count == start_bad and ctx.absent_count == start_absent
    verifications = doc.get('verifications')
    legit = perturbed = None
    if exact_keys(ctx, verifications, VARIANTS, 'verifications'):
        legit, perturbed = verifications['legitimate'], verifications['perturbed']
    input_sha, _total = verifier_facts(cand)
    verifier_sha = cand.sha_of(VERIFIER_PATH)
    # positive control: the legitimate variant passed, bound to this run, this artifact, this verifier container and this verifier code
    mark = ctx.bad_count
    legit_ok = exact_keys(ctx, legit, LEGIT_KEYS, 'verifications.legitimate')
    if legit_ok:
        ctx.expect(legit['schema'] == 'invoice-independent/v1' and legit['status'] == 'passed', 'verdict_not_passed', 'verifications.legitimate', 'the guard verdict is not passed')
        ctx.expect(legit['cleanup_confirmed'] is True, 'verifier_cleanup_unconfirmed', 'verifications.legitimate.cleanup_confirmed', 'the verifier container was not confirmed gone')
        fmt(ctx, legit['actor_receipt_id'], 'hex32', 'verifications.legitimate.actor_receipt_id')
        for key in ('artifact_sha256', 'container_id', 'input_sha256', 'verifier_sha256'):
            fmt(ctx, legit[key], 'hex64', 'verifications.legitimate.' + key)
        if verifier_sha is not None:
            ctx.expect(legit['verifier_sha256'] == verifier_sha, 'verifier_digest_mismatch', 'verifications.legitimate.verifier_sha256', 'the verdict was produced by other verifier code')
        if input_sha is not None:
            ctx.expect(legit['input_sha256'] == input_sha, 'verifier_input_mismatch', 'verifications.legitimate.input_sha256', 'the verdict is for another input than the candidate verifier embeds')
        else:
            ctx.absent('verifier_input_unbound', 'verifications.legitimate.input_sha256', 'the candidate verifier input could not be derived statically')
        if guard_runs is not None:
            ctx.expect(len(guard_runs) == 1, 'guard_transition_count', 'ledgers.guard', 'exactly one verifier run (the legitimate variant) is expected')
            for run in guard_runs[:1]:
                ctx.expect(run['run_id'] == doc.get('run_id') and run['variant'] == 'legitimate', 'guard_run_mismatch', 'ledgers.guard', 'the guard handled another run or variant')
                ctx.expect(run['artifact_sha256'] == legit['artifact_sha256'], 'guard_artifact_mismatch', 'ledgers.guard', 'the guard ledger and the verdict name different artifact digests')
                ctx.expect(run['container_id'] == legit['container_id'], 'guard_container_mismatch', 'ledgers.guard', 'the guard ledger and the verdict name different verifier containers')
                ctx.expect(run['container_id'] not in result['containers'], 'container_crossed', 'ledgers.guard', 'a verifier container is also an actor container')
    positive_clean = legit_ok and ctx.bad_count == mark
    # F-veto: the perturbed variant failed its task locally; the guard has no transition for it and the verdict is "unavailable", never "rejected"
    mark = ctx.bad_count
    pert_ok = exact_keys(ctx, perturbed, PERTURBED_KEYS, 'verifications.perturbed')
    if pert_ok:
        ctx.expect(perturbed['schema'] == 'invoice-independent/v1' and perturbed['status'] == 'unavailable' and perturbed['reason'] == 'actor_task_not_passed',
                   'f_veto_not_demonstrated', 'verifications.perturbed', 'F-veto requires status unavailable with reason actor_task_not_passed')
        fmt(ctx, perturbed['actor_receipt_id'], 'hex32', 'verifications.perturbed.actor_receipt_id')
        if legit_ok:
            ctx.expect(perturbed['actor_receipt_id'] != legit['actor_receipt_id'], 'identity_reused', 'verifications.perturbed.actor_receipt_id', 'both variants share an actor receipt')
    if guard_runs is not None:
        ctx.expect(all(run['variant'] != 'perturbed' for run in guard_runs), 'guard_saw_failed_variant', 'ledgers.guard', 'F-veto violated: the guard has a transition for the perturbed variant')
    veto_clean = pert_ok and intents is not None and guard_runs is not None and ctx.bad_count == mark
    bound = diffs == [] and harness_bound
    result.update(verdict=ctx.verdict, bound=bound, diffs=diffs or [], run_id=doc.get('run_id'), image_id=doc.get('image_id'), profile_sha256=doc.get('profile_sha256'),
                  positive=bool(common_ok and positive_clean and bound), f_veto=bool(common_ok and veto_clean and bound))
    result['run_ids'] = {doc['run_id']} if is_hex(doc.get('run_id'), HEX32) else set()
    return result


# ---------------------------------------------------------------- historical guard receipt (local-invoice-verifier-proof/v1): F-guard, own photo

GUARD_KEYS = ('containers_absent_after', 'direct_control', 'disconnected_client_container', 'guard_uid', 'image', 'lifecycle', 'receipts', 'schema',
              'socket_absent_after_stop', 'source_sha256', 'wrong_client', 'wrong_server')
GUARD_SOURCES = ('daemon_guard.py', 'guard_client.py', 'invoice_verifier.py')
RECEIPT_KEYS = ('artifact_sha256', 'cleanup_confirmed', 'container_id', 'input_sha256', 'status', 'verifier_sha256')
LIFECYCLE = ['create', 'attach', 'start', 'die', 'destroy']


def check_guard_receipt(rep, doc, cand, atts):
    """Direct guard control. Internally consistent evidence is `valid`; it counts for THIS candidate only when its sources equal the manifest (`bound`)."""
    ctx = Ctx(rep, 'guard_receipt')
    result = {'valid': False, 'bound': False, 'diffs': [], 'rejected_artifact_sha256': None, 'verifier_sha256': None, 'input_sha256': None,
              'image_id': None, 'guard_uid': None, 'containers': set()}
    if type(doc) is not dict or doc.get('schema') != GUARD_SCHEMA:
        ctx.bad('schema_mismatch', 'schema', 'expected ' + GUARD_SCHEMA)
        return result
    exact_keys(ctx, doc, GUARD_KEYS, '$')
    ctx.expect(doc.get('containers_absent_after') is True and doc.get('socket_absent_after_stop') is True, 'restitution_not_observed', '$',
               'the verifier containers and the guard socket must be observed absent after the run')
    direct = doc.get('direct_control')
    if exact_keys(ctx, direct, ('docker', 'groups', 'interfaces', 'malformed_request', 'mnt_hidden', 'uid'), 'direct_control'):
        ctx.expect(is_int(direct['uid']) and direct['uid'] == CONTROLLER_UID and same(direct['groups'], []) and same(direct['interfaces'], ['lo']) and direct['mnt_hidden'] is True,
                   'direct_control_invalid', 'direct_control', 'the client must be UID 65534 with no groups, loopback only and the host mounts hidden')
        check_docker_denials(ctx, direct['docker'], 'direct_control.docker')
        ctx.expect(same(direct['malformed_request'], {'reason': 'invalid_request', 'status': 'error'}), 'malformed_request_accepted', 'direct_control.malformed_request',
                   'a malformed request must be refused')
    ctx.expect(same(doc.get('wrong_client'), {'reason': 'unauthorized', 'status': 'error'}), 'wrong_client_accepted', 'wrong_client', 'a wrong client UID must be refused')
    ctx.expect(same(doc.get('wrong_server'), {'reason': 'unexpected_guard_uid', 'status': 'error'}), 'wrong_server_accepted', 'wrong_server', 'a wrong guard UID must be refused')
    fmt(ctx, doc.get('image'), 'image', 'image')
    ctx.expect(is_int(doc.get('guard_uid')) and doc['guard_uid'] >= 0, 'invalid_uid', 'guard_uid')
    lifecycle, known = doc.get('lifecycle'), set()
    if type(lifecycle) is dict and 0 < len(lifecycle) <= 16:
        for cid, actions in lifecycle.items():
            if is_hex(cid) and same(actions, LIFECYCLE):
                known.add(cid)
            else:
                ctx.bad('lifecycle_invalid', 'lifecycle', 'every container needs create, attach, start, die, destroy in that order')
    else:
        ctx.bad('type_mismatch', 'lifecycle', 'a bounded map of container lifecycles is required')
    disconnected = doc.get('disconnected_client_container')
    if fmt(ctx, disconnected, 'hex64', 'disconnected_client_container'):
        ctx.expect(disconnected in known, 'lifecycle_missing', 'disconnected_client_container', 'the container of the disconnected client has no lifecycle')
    input_sha, total = verifier_facts(cand)
    verifier_sha = cand.sha_of(VERIFIER_PATH)
    receipts, diffs = doc.get('receipts'), []
    if type(receipts) is list and len(receipts) == 2 and all(exact_keys(ctx, item, RECEIPT_KEYS, 'receipts[' + str(n) + ']') for n, item in enumerate(receipts)):
        passed, rejected = receipts
        ctx.expect(passed['status'] == 'passed' and rejected['status'] == 'rejected', 'verdicts_unexpected', 'receipts', 'the first receipt must be passed and the second rejected')
        for n, item in enumerate(receipts):
            where = 'receipts[' + str(n) + ']'
            ctx.expect(item['cleanup_confirmed'] is True, 'verifier_cleanup_unconfirmed', where + '.cleanup_confirmed', 'the verifier container was not confirmed gone')
            for key in ('artifact_sha256', 'container_id', 'input_sha256', 'verifier_sha256'):
                fmt(ctx, item[key], 'hex64', where + '.' + key)
            ctx.expect(item['container_id'] in known, 'lifecycle_missing', where + '.container_id', 'the verifier container has no recorded lifecycle')
        ctx.expect(passed['container_id'] != rejected['container_id'] and passed['container_id'] != disconnected and rejected['container_id'] != disconnected,
                   'identity_reused', 'receipts', 'two verdicts share a verifier container')
        ctx.expect(passed['artifact_sha256'] != rejected['artifact_sha256'], 'artifact_reused', 'receipts', 'the rejected artifact must differ from the passed one')
        ctx.expect(passed['verifier_sha256'] == rejected['verifier_sha256'] and passed['input_sha256'] == rejected['input_sha256'], 'verdicts_not_comparable', 'receipts',
                   'both verdicts must come from the same verifier code and the same input')
        result['rejected_artifact_sha256'] = rejected['artifact_sha256'] if is_hex(rejected['artifact_sha256']) else None
        result['verifier_sha256'], result['input_sha256'] = passed['verifier_sha256'], passed['input_sha256']
        result['containers'] = {passed['container_id'], rejected['container_id']}
        if input_sha is not None and passed['input_sha256'] != input_sha:
            diffs.append('changed:verifier_input')
    else:
        ctx.bad('type_mismatch', 'receipts', 'two verdict receipts (passed, rejected) are required')
    sources = doc.get('source_sha256')
    if exact_keys(ctx, sources, GUARD_SOURCES, 'source_sha256'):
        for name in GUARD_SOURCES:
            if not fmt(ctx, sources[name], 'hex64', 'source_sha256.' + name):
                continue
            expected = cand.sha_of('services/agent/' + name)
            if expected is None:
                diffs.append('absent:' + name)
            elif expected != sources[name]:
                diffs.append('changed:' + name)
        if result['verifier_sha256'] is not None and is_hex(sources.get('invoice_verifier.py')):
            ctx.expect(result['verifier_sha256'] == sources['invoice_verifier.py'], 'verifier_digest_mismatch', 'source_sha256.invoice_verifier.py',
                       'the verdicts and the recorded verifier source name different code')
    result.update(valid=ctx.bad_count == 0, bound=ctx.bad_count == 0 and not diffs, diffs=diffs, image_id=doc.get('image'),
                  guard_uid=doc.get('guard_uid') if is_int(doc.get('guard_uid')) else None)
    result['expected_total'] = total
    return result


def check_f_guard_artifact(rep, guard, atts):
    """Optional bytes of the rejected artifact, found by digest among the attachments: correct digest, valid JSON, false total."""
    digest = guard['rejected_artifact_sha256']
    match = next((item for item in atts.values() if item['sha256'] == digest), None) if digest else None
    if match is None:
        return 'missing'
    ctx = Ctx(rep, 'f_guard_artifact')
    try:
        artifact = strict_loads(match['data'])
    except ReceiptError as exc:
        ctx.bad(exc.code, 'artifact', 'the rejected artifact is not valid JSON: it would test the parser, not the total')
        return 'rejected'
    total, expected = (artifact.get('accepted_total_cents') if type(artifact) is dict else None), guard.get('expected_total')
    if type(total) is not int or expected is None:
        ctx.bad('f_guard_artifact_invalid', 'artifact', 'a JSON object with an integer accepted_total_cents is required')
        return 'rejected'
    if total == expected:
        ctx.bad('f_guard_total_not_false', 'artifact', 'the artifact carries the correct total, so its rejection would not test the oracle')
        return 'rejected'
    return 'established'


# ---------------------------------------------------------------- local offline authoring receipt (sc2-actor-compatibility-a4-offline/v1)

OFFLINE_KEYS = ('branches', 'classification', 'code', 'command', 'dependencies', 'docker_used', 'linux_docker_scenarios', 'output_tail', 'returncode', 'schema')


def check_offline_receipt(rep, doc, cand, atts):
    """Authoring and logic with doubles. It never contributes a control; it must still be coherent and bound if it is supplied."""
    ctx = Ctx(rep, 'offline_receipt')
    result = {'valid': False, 'bound': False, 'diffs': [], 'code': None}
    if type(doc) is not dict or doc.get('schema') != OFFLINE_SCHEMA:
        ctx.bad('schema_mismatch', 'schema', 'expected ' + OFFLINE_SCHEMA)
        return result
    exact_keys(ctx, doc, OFFLINE_KEYS, '$')
    result['code'] = doc.get('code') if type(doc.get('code')) is str else None
    ctx.expect(doc.get('code') == 'ok', 'receipt_code_not_ok', 'code', 'the offline run did not end ok')
    ctx.expect(doc.get('docker_used') is False and doc.get('linux_docker_scenarios') == 'not run in --offline', 'offline_not_offline', 'docker_used',
               'an offline receipt cannot be a Docker measurement')
    ctx.expect(is_int(doc.get('returncode')) and doc['returncode'] == 0, 'offline_tests_failed', 'returncode', 'the offline test run did not end with code 0')
    tail = doc.get('output_tail')
    ctx.expect(type(tail) is str and len(tail) <= 8000 and re.search(r'\b\d+ passed\b', tail) is not None and re.search(r'\b\d+ (failed|errors?)\b', tail) is None,
               'offline_tests_not_passed', 'output_tail', 'the recorded test summary does not show passes without failures')
    ctx.expect(type(doc.get('command')) is list and all(type(item) is str for item in doc['command']), 'type_mismatch', 'command', 'a command list of strings is required')
    ctx.expect(type(doc.get('branches')) is list and 0 < len(doc['branches']) <= 32 and all(type(item) is dict for item in doc['branches']), 'type_mismatch', 'branches',
               'a bounded branch table is required')
    check_classification(ctx, doc.get('classification'))
    deps, diffs = doc.get('dependencies'), []
    if exact_keys(ctx, deps, HARNESS_FILES + (INHERITANCE_PATH,), 'dependencies'):
        for path in HARNESS_FILES + (INHERITANCE_PATH,):
            entry = deps[path]
            if not exact_keys(ctx, entry, ('exists', 'sha256'), 'dependencies.' + path) or not fmt(ctx, entry['sha256'], 'hex64', 'dependencies.' + path + '.sha256'):
                continue
            ctx.expect(entry['exists'] is True, 'dependency_absent', 'dependencies.' + path, 'a dependency was absent when the offline run started')
            known = known_sha(cand, atts, path)
            if known is None:
                diffs.append('unbound:' + path)
            elif known != entry['sha256']:
                diffs.append('changed:' + path)
    result.update(valid=ctx.bad_count == 0, bound=ctx.bad_count == 0 and not diffs, diffs=diffs)
    return result


# ---------------------------------------------------------------- A2 inheritance (by hash and diff) and the A4 integration diff

def check_inheritance(rep, cand, atts, reference, path=INHERITANCE_PATH):
    """The four A2 verifier-lifecycle receipts are inherited by hash only, for that scope, and only while the guard modules are unchanged."""
    ctx = Ctx(rep, 'a2_inheritance')
    result = {'status': 'not_checked', 'scope': A2_SCOPE, 'changed_dependencies': []}
    item = atts.get(path)
    if item is None:
        ctx.absent('attachment_missing', INHERITANCE_PATH, 'attach the A2 inheritance manifest explicitly (REL PATH SHA256): docs/evidencia is outside P5')
        result['status'] = 'attachment_missing'
        return result
    if reference is not None and item['sha256'] != reference:
        ctx.bad('a2_inheritance_hash_mismatch', INHERITANCE_PATH, 'the attached manifest is not the one the scenario receipts reference')
        result['status'] = 'rejected'
        return result
    try:
        doc = strict_loads(item['data'])
    except ReceiptError as exc:
        ctx.bad(exc.code, INHERITANCE_PATH, exc.message)
        result['status'] = 'rejected'
        return result
    if not exact_keys(ctx, doc, ('decision', 'dependencies', 'diff_review', 'receipts', 'schema'), '$'):
        result['status'] = 'rejected'
        return result
    ctx.expect(doc['schema'] == INHERITANCE_SCHEMA and type(doc['decision']) is str and doc['decision'] != '', 'inheritance_schema', 'schema', 'unexpected inheritance schema or decision')
    receipts = doc['receipts']
    if type(receipts) is list and len(receipts) == len(A2_RECEIPT_STEMS):
        for stem, entry in zip(A2_RECEIPT_STEMS, receipts):
            path = 'docs/evidencia/sc3-lifecycle/' + stem + '.json'
            if not exact_keys(ctx, entry, ('inherited_scope', 'path', 'sha256'), 'receipts.' + stem):
                continue
            ctx.expect(entry['path'] == path, 'a2_receipt_path', 'receipts.' + stem, 'unexpected A2 receipt path')
            ctx.expect(entry['inherited_scope'] == A2_SCOPE, 'a2_scope_widened', 'receipts.' + stem, 'A2 evidence may be inherited for the verifier guard lifecycle only')
            if not fmt(ctx, entry['sha256'], 'hex64', 'receipts.' + stem + '.sha256'):
                continue
            attached = atts.get(path)
            if attached is None:
                ctx.absent('a2_receipt_attachment_missing', path, 'attach this A2 receipt explicitly (REL PATH SHA256) to confirm the inherited hash')
            elif attached['sha256'] != entry['sha256']:
                ctx.bad('a2_receipt_hash_changed', path, 'the attached A2 receipt differs from the inherited hash')
    else:
        ctx.bad('type_mismatch', 'receipts', 'the four A2 receipts are required')
    dependencies, seen, changed = doc['dependencies'], set(), []
    if type(dependencies) is list and 0 < len(dependencies) <= 32:
        for number, dep in enumerate(dependencies):
            here = 'dependencies[' + str(number) + ']'
            if not exact_keys(ctx, dep, ('a2_sha256', 'changed', 'current_sha256', 'path'), here):
                continue
            good = fmt(ctx, dep['a2_sha256'], 'hex64', here + '.a2_sha256')
            good = fmt(ctx, dep['current_sha256'], 'hex64', here + '.current_sha256') and good
            good = ctx.expect(dep['path'] in A2_DEPENDENCIES and dep['path'] not in seen, 'a2_dependency_unexpected', here + '.path', 'not one of the five reviewed dependencies, or repeated') and good
            if not good:
                continue
            seen.add(dep['path'])
            ctx.expect(type(dep['changed']) is bool and dep['changed'] is (dep['a2_sha256'] != dep['current_sha256']), 'diff_flag_inconsistent', here + '.changed',
                       'the changed flag does not follow from the two hashes')
            ctx.expect(dep['current_sha256'] == cand.sha_of(dep['path']), 'dependency_changed_after_review', here + '.current_sha256',
                       'the reviewed current hash is not the candidate manifest hash')
            if dep['a2_sha256'] != dep['current_sha256']:
                changed.append(dep['path'])
                ctx.expect(dep['path'] not in A2_GUARD_DEPENDENCIES, 'a2_inheritance_invalidated', here + '.path', 'a guard module changed: the inherited A2 evidence no longer describes it')
        ctx.expect(seen == set(A2_DEPENDENCIES), 'a2_dependency_missing', 'dependencies', 'all five reviewed dependencies must be listed')
    else:
        ctx.bad('type_mismatch', 'dependencies', 'a bounded dependency list is required')
    review = doc['diff_review']
    ctx.expect(type(review) is list and len(review) <= 32 and all(type(entry) is str and entry for entry in review) and (review or not changed), 'diff_review_missing', 'diff_review',
               'a changed dependency needs a classified diff review')
    result.update(status='bound' if ctx.clean else ('rejected' if ctx.bad_count else 'incomplete'), changed_dependencies=sorted(changed))
    return result


def check_a4_diff(rep, cand, atts):
    """Optional classification of the corrected integration: its candidate hashes must be the manifest's, with no interface or journal change."""
    item = atts.get(DIFF_PATH)
    if item is None:
        return {'status': 'not_attached'}
    ctx = Ctx(rep, 'a4_diff')
    try:
        doc = strict_loads(item['data'])
    except ReceiptError as exc:
        ctx.bad(exc.code, DIFF_PATH, exc.message)
        return {'status': 'rejected'}
    keys = ('a4_reception_requirement', 'base_path', 'base_sha256', 'interface_change', 'journal_or_protocol_change', 'reason', 'runtime_changes', 'schema', 'verified_cases')
    if exact_keys(ctx, doc, keys, '$'):
        ctx.expect(doc['schema'] == DIFF_SCHEMA, 'diff_schema', 'schema', 'unexpected diff schema')
        ctx.expect(doc['interface_change'] is False and doc['journal_or_protocol_change'] is False, 'diff_not_neutral', '$', 'the integration changed an interface, the journal or the protocol')
        changes = doc['runtime_changes']
        if type(changes) is list and 0 < len(changes) <= 32:
            for number, entry in enumerate(changes):
                here = 'runtime_changes[' + str(number) + ']'
                if exact_keys(ctx, entry, ('a4_base_sha256', 'candidate_sha256', 'path'), here):
                    fmt(ctx, entry['a4_base_sha256'], 'hex64', here + '.a4_base_sha256')
                    ctx.expect(type(entry['path']) is str and entry['candidate_sha256'] == cand.sha_of(entry['path']), 'a4_diff_candidate_mismatch', here,
                               'the diff names a candidate hash that is not the manifest hash')
        else:
            ctx.bad('type_mismatch', 'runtime_changes', 'a bounded list of runtime changes is required')
    return {'status': 'consistent' if ctx.clean else 'rejected'}


# ---------------------------------------------------------------- commands

EVIDENCE_CLASSES = {
    'measured_by_operator_as_declared_by_the_receipts': [
        'docker inspect/ls/events by exact ID', 'owner journals read-only (SQLite)', '/proc status of owners and controller',
        'SO_PEERCRED of both owners from the controller', 'HTTP codes and SQLite rows of the service'],
    'established_by_this_tool': [
        'external manifest digest, P5 integrity and clean extraction', 'hash links between candidate manifest, executed product sources, harness and receipts',
        'exact JSON types, no duplicate keys, bounded sizes', 'ledger structure, identity links and observations recorded as criterion details'],
    'simulation': ['model provider double (no inference)', 'synthetic invoice task content'],
    'unknown_or_not_covered': [
        'the receipts are self-reported by the operator harness and are not signed: this tool cannot show the harness ran as described',
        'host or VM restart, the private VM identities and the private run', 'independent reproduction', 'authenticity of the package'],
}


def load_receipt(rep, path, label):
    try:
        return strict_loads(read_file(path, MAX_RECEIPT_BYTES, label))
    except ReceiptError as exc:
        rep.reject(exc.code, label, exc.message)
        return None


def public(result):
    return {key: (sorted(value) if isinstance(value, set) else value) for key, value in result.items() if key != '_ids'}


def control_from_service(service, key):
    if service is None:
        return {'status': 'not_supplied', 'basis': 'no local service receipt was supplied'}
    return {'status': 'established_local_provider_double' if service[key] else 'not_established', 'source_bound_to_candidate': service['bound'],
            'differing_sources': service['diffs'][:10], 'basis': 'invoice-actor-service-local/v1 (local fixture, provider double)'}


def run_check_candidate(args, p5, rep):
    body = {'candidate': None, 'extraction': None, 'frontier': {'required': list(FRONTIER_MODULES)}, 'sources': [], 'deploy_candidate': None, 'attachments': {}}
    cand = bind_candidate(rep, p5, args)
    atts = load_attachments(rep, args.attachment, cand)
    body['attachments'] = attachment_inventory(atts)
    if cand is None:
        return body, []
    body['candidate'] = candidate_summary(cand)
    ctx = Ctx(rep, 'candidate')
    try:
        verified = p5.verify_dir(args.dir, args.manifest)
        body['extraction'] = {'verified': True, 'files': verified['files'], 'files_sha256': verified['files_sha256']}
        ctx.expect(verified['files_sha256'] == cand.files_sha256, 'extraction_files_sha256_mismatch', 'dir', 'the extracted tree hashes to another files_sha256')
    except p5.CandidateError as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {}
        body['extraction'] = {'verified': False}
        ctx.bad(exc.code, 'dir', 'missing ' + str(len(detail.get('missing', []))) + ', modified ' + str(len(detail.get('modified', []))) + ', unlisted ' + str(len(detail.get('unlisted', []))))
    except OSError as exc:
        body['extraction'] = {'verified': False}
        ctx.bad('dir_unreadable', 'dir', type(exc).__name__)
    check_frontier(ctx, cand)
    body['sources'] = check_required_paths(ctx, cand, atts, list(REQUIRED_PATHS) + list(args.require_path))
    for rel in args.require_attachment:
        if rel not in atts:
            rep.missing('attachment_missing', rel, 'a required attachment was not supplied with its externally declared digest')
    body['deploy_candidate'] = check_deploy(rep, p5, cand, args)
    accredits = []
    if rep.decision == 'accepted':
        accredits = ['candidate integrity against the externally recorded manifest digest (offline, local)', 'clean extraction equals the manifest',
                     'all current boundary modules present', 'fixtures and tests reachable by manifest or explicit attachment']
    return body, accredits


def run_check_receipts(args, p5, rep):
    body = {'candidate': None, 'scenarios': {}, 'receipts': {}, 'controls': {}, 'a2_inheritance': None, 'a4_diff': None, 'attachments': {}}
    cand = bind_candidate(rep, p5, args)
    atts = load_attachments(rep, args.attachment, cand)
    body['attachments'] = attachment_inventory(atts)
    if cand is None:
        return body, []
    body['candidate'] = candidate_summary(cand)
    required = A4B_SCENARIOS if getattr(args, 'scenario_set', 'a4') == 'a4b' else SCENARIOS
    records = {}
    for index, path in enumerate(args.scenario_receipt):
        doc = load_receipt(rep, path, 'receipt[' + str(index) + ']')
        record = check_scenario(rep, doc, cand, atts, index) if doc is not None else None
        if record is None:
            continue
        if record['scenario'] not in required:
            Ctx(rep, 'scenario:' + record['scenario']).bad('scenario_outside_set', 'scenario', 'supply only the selected scenario set')
            continue
        if record['scenario'] in records:
            Ctx(rep, 'scenario:' + record['scenario']).bad('scenario_duplicate', 'scenario', 'the scenario was supplied twice')
            continue
        records[record['scenario']] = record
    for name in required:
        if name not in records:
            rep.missing('scenario_missing', name, 'no receipt was supplied for this scenario')
    cross = Ctx(rep, 'cross_receipts')
    full = [rec for rec in records.values() if '_ids' in rec]
    for field in ('image_id', 'profile_sha256', 'a2_inheritance_sha256'):
        if len({rec[field] for rec in full if rec.get(field) is not None}) > 1:
            cross.bad(field + '_crossed', field, 'the scenario receipts do not share one value')
    owners, reused = {}, set()

    def claim(owner, items):
        for item in items:
            if owners.setdefault(item, owner) != owner:
                reused.add(item)
    for rec in full:
        ids = rec['_ids']
        claim(rec['scenario'], set(ids['runs']) | set(ids['intents']) | set(ids['containers']) | set(ids['guard_containers']) | ({ids['sentinel']} if ids['sentinel'] else set()))
    references = {rec['a2_inheritance_sha256'] for rec in full if rec.get('a2_inheritance_sha256')}
    body['a2_inheritance'] = check_inheritance(rep, cand, atts, next(iter(references)) if len(references) == 1 else None,
        A4B_INHERITANCE_PATH if required == A4B_SCENARIOS else INHERITANCE_PATH)
    body['a4_diff'] = check_a4_diff(rep, cand, atts)
    if required == A4B_SCENARIOS:
        if reused:
            cross.bad('identity_reused_across_receipts', 'ids', 'identities crossed between the two cuts')
        body.update(scenarios={name: public(records[name]) for name in required if name in records},
                    scenario_set='a4b', coverage='two local service cuts only; no new positive/F-veto/private acceptance')
        return body, ['A4b local service cuts bound to the externally digested candidate; A2 guard inheritance only'] if rep.decision == 'accepted' else []
    scenario_values = {field: {rec[field] for rec in full if rec.get(field) is not None} for field in ('image_id', 'profile_sha256')}
    service = guard = offline = None
    if args.service_receipt:
        doc = load_receipt(rep, args.service_receipt, 'service_receipt')
        service = check_service_receipt(rep, doc, cand, atts) if doc is not None else None
    else:
        rep.missing('service_receipt_missing', 'service_receipt', 'the positive and F-veto controls need the local actor service receipt (invoice-actor-service-local/v1)')
    if service is not None:
        claim('service', service['containers'] | service['run_ids'])
        for field in ('image_id', 'profile_sha256'):
            if service[field] is not None and scenario_values[field] and service[field] not in scenario_values[field]:
                cross.bad(field + '_crossed', 'service_receipt', 'the service receipt and the scenario receipts disagree')
    if args.guard_receipt:
        doc = load_receipt(rep, args.guard_receipt, 'guard_receipt')
        guard = check_guard_receipt(rep, doc, cand, atts) if doc is not None else None
        if guard is not None and guard['image_id'] and scenario_values['image_id'] and guard['image_id'] not in scenario_values['image_id']:
            guard['diffs'].append('differs:image')
            guard['bound'] = False
        if guard is not None:
            claim('guard', guard['containers'])
    if args.offline_receipt:
        doc = load_receipt(rep, args.offline_receipt, 'offline_receipt')
        offline = check_offline_receipt(rep, doc, cand, atts) if doc is not None else None
    if reused:
        cross.bad('identity_reused_across_receipts', 'ids', str(len(reused)) + ' identifiers appear in more than one receipt')
    controls = {'positive': control_from_service(service, 'positive'), 'f_veto': control_from_service(service, 'f_veto')}
    for key in ('positive', 'f_veto'):
        if service is not None and service['verdict'] == 'accepted' and not service[key]:
            rep.missing('control_not_established', key, 'the supplied service receipt does not establish this control')
    controls['f_guard'] = f_guard_control(rep, guard, atts, args.scope)
    body['controls'] = controls
    body['scenarios'] = {name: public(records[name]) for name in SCENARIOS if name in records}
    body['receipts'] = {'service': public(service) if service else None, 'guard': public(guard) if guard else None, 'offline': public(offline) if offline else None}
    accredits = []
    if rep.decision == 'accepted':
        accredits = ['M1 local with provider double: the five A4 scenarios (cancel by API, owner cut at provider wait, owner cut before close, lost close response, '
                     'second-run exclusion) bound to the externally digested candidate',
                     'A2 verifier-lifecycle inheritance by hash, for the verifier guard lifecycle only',
                     'positive control (local, provider double)', 'F-veto control (local, provider double)']
        if controls['f_guard']['status'] == 'established_local':
            accredits.append('F-guard control (local, same photo as the candidate)')
    return body, accredits


def f_guard_control(rep, guard, atts, scope):
    """F-guard stays separate from the actor controls: only a guard receipt on the candidate's own photo, with the false-total artifact, establishes it.

    The M1 local criterion does not include F-guard, so a missing artifact is a pending field only for the wider scopes."""
    if guard is None:
        return {'status': 'not_supplied', 'basis': 'no direct guard receipt was supplied'}
    view = {'differing_sources': guard['diffs'][:10], 'guard_uid_recorded': guard['guard_uid'], 'basis': 'local-invoice-verifier-proof/v1 (direct guard, local Docker)'}
    if not guard['valid']:
        return {'status': 'rejected', **view}
    if not guard['bound']:
        return {'status': 'historical_other_photo', 'counts_for_current_candidate': False, **view,
                'note': 'internally consistent but its sources are not the candidate: it cannot be presented as the current candidate'}
    state = check_f_guard_artifact(rep, guard, atts)
    if state == 'established':
        return {'status': 'established_local', **view}
    if state == 'missing':
        note = ('The guard receipt records only the artifact digest. The bytes of the rejected artifact (correct digest, false total) are not emitted by the frozen '
                'producer, so the false total cannot be re-derived; attach them by digest (--attachment REL PATH SHA256) to establish the control.')
        if scope != 'local':
            rep.pend('f_guard.artifact_bytes', 'SC4 2c F-guard', note)
        return {'status': 'incomplete_artifact_bytes_missing', 'note': note, **view}
    return {'status': 'rejected', **view}


def assemble(command, scope, rep, body, accredits, tool_sources):
    local_decision = rep.decision
    apply_scope(rep, scope)
    decision = rep.decision
    result = {'schema': SCHEMA, 'tool': {'name': 'scripts/evaluation/sc4_receipts.py', 'version': TOOL_VERSION, 'sources_sha256': tool_sources},
              'command': command, 'scope_requested': scope, 'decision': decision, 'ok': decision == 'accepted',
              'local_layer': {'decision': local_decision, 'accredits': accredits if local_decision == 'accepted' else []},
              'accredits': accredits if scope == 'local' and decision == 'accepted' else [],
              'does_not_accredit': list(DOES_NOT_ACCREDIT), 'evidence_classes': EVIDENCE_CLASSES,
              'rejections': rep.rejections[:MAX_LISTED], 'incomplete': rep.incomplete[:MAX_LISTED], 'pending_fields': rep.pending,
              'counts': {'rejections': len(rep.rejections), 'incomplete': len(rep.incomplete), 'pending_fields': len(rep.pending)}}
    result.update(body)
    return result


# ---------------------------------------------------------------- CLI

class JsonParser(argparse.ArgumentParser):
    """Usage errors are decisions too: one JSON document and exit status 2."""

    def error(self, message):
        print(json.dumps({'schema': SCHEMA, 'decision': 'rejected', 'ok': False,
                          'rejections': [{'code': 'usage', 'where': 'cli', 'message': str(message)[:240]}]}, sort_keys=True))
        raise SystemExit(2)


def build_parser():
    parser = JsonParser(prog='sc4_receipts.py', description=__doc__.split('\n')[0])
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('check-candidate', 'check-receipts'):
        sub = commands.add_parser(name)
        sub.add_argument('--scope', required=True, choices=SCOPES, help='requested scope; only local can be accredited by this tool')
        sub.add_argument('--package', required=True)
        sub.add_argument('--manifest', required=True)
        sub.add_argument('--manifest-sha256', required=True, help='digest of the manifest recorded OUTSIDE the package')
        sub.add_argument('--candidate-id')
        sub.add_argument('--files-sha256')
        sub.add_argument('--attachment', nargs=3, action='append', default=[], metavar=('REL', 'PATH', 'SHA256'),
                         help='explicit file outside P5 (docs/evidencia, D1 artifact) with its externally declared digest')
        sub.add_argument('--expect-tool-sha256')
        sub.add_argument('--expect-p5-sha256')
        if name == 'check-candidate':
            sub.add_argument('--dir', required=True, help='clean extraction to compare with the manifest')
            sub.add_argument('--deploy-manifest')
            sub.add_argument('--deploy-manifest-sha256')
            sub.add_argument('--require-path', action='append', default=[], help='extra fixture/test path that must be reachable')
            sub.add_argument('--require-attachment', action='append', default=[], help='extra attachment REL that must be supplied')
        else:
            sub.add_argument('--scenario-set', choices=('a4', 'a4b'), default='a4',
                             help='a4: five original scenarios plus service controls; a4b: only the two extra service cuts')
            sub.add_argument('--scenario-receipt', action='append', default=[])
            sub.add_argument('--service-receipt')
            sub.add_argument('--guard-receipt')
            sub.add_argument('--offline-receipt')
    return parser


def file_sha(path):
    try:
        return sha256(Path(path).read_bytes())
    except OSError:
        return None


def main(argv=None):
    try:
        args = build_parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if isinstance(exc.code, int) else 2
    rep = Report()
    tool_sha, p5_sha = file_sha(__file__), file_sha(P5_PATH)
    tool_sources = {'sc4_receipts.py': tool_sha, 'p5_candidate.py': p5_sha}
    for expected, actual, option in ((args.expect_tool_sha256, tool_sha, 'expect-tool-sha256'), (args.expect_p5_sha256, p5_sha, 'expect-p5-sha256')):
        if expected is not None and expected != actual:
            rep.reject('tool_pin_mismatch', option, 'the running tool bytes differ from the digest pinned by the operator')
    body, accredits = {}, []
    if not rep.rejections:
        try:
            p5 = load_p5()
            body, accredits = (run_check_candidate if args.command == 'check-candidate' else run_check_receipts)(args, p5, rep)
        except Exception as exc:  # noqa: BLE001 - the contract is a JSON decision and exit 2, never a traceback
            rep.reject('internal_error', args.command, type(exc).__name__ + ': ' + str(exc)[:160])
    result = assemble(args.command, args.scope, rep, body, accredits, tool_sources)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result['ok'] else 2


if __name__ == '__main__':
    sys.exit(main())
