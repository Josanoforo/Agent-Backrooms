"""Tests of services/agent/invoice_actor_protocol.py (pure contract; no Docker, socket, subprocess or host path)."""
import ast
import dataclasses
import json
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.agent import invoice_actor_protocol as proto  # noqa: E402

MODULE = ROOT / 'services' / 'agent' / 'invoice_actor_protocol.py'
WORKFLOW = ROOT / 'services' / 'agent' / 'workflow.py'
RUN = '0123456789abcdef' * 2
HANDLE = 'ab' * 32
INSTALL = '1' * 32
INTENT = '2' * 32
CONTAINER = 'c' * 64

VALID = {
    'health': {'op': 'health'},
    'open': {'op': 'open', 'run_id': RUN, 'variant': 'legitimate'},
    'execute': {'op': 'execute', 'handle': HANDLE, 'command': 'cat -- /work/input.json'},
    'probe': {'op': 'probe', 'handle': HANDLE, 'name': 'task_result'},
    'close': {'op': 'close', 'handle': HANDLE},
    'receipt': {'op': 'receipt', 'installation_id': INSTALL, 'run_id': RUN, 'variant': 'legitimate', 'intent_id': INTENT,
                'container_id': CONTAINER},
}
# Written independently of the module: parity with the contract of the task, not with the implementation.
CONTRACT_FIELDS = {
    'health': {'op'},
    'open': {'op', 'run_id', 'variant'},
    'execute': {'op', 'handle', 'command'},
    'probe': {'op', 'handle', 'name'},
    'close': {'op', 'handle'},
    'receipt': {'op', 'installation_id', 'run_id', 'variant', 'intent_id', 'container_id'},
}
ORIGINAL_FIELDS = {op: fields for op, fields in CONTRACT_FIELDS.items() if op != 'receipt'}  # A3 operations: unchanged
RECEIPT_BAD = {
    'installation_id': ('invalid_installation_id', ('9' * 31, '9' * 33, 'A' * 32, 'g' * 32, '1' * 32 + '\n', '٠' * 32, '', 5,
                                                    None, [INSTALL], True, 'ab' * 32)),
    'run_id': ('invalid_run_id', (RUN.upper(), RUN[:-1], RUN + '0', 'g' * 32, RUN + '\n', '', 5, None, [RUN], 'ab' * 32)),
    'variant': ('invalid_variant', ('Legitimate', 'legit', '', None, 1, ['legitimate'], 'perturbed\n', 'actor')),
    'intent_id': ('invalid_intent_id', ('2' * 31, '2' * 33, 'F' * 32, 'g' * 32, INTENT + '\n', '', 5, None, [INTENT],
                                        'cd' * 32)),
    'container_id': ('invalid_container_id', ('c' * 63, 'c' * 65, 'C' * 64, 'g' * 64, CONTAINER + '\n', '', 5, None,
                                              [CONTAINER], RUN)),
}


CONTEXT = '7' * 64
VALID_LEVEL = {  # M2.1 operations; the M1 table VALID above is deliberately left as it was
    'open_level': {'op': 'open_level', 'run_id': RUN, 'level': 'memory', 'stage': 'actor', 'context_sha256': CONTEXT},
    'level_probe': {'op': 'level_probe', 'handle': HANDLE, 'name': 'cgroup_events'},
    'level_receipt': {'op': 'level_receipt', 'installation_id': INSTALL, 'run_id': RUN, 'level': 'memory', 'stage': 'actor',
                      'context_sha256': CONTEXT, 'intent_id': INTENT, 'container_id': CONTAINER},
}
# Written independently of the module, from M2-CONTRATO-AGENTE: parity with the contract, not with the implementation.
CONTRACT_LEVEL_FIELDS = {
    'open_level': {'op', 'run_id', 'level', 'stage', 'context_sha256'},
    'level_probe': {'op', 'handle', 'name'},
    'level_receipt': {'op', 'installation_id', 'run_id', 'level', 'stage', 'context_sha256', 'intent_id', 'container_id'},
}
# M2.3 · the probe requests by name. Written independently of the module, from M2-CONTRATO-AGENTE (table of the fixed probes).
MARKER = '/work/marker-' + 'a' * 24
DIGEST = 'b' * 64
VALID_PROBE = {
    'cgroup_events': {'op': 'level_probe', 'handle': HANDLE, 'name': 'cgroup_events'},
    'file_state': {'op': 'level_probe', 'handle': HANDLE, 'name': 'file_state', 'path': MARKER},
    'copy_scan': {'op': 'level_probe', 'handle': HANDLE, 'name': 'copy_scan', 'sha256': DIGEST, 'size': 24, 'exclude': MARKER},
}
CONTRACT_PROBE_FIELDS = {
    'cgroup_events': {'op', 'handle', 'name'},
    'file_state': {'op', 'handle', 'name', 'path'},
    'copy_scan': {'op', 'handle', 'name', 'sha256', 'size', 'exclude'},
}


def enc(obj):
    return json.dumps(obj, ensure_ascii=False, separators=(',', ':')).encode('utf-8')


def run_id(n):
    return '%032x' % n


class DecodeCase(unittest.TestCase):
    def reason(self, raw):
        with self.assertRaises(proto.ProtocolError) as caught:
            proto.decode_request(raw)
        self.assertIn(caught.exception.reason, proto.DECODE_REASONS)
        return caught.exception.reason

    def assertRejects(self, raw, reason):
        self.assertEqual(self.reason(raw), reason, raw[:80] if isinstance(raw, (bytes, bytearray)) else raw)


class ContractParityTests(DecodeCase):
    def test_field_table_matches_the_contract(self):
        self.assertEqual({op: set(fields) for op, fields in proto.OP_FIELDS.items()}, CONTRACT_FIELDS)
        self.assertEqual({op: set(body) for op, body in VALID.items()}, CONTRACT_FIELDS)

    def test_constants_match_the_contract(self):
        self.assertEqual(proto.MAX_REQUEST_BYTES, 16384)
        self.assertEqual(proto.MAX_COMMAND_BYTES, 8192)
        self.assertEqual(proto.PROBE_NAMES, ('task_result', 'artifact_capture', 'measure'))
        self.assertEqual(proto.MISSION, 'invoice-reconcile/v1')

    def test_variants_match_workflow_source(self):
        # Read as source, not imported: workflow pulls in the runner and provider, which this pure test must not load.
        tree = ast.parse(WORKFLOW.read_text(encoding='utf-8'))
        found = [ast.literal_eval(node.value) for node in tree.body
                 if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == 'VARIANTS' for t in node.targets)]
        self.assertEqual(found, [proto.VARIANTS])

    def test_valid_requests_decode_to_exactly_their_fields(self):
        for op, body in VALID.items():
            request = proto.decode_request(enc(body))
            self.assertEqual(request.op, op)
            for name in ('run_id', 'variant', 'handle', 'command', 'name', 'installation_id', 'intent_id', 'container_id'):
                self.assertEqual(getattr(request, name), body.get(name), (op, name))

    def test_every_variant_and_probe_name_is_accepted(self):
        for variant in proto.VARIANTS:
            self.assertEqual(proto.decode_request(enc({**VALID['open'], 'variant': variant})).variant, variant)
        for name in proto.PROBE_NAMES:
            self.assertEqual(proto.decode_request(enc({**VALID['probe'], 'name': name})).name, name)

    def test_bytearray_is_accepted_and_text_is_not(self):
        self.assertEqual(proto.decode_request(bytearray(enc(VALID['health']))).op, 'health')
        for bad in ('{"op":"health"}', None, 1, memoryview(b'{"op":"health"}'), [b'{}']):
            self.assertRejects(bad, 'not_bytes')

    def test_request_is_immutable_and_hides_secrets_in_repr(self):
        request = proto.decode_request(enc(VALID['execute']))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.command = 'other'
        self.assertNotIn(HANDLE, repr(request))
        self.assertNotIn('input.json', repr(request))

    def test_every_decode_reason_is_reachable(self):
        long_command = enc({**VALID['execute'], 'command': 'a' * (proto.MAX_COMMAND_BYTES + 1)})
        cases = [
            ('text', 'not_bytes'), (b'', 'empty'), (b' ' * (proto.MAX_REQUEST_BYTES + 1), 'too_large'), (b'\xff', 'not_utf8'),
            (b'{', 'invalid_json'), (b'{"op":"health","op":"health"}', 'duplicate_key'), (b'{"op":"health","x":NaN}', 'non_finite'),
            (b'[]', 'not_object'), (enc({'op': 'prepare'}), 'unknown_op'), (enc({'op': 'close'}), 'missing_field'),
            (enc({'op': 'health', 'foo': 1}), 'unexpected_field'), (enc({'op': 'health', 'image': 'x'}), 'forbidden_field'),
            (enc({**VALID['open'], 'run_id': 'x'}), 'invalid_run_id'), (enc({**VALID['open'], 'variant': 'x'}), 'invalid_variant'),
            (enc({**VALID['close'], 'handle': 'x'}), 'invalid_handle'), (enc({**VALID['probe'], 'name': 'x'}), 'invalid_name'),
            (enc({**VALID['execute'], 'command': 1}), 'invalid_command'), (enc({**VALID['execute'], 'command': ''}), 'command_empty'),
            (enc({**VALID['execute'], 'command': 'a\x00b'}), 'command_nul'), (long_command, 'command_too_large'),
            (enc({**VALID['receipt'], 'installation_id': 'x'}), 'invalid_installation_id'),
            (enc({**VALID['receipt'], 'intent_id': 'x'}), 'invalid_intent_id'),
            (enc({**VALID['receipt'], 'container_id': 'x'}), 'invalid_container_id'),
            (enc({**VALID_LEVEL['open_level'], 'level': 'x'}), 'invalid_level'),   # M2.1 reasons: the vocabulary stays closed
            (enc({**VALID_LEVEL['open_level'], 'stage': 'x'}), 'invalid_stage'),
            (enc({**VALID_LEVEL['open_level'], 'context_sha256': 'x'}), 'invalid_context'),
            (enc({**VALID_PROBE['file_state'], 'path': 'x'}), 'invalid_path'),   # M2.3 reasons: the vocabulary stays closed
            (enc({**VALID_PROBE['copy_scan'], 'sha256': 'x'}), 'invalid_digest'),
            (enc({**VALID_PROBE['copy_scan'], 'size': 0}), 'invalid_size'),
            (enc({**VALID_PROBE['copy_scan'], 'exclude': 'x'}), 'invalid_exclude'),
            # M3.1 reasons: the vocabulary stays closed (VALID_CATALOG is defined with the M3.1 tests below)
            (enc({**VALID_CATALOG['open_catalog'], 'catalog_profile': 'C'}), 'invalid_catalog_profile'),
            (enc({**VALID_CATALOG['open_catalog'], 'catalog_id': 'other/v1'}), 'invalid_catalog_id'),
            (enc({**VALID_CATALOG['open_catalog'], 'catalog_sha256': 'e' * 64}), 'invalid_catalog_digest'),
        ]
        for raw, reason in cases:
            self.assertRejects(raw, reason)
        self.assertEqual({reason for _, reason in cases}, set(proto.DECODE_REASONS))

    def test_protocol_error_is_a_closed_vocabulary(self):
        self.assertEqual(proto.REASONS, proto.DECODE_REASONS | proto.LEASE_REASONS)
        self.assertFalse(proto.DECODE_REASONS & proto.LEASE_REASONS)
        with self.assertRaises(ValueError):
            proto.ProtocolError('anything else')
        self.assertEqual(str(proto.ProtocolError('empty')), 'empty')


class LimitTests(DecodeCase):
    def test_request_size_boundary(self):
        base = enc(VALID['health'])
        exact = base + b' ' * (proto.MAX_REQUEST_BYTES - len(base))
        self.assertEqual(len(exact), 16384)
        self.assertEqual(proto.decode_request(exact).op, 'health')
        self.assertRejects(exact + b' ', 'too_large')

    def test_size_is_checked_before_decoding(self):
        self.assertRejects(b'\xff' * (proto.MAX_REQUEST_BYTES + 1), 'too_large')
        self.assertRejects(bytearray(b'{' * (proto.MAX_REQUEST_BYTES + 1)), 'too_large')

    def test_empty_versus_blank(self):
        self.assertRejects(b'', 'empty')
        self.assertRejects(b'   \n', 'invalid_json')

    def test_command_size_is_counted_in_utf8_bytes(self):
        for command in ('a' * 8192, 'é' * 4096, '€' * 2730 + 'ab'):
            self.assertEqual(len(command.encode('utf-8')), 8192)
            self.assertEqual(proto.decode_request(enc({**VALID['execute'], 'command': command})).command, command)
        for command in ('a' * 8193, 'é' * 4097, '\U0001f600' * 2049):
            self.assertRejects(enc({**VALID['execute'], 'command': command}), 'command_too_large')

    def test_escaped_command_can_exceed_the_request_limit_first(self):
        command = '\x01' * 3000  # 3000 bytes of command, 18000 bytes once JSON-escaped
        self.assertRejects(enc({**VALID['execute'], 'command': command}), 'too_large')

    def test_command_rules(self):
        self.assertRejects(enc({**VALID['execute'], 'command': ''}), 'command_empty')
        self.assertRejects(enc({**VALID['execute'], 'command': 'a\x00'}), 'command_nul')
        self.assertRejects(enc({**VALID['execute'], 'command': '\x00'}), 'command_nul')
        for bad in (123, None, ['ls'], {'a': 1}, True, 1.5):
            self.assertRejects(enc({**VALID['execute'], 'command': bad}), 'invalid_command')
        lone = b'{"op":"execute","handle":"' + HANDLE.encode() + b'","command":"\\ud800"}'
        self.assertRejects(lone, 'invalid_command')

    def test_command_is_passed_through_verbatim(self):
        command = '  echo "$(id)"; `x` | sh\n\t&& cat /etc/passwd  '
        self.assertEqual(proto.decode_request(enc({**VALID['execute'], 'command': command})).command, command)


class StrictJsonTests(DecodeCase):
    def test_invalid_utf8(self):
        for raw in (b'\xff', b'\xc0\x80', b'\xed\xa0\x80', b'{"op":"health\xe9"}', b'{"op":"health"}\xf8'):
            self.assertRejects(raw, 'not_utf8')

    def test_invalid_json(self):
        cases = [b'{', b'{"op":"health",}', b"{'op':'health'}", b'{"op":"health"} x', b'{"op":"health"}{"op":"health"}',
                 b'\xef\xbb\xbf{"op":"health"}', b'{"op":"hea\nlth"}', b'{"op":"health"', b'{op:"health"}']
        for raw in cases:
            self.assertRejects(raw, 'invalid_json')

    def test_deep_nesting_is_a_closed_rejection_not_a_crash(self):
        raw = b'[' * 8000 + b']' * 8000
        self.assertIn(self.reason(raw), {'invalid_json', 'not_object'})
        raw = b'{"op":"health","x":' + b'[' * 8000 + b']' * 8000 + b'}'
        self.assertIn(self.reason(raw), {'invalid_json', 'unexpected_field'})

    def test_duplicate_keys_at_any_depth(self):
        cases = [b'{"op":"health","op":"health"}', b'{"op":"health","\\u006fp":"close"}',
                 b'{"op":"health","x":{"a":1,"a":2}}', b'{"x":[{"a":1,"a":1}],"op":"health"}',
                 ('{"op":"close","handle":"%s","handle":"%s"}' % (HANDLE, 'cd' * 32)).encode()]
        for raw in cases:
            self.assertRejects(raw, 'duplicate_key')

    def test_non_finite_numbers(self):
        for raw in (b'{"op":"health","x":NaN}', b'{"op":"health","x":Infinity}', b'{"op":"health","x":-Infinity}',
                    b'{"op":"health","x":1e999}', b'{"op":"health","x":-1e999}', b'[NaN]'):
            self.assertRejects(raw, 'non_finite')
        self.assertRejects(b'{"op":"health","x":1.5}', 'unexpected_field')

    def test_top_level_must_be_an_object(self):
        for raw in (b'[]', b'"health"', b'1', b'null', b'true', b'[{"op":"health"}]'):
            self.assertRejects(raw, 'not_object')


class FieldTests(DecodeCase):
    def test_unknown_or_malformed_op(self):
        for op in ('prepare', 'HEALTH', 'health ', 'exec', '', None, 1, ['health'], {'a': 1}, True):
            self.assertRejects(enc({'op': op}), 'unknown_op')
        self.assertRejects(enc({'run_id': RUN, 'variant': 'legitimate'}), 'missing_field')

    def test_extra_fields_are_rejected_for_every_operation(self):
        for op, body in VALID.items():
            self.assertRejects(enc({**body, 'foo': 'x'}), 'unexpected_field')
            for other in set().union(*CONTRACT_FIELDS.values()) - CONTRACT_FIELDS[op]:
                # container_id is a real field only of receipt; everywhere else it stays a forbidden Docker-shaped name
                expected = 'forbidden_field' if other == 'container_id' else 'unexpected_field'
                self.assertRejects(enc({**body, other: 'x'}), expected)

    def test_missing_fields_are_rejected_for_every_operation(self):
        for op, body in VALID.items():
            for key in CONTRACT_FIELDS[op] - {'op'}:
                self.assertRejects(enc({k: v for k, v in body.items() if k != key}), 'missing_field')

    def test_docker_options_and_host_paths_are_forbidden_fields(self):
        keys = ['image', 'Image', 'volumes', 'Volumes', 'privileged', 'network_mode', 'network-mode', 'cap_add', 'cap_drop',
                'security_opt', 'host_path', 'hostPath', 'HostConfig', 'docker_args', 'docker', 'mount', 'mounts', 'path',
                'entrypoint', 'user', 'env', 'workdir', 'devices', 'tmpfs', 'container', 'container_id', 'socket']
        for op, body in VALID.items():
            for key in keys:
                if key in CONTRACT_FIELDS[op]:  # container_id belongs to receipt: there it is validated, not forbidden
                    continue
                self.assertRejects(enc({**body, key: 'x'}), 'forbidden_field')
        self.assertRejects(enc({**VALID['open'], 'volumes': ['/:/host'], 'foo': 1}), 'forbidden_field')

    def test_field_values_are_not_normalized(self):
        self.assertRejects(enc({**VALID['open'], 'run_id': RUN.upper()}), 'invalid_run_id')
        self.assertRejects(enc({**VALID['open'], 'variant': 'Legitimate'}), 'invalid_variant')
        self.assertRejects(enc({**VALID['open'], 'variant': 'legitimate '}), 'invalid_variant')

    def test_run_id_is_32_lowercase_hex(self):
        for bad in (RUN.upper(), RUN[:-1], RUN + '0', 'g' * 32, RUN + '\n', '٠' * 32, ' ' + RUN[:-1], '', 123, None,
                    [RUN], 'ab' * 32):
            self.assertRejects(enc({**VALID['open'], 'run_id': bad}), 'invalid_run_id')

    def test_variant_is_closed(self):
        for bad in ('legit', 'LEGITIMATE', '', None, 1, ['legitimate'], 'perturbed\n', 'document-workflow/v1'):
            self.assertRejects(enc({**VALID['open'], 'variant': bad}), 'invalid_variant')

    def test_handle_is_64_lowercase_hex_for_every_handle_operation(self):
        bad_handles = (HANDLE.upper(), HANDLE[:-1], HANDLE + '0', 'g' * 64, HANDLE + '\n', RUN, '', 123, None, [HANDLE])
        for op in ('execute', 'probe', 'close'):
            for bad in bad_handles:
                self.assertRejects(enc({**VALID[op], 'handle': bad}), 'invalid_handle')

    def test_probe_name_is_closed(self):
        for bad in ('Task_Result', 'task', '', None, 'measure ', 'probe', 'canary', 1, ['measure']):
            self.assertRejects(enc({**VALID['probe'], 'name': bad}), 'invalid_name')

    def test_run_id_and_handle_are_not_interchangeable(self):
        self.assertRejects(enc({**VALID['open'], 'run_id': HANDLE}), 'invalid_run_id')
        self.assertRejects(enc({**VALID['close'], 'handle': RUN}), 'invalid_handle')


class ReceiptRequestTests(DecodeCase):
    def test_original_operations_keep_exactly_their_fields(self):
        for op, fields in ORIGINAL_FIELDS.items():
            self.assertEqual(set(proto.OP_FIELDS[op]), fields, op)
        self.assertEqual(set(proto.OP_FIELDS), set(ORIGINAL_FIELDS) | {'receipt'})

    def test_receipt_decodes_to_exactly_the_five_identities_and_no_handle(self):
        request = proto.decode_request(enc(VALID['receipt']))
        self.assertEqual((request.op, request.installation_id, request.run_id, request.variant, request.intent_id,
                          request.container_id), ('receipt', INSTALL, RUN, 'legitimate', INTENT, CONTAINER))
        self.assertEqual((request.handle, request.command, request.name), (None, None, None))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.container_id = 'c' * 64
        for variant in proto.VARIANTS:
            self.assertEqual(proto.decode_request(enc({**VALID['receipt'], 'variant': variant})).variant, variant)

    def test_other_operations_carry_no_receipt_fields(self):
        for op, body in VALID.items():
            if op == 'receipt':
                continue
            request = proto.decode_request(enc(body))
            self.assertEqual((request.installation_id, request.intent_id, request.container_id), (None, None, None), op)

    def test_every_identity_has_the_m1_bounds_and_its_own_closed_reason(self):
        for key, (reason, bad_values) in RECEIPT_BAD.items():
            for bad in bad_values:
                self.assertRejects(enc({**VALID['receipt'], key: bad}), reason)

    def test_values_are_checked_in_a_fixed_order(self):
        everything_bad = {**VALID['receipt'], 'installation_id': 'x', 'run_id': 'x', 'variant': 'x', 'intent_id': 'x',
                          'container_id': 'x'}
        expected = ['invalid_installation_id', 'invalid_run_id', 'invalid_variant', 'invalid_intent_id', 'invalid_container_id']
        body = dict(everything_bad)
        for reason, key in zip(expected, ('installation_id', 'run_id', 'variant', 'intent_id', 'container_id')):
            self.assertRejects(enc(body), reason)
            body[key] = VALID['receipt'][key]

    def test_receipt_takes_no_handle_command_name_or_docker_shape(self):
        for extra, reason in (('handle', 'unexpected_field'), ('command', 'unexpected_field'), ('name', 'unexpected_field'),
                              ('image', 'forbidden_field'), ('volumes', 'forbidden_field'), ('container', 'forbidden_field'),
                              ('socket', 'forbidden_field'), ('foo', 'unexpected_field')):
            self.assertRejects(enc({**VALID['receipt'], extra: 'x'}), reason)
        self.assertRejects(enc({**VALID['receipt'], 'handle': HANDLE, 'command': 'id'}), 'unexpected_field')

    def test_receipt_needs_all_five_identities(self):
        for key in CONTRACT_FIELDS['receipt'] - {'op'}:
            self.assertRejects(enc({k: v for k, v in VALID['receipt'].items() if k != key}), 'missing_field')
        self.assertRejects(enc({'op': 'receipt'}), 'missing_field')

    def test_receipt_fields_are_not_accepted_by_the_original_operations(self):
        for op in ORIGINAL_FIELDS:
            for key in ('installation_id', 'intent_id'):
                self.assertRejects(enc({**VALID[op], key: INSTALL}), 'unexpected_field')
            self.assertRejects(enc({**VALID[op], 'container_id': CONTAINER}), 'forbidden_field')

    def test_receipt_values_are_not_normalized_and_duplicates_fail(self):
        self.assertRejects(enc({**VALID['receipt'], 'installation_id': 'A' * 32}), 'invalid_installation_id')
        self.assertRejects(enc({**VALID['receipt'], 'container_id': ' ' + CONTAINER[:-1]}), 'invalid_container_id')
        duplicate = ('{"op":"receipt","installation_id":"%s","installation_id":"%s","run_id":"%s","variant":"legitimate",'
                     '"intent_id":"%s","container_id":"%s"}' % (INSTALL, INSTALL, RUN, INTENT, CONTAINER)).encode()
        self.assertRejects(duplicate, 'duplicate_key')

    def test_receipt_request_fits_the_request_limit_with_room(self):
        self.assertLess(len(enc(VALID['receipt'])), 512)
        base = enc(VALID['receipt'])
        exact = base + b' ' * (proto.MAX_REQUEST_BYTES - len(base))
        self.assertEqual(proto.decode_request(exact).op, 'receipt')
        self.assertRejects(exact + b' ', 'too_large')


class PurityTests(unittest.TestCase):
    ALLOWED = {'dataclasses', 'json', 'math', 're', 'secrets', 'threading', 'time', 'types'}
    FORBIDDEN = {'subprocess', 'socket', 'os', 'shutil', 'asyncio', 'pathlib', 'ctypes', 'http', 'urllib', 'docker', 'sys'}

    def test_module_imports_only_pure_standard_library(self):
        tree = ast.parse(MODULE.read_text(encoding='utf-8'))
        names = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names |= {alias.name.split('.')[0] for alias in node.names}
            elif isinstance(node, ast.ImportFrom):
                names.add('.' if node.level else (node.module or '').split('.')[0])
        self.assertLessEqual(names, self.ALLOWED)
        self.assertFalse(names & self.FORBIDDEN)

    def test_module_does_not_execute_or_open_anything(self):
        tree = ast.parse(MODULE.read_text(encoding='utf-8'))
        called = {node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}
        self.assertFalse(called & {'eval', 'exec', 'compile', '__import__', 'open'})

    def test_module_defines_no_mutable_registry_at_import(self):
        for name, value in vars(proto).items():
            if name.startswith('__'):
                continue
            self.assertNotIsInstance(value, (list, dict, set, bytearray), name)
            self.assertNotIsInstance(value, proto.ActorLeases, name)


class Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def make(max_sessions=3, ttl=60, **options):
    clock = Clock()
    return proto.ActorLeases(max_sessions=max_sessions, ttl_seconds=ttl, clock=clock, **options), clock


class LeaseCase(unittest.TestCase):
    def reason(self, call, *args, **kwargs):
        with self.assertRaises(proto.ProtocolError) as caught:
            call(*args, **kwargs)
        self.assertIn(caught.exception.reason, proto.LEASE_REASONS | proto.DECODE_REASONS)
        return caught.exception.reason


class LeaseConfigurationTests(LeaseCase):
    def test_limits_are_required_and_explicit(self):
        with self.assertRaises(TypeError):
            proto.ActorLeases()
        with self.assertRaises(TypeError):
            proto.ActorLeases(max_sessions=1)
        with self.assertRaises(TypeError):
            proto.ActorLeases(1, 60)

    def test_invalid_configuration(self):
        for bad in (0, -1, True, 1.5, None, '2'):
            self.assertEqual(self.reason(proto.ActorLeases, max_sessions=bad, ttl_seconds=60), 'invalid_configuration')
        for bad in (0, -1, True, None, '60', float('nan'), float('inf'), -float('inf'), 10 ** 400):
            self.assertEqual(self.reason(proto.ActorLeases, max_sessions=1, ttl_seconds=bad), 'invalid_configuration')
        self.assertEqual(self.reason(proto.ActorLeases, max_sessions=1, ttl_seconds=1, clock=5), 'invalid_configuration')
        self.assertEqual(self.reason(proto.ActorLeases, max_sessions=1, ttl_seconds=1, token_source='x'), 'invalid_configuration')

    def test_registries_share_no_state(self):
        first, _ = make(max_sessions=1)
        second, _ = make(max_sessions=1)
        first.open(1000, RUN, 'legitimate')
        self.assertEqual(second.held(), 0)
        second.open(1000, RUN, 'legitimate')  # the same corrida/variant in another registry is independent
        self.assertEqual((first.held(), second.held()), (1, 1))

    def test_repr_does_not_leak_handles(self):
        leases, _ = make()
        handle = leases.open(1000, RUN, 'legitimate')
        self.assertNotIn(handle, repr(leases))
        self.assertNotIn(handle, repr(leases.authorize(handle, 1000)))


class LeaseHandleTests(LeaseCase):
    def test_handles_are_random_64_hex_and_distinct(self):
        leases, _ = make(max_sessions=40)
        handles = {leases.open(1000, run_id(n), 'legitimate') for n in range(40)}
        self.assertEqual(len(handles), 40)
        for handle in handles:
            self.assertRegex(handle, r'\A[0-9a-f]{64}\Z')

    def test_default_token_source_is_secrets(self):
        with mock.patch.object(proto.secrets, 'token_hex', return_value='c' * 64) as token:
            leases, _ = make()
            self.assertEqual(leases.open(1000, RUN, 'legitimate'), 'c' * 64)
        token.assert_called_once_with(32)

    def test_collision_is_retried_then_refused(self):
        values = iter(['a' * 64, 'a' * 64, 'b' * 64])
        leases, _ = make(token_source=lambda: next(values))
        self.assertEqual(leases.open(1000, run_id(1), 'legitimate'), 'a' * 64)
        self.assertEqual(leases.open(1000, run_id(2), 'legitimate'), 'b' * 64)  # the duplicate 'a' was skipped
        stuck, _ = make(token_source=lambda: 'a' * 64)
        stuck.open(1000, run_id(1), 'legitimate')
        self.assertEqual(self.reason(stuck.open, 1000, run_id(2), 'legitimate'), 'handle_unavailable')
        self.assertEqual(stuck.held(), 1)

    def test_malformed_token_source_output_is_refused(self):
        for bad in ('A' * 64, 'a' * 63, '', None, 5, ('a' * 64).encode()):
            leases, _ = make(token_source=lambda bad=bad: bad)
            self.assertEqual(self.reason(leases.open, 1000, RUN, 'legitimate'), 'handle_unavailable')
            self.assertEqual(leases.held(), 0)

    def test_malformed_handle_is_refused_before_lookup(self):
        leases, _ = make()
        leases.open(1000, RUN, 'legitimate')
        for bad in (HANDLE.upper(), 'ab', '', None, 5, RUN):
            self.assertEqual(self.reason(leases.authorize, bad, 1000), 'invalid_handle')
            self.assertEqual(self.reason(leases.begin_close, bad, 1000), 'invalid_handle')
            self.assertEqual(self.reason(leases.retire, bad, cleanup_confirmed=True), 'invalid_handle')

    def test_unknown_handle(self):
        leases, _ = make()
        self.assertEqual(self.reason(leases.authorize, HANDLE, 1000), 'unknown_handle')
        self.assertEqual(self.reason(leases.begin_close, HANDLE, 1000), 'unknown_handle')
        self.assertEqual(self.reason(leases.retire, HANDLE, cleanup_confirmed=True), 'unknown_handle')


class LeaseOwnerTests(LeaseCase):
    def test_owner_must_be_a_non_root_integer_uid(self):
        leases, _ = make()
        for bad in (0, -1, True, False, 1.0, '1000', None, 2 ** 32, 2 ** 32 - 1, [1000]):
            self.assertEqual(self.reason(leases.open, bad, RUN, 'legitimate'), 'invalid_owner')
        self.assertEqual(leases.held(), 0)
        handle = leases.open(1000, RUN, 'legitimate')
        for bad in (0, True, None, '1000'):
            self.assertEqual(self.reason(leases.authorize, handle, bad), 'invalid_owner')
        self.assertEqual(leases.authorize(handle, 1000).owner_uid, 1000)

    def test_uid_range_edges(self):
        leases, _ = make()
        leases.open(1, run_id(1), 'legitimate')
        leases.open(2 ** 32 - 2, run_id(2), 'legitimate')

    def test_foreign_owner_cannot_use_or_close_a_handle(self):
        leases, _ = make()
        handle = leases.open(1000, RUN, 'legitimate')
        self.assertEqual(self.reason(leases.authorize, handle, 1001), 'foreign_owner')
        self.assertEqual(self.reason(leases.begin_close, handle, 1001), 'foreign_owner')
        lease = leases.authorize(handle, 1000)  # the real owner is undisturbed and the lease is still active
        self.assertEqual((lease.state, lease.owner_uid), (proto.ACTIVE, 1000))

    def test_lease_is_bound_to_run_and_variant(self):
        leases, _ = make()
        handle = leases.open(1000, RUN, 'perturbed')
        lease = leases.authorize(handle, 1000)
        self.assertEqual((lease.run_id, lease.variant, lease.handle), (RUN, 'perturbed', handle))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            lease.run_id = run_id(9)

    def test_open_validates_run_and_variant_without_taking_a_slot(self):
        leases, _ = make()
        self.assertEqual(self.reason(leases.open, 1000, RUN.upper(), 'legitimate'), 'invalid_run_id')
        self.assertEqual(self.reason(leases.open, 1000, RUN, 'other'), 'invalid_variant')
        self.assertEqual(leases.held(), 0)


class LeaseReopenAndCapacityTests(LeaseCase):
    def test_same_identity_run_and_variant_cannot_reopen(self):
        leases, _ = make()
        first = leases.open(1000, RUN, 'legitimate')
        self.assertEqual(self.reason(leases.open, 1000, RUN, 'legitimate'), 'already_active')
        self.assertEqual(leases.authorize(first, 1000).handle, first)
        self.assertEqual(leases.held(), 1)

    def test_another_owner_cannot_take_an_active_run_and_variant(self):
        leases, _ = make()
        leases.open(1000, RUN, 'legitimate')
        self.assertEqual(self.reason(leases.open, 1001, RUN, 'legitimate'), 'already_active')

    def test_other_variant_or_run_is_independent(self):
        leases, _ = make()
        leases.open(1000, RUN, 'legitimate')
        leases.open(1000, RUN, 'perturbed')
        leases.open(1000, run_id(2), 'legitimate')
        self.assertEqual(leases.held(), 3)

    def test_capacity_is_fixed_and_released_only_by_retire(self):
        leases, _ = make(max_sessions=2)
        first = leases.open(1000, run_id(1), 'legitimate')
        leases.open(1000, run_id(2), 'legitimate')
        self.assertEqual(self.reason(leases.open, 1000, run_id(3), 'legitimate'), 'capacity_exhausted')
        self.assertEqual(leases.max_sessions, 2)
        leases.begin_close(first, 1000)
        self.assertEqual(self.reason(leases.open, 1000, run_id(3), 'legitimate'), 'capacity_exhausted')
        leases.retire(first, cleanup_confirmed=True)
        leases.open(1000, run_id(3), 'legitimate')
        self.assertEqual(leases.held(), 2)

    def test_concurrent_opens_never_exceed_capacity(self):
        leases = proto.ActorLeases(max_sessions=10, ttl_seconds=60)
        barrier, handles, reasons = threading.Barrier(40), [], []

        def work(n):
            barrier.wait()
            try:
                handles.append(leases.open(1000, run_id(n), 'legitimate'))
            except proto.ProtocolError as exc:
                reasons.append(exc.reason)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(40)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertEqual((len(handles), len(set(handles)), leases.held()), (10, 10, 10))
        self.assertEqual(reasons, ['capacity_exhausted'] * 30)


class LeaseLifecycleTests(LeaseCase):
    def test_expired_handle_is_refused_and_the_deadline_is_absolute(self):
        leases, clock = make(ttl=60)
        handle = leases.open(1000, RUN, 'legitimate')
        clock.now += 59
        leases.authorize(handle, 1000)  # using it does not extend it
        clock.now += 1  # exactly the deadline
        self.assertEqual(self.reason(leases.authorize, handle, 1000), 'expired')

    def test_expired_lease_keeps_its_slot_until_cleanup_is_confirmed(self):
        leases, clock = make(max_sessions=1, ttl=60)
        handle = leases.open(1000, RUN, 'legitimate')
        clock.now += 61
        self.assertEqual(self.reason(leases.open, 1000, RUN, 'legitimate'), 'already_active')
        self.assertEqual(self.reason(leases.open, 1000, run_id(2), 'legitimate'), 'capacity_exhausted')
        self.assertEqual([item.handle for item in leases.pending_cleanup()], [handle])
        leases.begin_close(handle, 1000)  # closing an expired lease is allowed
        leases.retire(handle, cleanup_confirmed=True)
        reopened = leases.open(1000, RUN, 'legitimate')
        self.assertNotEqual(reopened, handle)

    def test_close_blocks_use_but_keeps_the_slot(self):
        leases, _ = make()
        handle = leases.open(1000, RUN, 'legitimate')
        self.assertEqual(leases.begin_close(handle, 1000).state, proto.CLOSING)
        self.assertEqual(leases.begin_close(handle, 1000).state, proto.CLOSING)  # idempotent
        self.assertEqual(self.reason(leases.authorize, handle, 1000), 'closing')
        self.assertEqual(self.reason(leases.open, 1000, RUN, 'legitimate'), 'already_active')
        self.assertEqual(leases.held(), 1)

    def test_retire_needs_confirmed_cleanup_exactly_true(self):
        leases, _ = make()
        handle = leases.open(1000, RUN, 'legitimate')
        leases.begin_close(handle, 1000)
        for bad in (False, None, 1, 'true', 'yes', [True]):
            self.assertEqual(self.reason(leases.retire, handle, cleanup_confirmed=bad), 'cleanup_not_confirmed')
        self.assertEqual(leases.held(), 1)
        with self.assertRaises(TypeError):
            leases.retire(handle)
        leases.retire(handle, cleanup_confirmed=True)
        self.assertEqual(leases.held(), 0)

    def test_retire_without_close_is_possible_for_the_owner(self):
        leases, _ = make()
        handle = leases.open(1000, RUN, 'legitimate')
        leases.retire(handle, cleanup_confirmed=True)  # e.g. owner recovered a failed session
        self.assertEqual(leases.held(), 0)

    def test_retired_handle_is_dead_and_not_reissued_for_the_same_run(self):
        leases, _ = make()
        handle = leases.open(1000, RUN, 'legitimate')
        leases.begin_close(handle, 1000)
        leases.retire(handle, cleanup_confirmed=True)
        for call in (leases.authorize, leases.begin_close):
            self.assertEqual(self.reason(call, handle, 1000), 'unknown_handle')
        self.assertEqual(self.reason(leases.retire, handle, cleanup_confirmed=True), 'unknown_handle')
        self.assertNotEqual(leases.open(1000, RUN, 'legitimate'), handle)
        self.assertEqual(self.reason(leases.authorize, handle, 1000), 'unknown_handle')

    def test_handle_of_another_session_is_never_valid_after_reuse_of_the_slot(self):
        leases, _ = make(max_sessions=1)
        old = leases.open(1000, run_id(1), 'legitimate')
        leases.retire(old, cleanup_confirmed=True)
        new = leases.open(1001, run_id(2), 'legitimate')
        self.assertEqual(self.reason(leases.authorize, old, 1000), 'unknown_handle')
        self.assertEqual(self.reason(leases.authorize, old, 1001), 'unknown_handle')
        self.assertEqual(self.reason(leases.authorize, new, 1000), 'foreign_owner')

    def test_pending_cleanup_lists_only_closing_and_expired(self):
        leases, clock = make(ttl=60)
        live = leases.open(1000, run_id(1), 'legitimate')
        closing = leases.open(1000, run_id(2), 'legitimate')
        leases.begin_close(closing, 1000)
        self.assertEqual([item.handle for item in leases.pending_cleanup()], [closing])
        clock.now += 60
        self.assertEqual({item.handle for item in leases.pending_cleanup()}, {live, closing})

    def test_every_lease_reason_is_reachable(self):
        seen = set()

        def hit(call, *args, **kwargs):
            seen.add(self.reason(call, *args, **kwargs))

        hit(proto.ActorLeases, max_sessions=0, ttl_seconds=1)
        leases, clock = make(max_sessions=1)
        hit(leases.open, 0, RUN, 'legitimate')
        handle = leases.open(1000, RUN, 'legitimate')
        hit(leases.open, 1000, RUN, 'legitimate')
        hit(leases.open, 1000, run_id(2), 'legitimate')
        hit(leases.authorize, handle, 1001)
        hit(leases.authorize, 'cd' * 32, 1000)
        clock.now += 60
        hit(leases.authorize, handle, 1000)
        leases.begin_close(handle, 1000)
        hit(leases.authorize, handle, 1000)
        hit(leases.retire, handle, cleanup_confirmed=False)
        stuck, _ = make(token_source=lambda: 'x')
        hit(stuck.open, 1000, RUN, 'legitimate')
        # M4 (invalidated by contract): the two reasons of the room action permit are part of the closed lease vocabulary
        rooms, _ = make(max_sessions=2)
        room = rooms.open_level(1000, RUN, 'processes', 'actor', CONTEXT)
        rooms.consume_action(room, 1000)
        hit(rooms.consume_action, room, 1000)
        hit(rooms.consume_action, rooms.open_level(1000, run_id(2), 'memory', 'actor', CONTEXT), 1000)
        self.assertEqual(seen, set(proto.LEASE_REASONS))


# ------------------------------------------------------------------------------------------------------- M2.1 · levels

BAD_LEVELS = ('Persistence', 'Memory', 'MEMORY', '', 'memory ', 'memory\n', None, 1, ['memory'], {'a': 1}, 'legitimate',
              'perturbed', 'Network', 'fresh', True)  # M5: `network` is now a valid level name (only the capitalized form is not)
BAD_STAGES = ('fresh', 'Actor', 'ACTOR', '', 'actor ', 'actor\n', None, 1, ['actor'], 'memory', True)
BAD_CONTEXTS = ('A' * 64, 'a' * 63, 'a' * 65, 'g' * 64, CONTEXT + '\n', ' ' + CONTEXT[:-1], '٠' * 64, '', None, 5, [CONTEXT],
                INTENT, RUN, True)


class LevelContractTests(DecodeCase):
    def test_level_field_table_matches_the_contract_and_the_m1_table_is_untouched(self):
        self.assertEqual({op: set(fields) for op, fields in proto.LEVEL_OP_FIELDS.items()}, CONTRACT_LEVEL_FIELDS)
        self.assertEqual({op: set(body) for op, body in VALID_LEVEL.items()}, CONTRACT_LEVEL_FIELDS)
        self.assertEqual({op: set(fields) for op, fields in proto.OP_FIELDS.items()}, CONTRACT_FIELDS)  # M1: exactly as before
        self.assertFalse(set(proto.OP_FIELDS) & set(proto.LEVEL_OP_FIELDS))

    def test_vocabularies_are_closed_and_level_is_not_a_variant(self):
        # M2.3 extends the closed vocabularies (invalidated by contract: the M2.1 assertions listed only memory/secret, actor and one probe)
        # M4 (invalidated by contract): processes and privileges extend the closed level names, stage actor only
        # M5 (invalidated by contract): `network` extends the closed level names, stage actor only
        self.assertEqual(proto.LEVELS, ('memory', 'secret', 'persistence', 'processes', 'privileges', 'network'))
        self.assertEqual(proto.STAGES, ('actor', 'fresh'))
        self.assertEqual(proto.LEVEL_PROBE_NAMES, ('cgroup_events', 'file_state', 'copy_scan'))
        self.assertEqual(proto.VARIANTS, ('legitimate', 'perturbed'))
        self.assertFalse(set(proto.LEVELS) & set(proto.VARIANTS))
        self.assertTrue({'invalid_level', 'invalid_stage', 'invalid_context'} <= proto.DECODE_REASONS)
        self.assertEqual(proto.PROBE_NAMES, ('task_result', 'artifact_capture', 'measure'))  # the M1 probes did not grow

    def test_valid_level_requests_decode_to_exactly_their_fields(self):
        for op, body in VALID_LEVEL.items():
            request = proto.decode_request(enc(body))
            self.assertEqual(request.op, op)
            for name in ('run_id', 'handle', 'name', 'installation_id', 'intent_id', 'container_id', 'level', 'stage',
                         'context_sha256'):
                self.assertEqual(getattr(request, name), body.get(name), (op, name))
            self.assertEqual((request.variant, request.command), (None, None))

    def test_codec_recognizes_memory_and_secret_with_stage_actor_and_nothing_else(self):
        for level in ('memory', 'secret'):
            for op in ('open_level', 'level_receipt'):
                self.assertEqual(proto.decode_request(enc({**VALID_LEVEL[op], 'level': level})).level, level)
        self.assertEqual(proto.decode_request(enc(VALID_LEVEL['open_level'])).stage, 'actor')

    def test_m1_requests_carry_no_level_fields(self):
        for op, body in VALID.items():
            request = proto.decode_request(enc(body))
            self.assertEqual((request.level, request.stage, request.context_sha256), (None, None, None), op)

    def test_request_is_immutable_and_hides_the_handle(self):
        request = proto.decode_request(enc(VALID_LEVEL['level_probe']))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.name = 'other'
        self.assertNotIn(HANDLE, repr(request))
        opened = proto.decode_request(enc(VALID_LEVEL['open_level']))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            opened.level = 'secret'

    def test_extra_fields_are_rejected_for_every_level_operation(self):
        everything = set().union(*CONTRACT_LEVEL_FIELDS.values(), *CONTRACT_FIELDS.values())
        for op, body in VALID_LEVEL.items():
            self.assertRejects(enc({**body, 'foo': 'x'}), 'unexpected_field')
            for other in everything - CONTRACT_LEVEL_FIELDS[op]:
                # container_id is a real field only of the receipts; everywhere else it stays a forbidden Docker-shaped name
                expected = 'forbidden_field' if other == 'container_id' else 'unexpected_field'
                self.assertRejects(enc({**body, other: 'x'}), expected)

    def test_a_level_is_never_read_as_a_variant_nor_a_variant_as_a_level(self):
        self.assertRejects(enc({**VALID_LEVEL['open_level'], 'variant': 'legitimate'}), 'unexpected_field')
        self.assertRejects(enc({**VALID_LEVEL['level_receipt'], 'variant': 'legitimate'}), 'unexpected_field')
        self.assertRejects(enc({**VALID_LEVEL['open_level'], 'level': 'legitimate'}), 'invalid_level')
        self.assertRejects(enc({**VALID_LEVEL['open_level'], 'level': 'perturbed'}), 'invalid_level')
        self.assertRejects(enc({**VALID['open'], 'variant': 'memory'}), 'invalid_variant')
        self.assertRejects(enc({**VALID['open'], 'level': 'memory'}), 'unexpected_field')
        self.assertRejects(enc({**VALID['open'], 'stage': 'actor'}), 'unexpected_field')
        self.assertRejects(enc({**VALID['receipt'], 'context_sha256': CONTEXT}), 'unexpected_field')
        self.assertRejects(enc({**VALID['close'], 'level': 'memory'}), 'unexpected_field')
        # the surplus field is judged before the missing ones, so a variant-shaped open never reads as a level open
        self.assertRejects(enc({'op': 'open_level', 'run_id': RUN, 'variant': 'legitimate'}), 'unexpected_field')

    def test_docker_options_host_paths_and_scripts_are_rejected_for_every_level_operation(self):
        forbidden = ('image', 'Image', 'volumes', 'privileged', 'network_mode', 'cap_add', 'security_opt', 'host_path', 'hostPath',
                     'path', 'mounts', 'entrypoint', 'user', 'env', 'workdir', 'devices', 'tmpfs', 'socket', 'args', 'options',
                     'docker', 'container', 'memory')
        for op, body in VALID_LEVEL.items():
            for key in forbidden:
                if key in CONTRACT_LEVEL_FIELDS[op]:
                    continue
                self.assertRejects(enc({**body, key: 'x'}), 'forbidden_field')
            for key in ('script', 'argv', 'cmd', 'command', 'sh', 'sha256', 'size', 'exclude', 'allowed_levels', 'levels'):
                self.assertIn(self.reason(enc({**body, key: 'x'})), {'unexpected_field', 'forbidden_field'}, (op, key))
        # M2.3 (invalidated by contract: these shapes were "not part of this lot"): the persistence probes now exist, with exactly their
        # typed arguments; a path is still forbidden on cgroup_events and a script is still nobody's field
        self.assertEqual(proto.decode_request(enc(VALID_PROBE['file_state'])).path, MARKER)
        self.assertRejects(enc({'op': 'level_probe', 'handle': HANDLE, 'name': 'file_state'}), 'missing_field')
        self.assertEqual(proto.decode_request(enc({'op': 'level_probe', 'handle': HANDLE, 'name': 'copy_scan', 'sha256': 'a' * 64,
                                                   'size': 5, 'exclude': None})).exclude, None)
        self.assertRejects(enc({**VALID_LEVEL['level_probe'], 'path': MARKER}), 'forbidden_field')

    def test_missing_fields_are_rejected_for_every_level_operation(self):
        for op, body in VALID_LEVEL.items():
            for key in CONTRACT_LEVEL_FIELDS[op] - {'op'}:
                self.assertRejects(enc({k: v for k, v in body.items() if k != key}), 'missing_field')
        self.assertRejects(enc({'op': 'open_level'}), 'missing_field')
        self.assertRejects(enc({'op': 'level_receipt'}), 'missing_field')

    def test_level_values_are_closed_and_not_normalized(self):
        for op in ('open_level', 'level_receipt'):
            for bad in BAD_LEVELS:
                self.assertRejects(enc({**VALID_LEVEL[op], 'level': bad}), 'invalid_level')
            for bad in BAD_STAGES:
                self.assertRejects(enc({**VALID_LEVEL[op], 'stage': bad}), 'invalid_stage')
            for bad in BAD_CONTEXTS:
                self.assertRejects(enc({**VALID_LEVEL[op], 'context_sha256': bad}), 'invalid_context')
            for bad in (RUN.upper(), RUN[:-1], RUN + '0', 'g' * 32, RUN + '\n', '', 5, None, [RUN], HANDLE):
                self.assertRejects(enc({**VALID_LEVEL[op], 'run_id': bad}), 'invalid_run_id')

    def test_level_receipt_identities_have_the_m1_bounds_and_their_own_reasons(self):
        for key, (reason, bad_values) in RECEIPT_BAD.items():
            if key == 'variant':
                continue
            for bad in bad_values:
                self.assertRejects(enc({**VALID_LEVEL['level_receipt'], key: bad}), reason)

    def test_values_are_checked_in_a_fixed_order(self):
        for op, order in (('open_level', ('run_id', 'level', 'stage', 'context_sha256')),
                          ('level_receipt', ('installation_id', 'run_id', 'level', 'stage', 'context_sha256', 'intent_id',
                                             'container_id'))):
            reasons = {'installation_id': 'invalid_installation_id', 'run_id': 'invalid_run_id', 'level': 'invalid_level',
                       'stage': 'invalid_stage', 'context_sha256': 'invalid_context', 'intent_id': 'invalid_intent_id',
                       'container_id': 'invalid_container_id'}
            body = {**VALID_LEVEL[op], **{key: 'x' for key in order}}
            for key in order:
                self.assertRejects(enc(body), reasons[key])
                body[key] = VALID_LEVEL[op][key]

    def test_level_probe_name_is_exactly_cgroup_events_and_the_handle_is_checked(self):
        self.assertEqual(proto.decode_request(enc(VALID_LEVEL['level_probe'])).name, 'cgroup_events')
        for bad in ('measure', 'task_result', 'artifact_capture', 'net_counters', 'Cgroup_events', 'File_state', 'copy_scan ',
                    'cgroup_events ', 'cgroup_events\n', '', None, 1, ['cgroup_events'], ['file_state']):  # M2.3: the two probe names are valid
            self.assertRejects(enc({**VALID_LEVEL['level_probe'], 'name': bad}), 'invalid_name')
        for bad in (HANDLE.upper(), HANDLE[:-1], HANDLE + '0', 'g' * 64, HANDLE + '\n', RUN, '', 123, None, [HANDLE]):
            self.assertRejects(enc({**VALID_LEVEL['level_probe'], 'handle': bad}), 'invalid_handle')

    def test_m1_probe_does_not_gain_the_level_probe_name(self):
        self.assertRejects(enc({**VALID['probe'], 'name': 'cgroup_events'}), 'invalid_name')
        self.assertRejects(enc({**VALID['probe'], 'name': 'oom_kill'}), 'invalid_name')
        for name in ('file_state', 'copy_scan'):  # M1 gains no persistence probe
            self.assertRejects(enc({**VALID['probe'], 'name': name}), 'invalid_name')

    def test_duplicates_and_size_are_checked_for_level_operations(self):
        duplicate = ('{"op":"open_level","run_id":"%s","level":"memory","level":"secret","stage":"actor","context_sha256":"%s"}'
                     % (RUN, CONTEXT)).encode()
        self.assertRejects(duplicate, 'duplicate_key')
        self.assertRejects(b' ' * (proto.MAX_REQUEST_BYTES + 1), 'too_large')
        for op, body in VALID_LEVEL.items():
            base = enc(body)
            self.assertLess(len(base), 512, op)
            exact = base + b' ' * (proto.MAX_REQUEST_BYTES - len(base))
            self.assertEqual(proto.decode_request(exact).op, op)
            self.assertRejects(exact + b' ', 'too_large')

    def test_operations_beyond_the_lot_remain_unknown(self):
        for op in ('open_session', 'copy_scan', 'file_state', 'net_counters', 'level_open', 'open_fresh', 'level_close'):
            self.assertRejects(enc({'op': op}), 'unknown_op')


class LevelLeaseTests(LeaseCase):
    def test_open_level_binds_level_stage_and_context_and_has_no_variant(self):
        leases, _ = make()
        handle = leases.open_level(1000, RUN, 'memory', 'actor', CONTEXT)
        lease = leases.authorize(handle, 1000)
        self.assertEqual((lease.run_id, lease.level, lease.stage, lease.context_sha256, lease.variant, lease.handle),
                         (RUN, 'memory', 'actor', CONTEXT, None, handle))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            lease.level = 'secret'
        self.assertNotIn(handle, repr(lease))
        self.assertNotIn(handle, repr(leases))

    def test_a_workflow_lease_has_no_level(self):
        leases, _ = make()
        lease = leases.authorize(leases.open(1000, RUN, 'legitimate'), 1000)
        self.assertEqual((lease.variant, lease.level, lease.stage, lease.context_sha256), ('legitimate', None, None, None))

    def test_handles_are_random_64_hex(self):
        leases, _ = make(max_sessions=3)
        handles = {leases.open_level(1000, run_id(n), 'memory', 'actor', CONTEXT) for n in range(3)}
        self.assertEqual(len(handles), 3)
        for handle in handles:
            self.assertRegex(handle, r'\A[0-9a-f]{64}\Z')

    def test_arguments_are_validated_without_taking_a_slot(self):
        leases, _ = make()
        cases = [(('owner', 0), 'invalid_owner'), (('owner', True), 'invalid_owner'), (('run', RUN.upper()), 'invalid_run_id'),
                 (('run', HANDLE), 'invalid_run_id')]
        cases += [(('level', bad), 'invalid_level') for bad in BAD_LEVELS]
        cases += [(('stage', bad), 'invalid_stage') for bad in BAD_STAGES]
        cases += [(('context', bad), 'invalid_context') for bad in BAD_CONTEXTS]
        for (name, bad), reason in cases:
            args = {'owner': 1000, 'run': RUN, 'level': 'memory', 'stage': 'actor', 'context': CONTEXT}
            args[name] = bad
            self.assertEqual(self.reason(leases.open_level, args['owner'], args['run'], args['level'], args['stage'],
                                         args['context']), reason, (name, bad))
        self.assertEqual(leases.held(), 0)

    def test_replay_of_run_level_and_stage_is_refused_for_any_owner_and_any_context(self):
        leases, _ = make()
        first = leases.open_level(1000, RUN, 'memory', 'actor', CONTEXT)
        self.assertEqual(self.reason(leases.open_level, 1000, RUN, 'memory', 'actor', CONTEXT), 'already_active')
        self.assertEqual(self.reason(leases.open_level, 1001, RUN, 'memory', 'actor', CONTEXT), 'already_active')
        self.assertEqual(self.reason(leases.open_level, 1000, RUN, 'memory', 'actor', '8' * 64), 'already_active')
        self.assertEqual(leases.authorize(first, 1000).handle, first)
        self.assertEqual(leases.held(), 1)

    def test_other_level_or_run_is_independent_and_a_level_never_collides_with_a_variant(self):
        leases, _ = make(max_sessions=4)
        leases.open_level(1000, RUN, 'memory', 'actor', CONTEXT)
        leases.open_level(1000, RUN, 'secret', 'actor', CONTEXT)
        leases.open_level(1000, run_id(2), 'memory', 'actor', CONTEXT)
        leases.open(1000, RUN, 'legitimate')  # the same run id, another domain
        self.assertEqual(leases.held(), 4)

    def test_there_is_one_plaza_shared_by_workflow_and_level(self):
        leases, _ = make(max_sessions=1)
        variant = leases.open(1000, RUN, 'legitimate')
        self.assertEqual(self.reason(leases.open_level, 1000, run_id(2), 'memory', 'actor', CONTEXT), 'capacity_exhausted')
        leases.retire(variant, cleanup_confirmed=True)
        level = leases.open_level(1000, run_id(2), 'memory', 'actor', CONTEXT)
        self.assertEqual(self.reason(leases.open, 1000, RUN, 'legitimate'), 'capacity_exhausted')
        self.assertEqual(self.reason(leases.open_level, 1000, run_id(3), 'memory', 'actor', CONTEXT), 'capacity_exhausted')
        leases.retire(level, cleanup_confirmed=True)
        leases.open(1000, RUN, 'legitimate')

    def test_foreign_owner_cannot_use_or_close_a_level_handle(self):
        leases, _ = make()
        handle = leases.open_level(1000, RUN, 'memory', 'actor', CONTEXT)
        self.assertEqual(self.reason(leases.authorize, handle, 1001), 'foreign_owner')
        self.assertEqual(self.reason(leases.begin_close, handle, 1001), 'foreign_owner')
        self.assertEqual(leases.authorize(handle, 1000).state, proto.ACTIVE)

    def test_expiry_close_and_retire_follow_the_m1_rules_and_keep_the_level_binding(self):
        leases, clock = make(max_sessions=1, ttl=60)
        handle = leases.open_level(1000, RUN, 'memory', 'actor', CONTEXT)
        clock.now += 59
        leases.authorize(handle, 1000)  # using it does not extend it
        clock.now += 1
        self.assertEqual(self.reason(leases.authorize, handle, 1000), 'expired')
        self.assertEqual(self.reason(leases.open_level, 1000, RUN, 'memory', 'actor', CONTEXT), 'already_active')
        self.assertEqual(self.reason(leases.open_level, 1000, run_id(2), 'memory', 'actor', CONTEXT), 'capacity_exhausted')
        closing = leases.begin_close(handle, 1000)
        self.assertEqual((closing.state, closing.level, closing.stage, closing.context_sha256, closing.variant),
                         (proto.CLOSING, 'memory', 'actor', CONTEXT, None))
        self.assertEqual([item.handle for item in leases.pending_cleanup()], [handle])
        self.assertEqual(self.reason(leases.retire, handle, cleanup_confirmed=False), 'cleanup_not_confirmed')
        self.assertEqual(leases.held(), 1)
        leases.retire(handle, cleanup_confirmed=True)
        self.assertNotEqual(leases.open_level(1000, RUN, 'memory', 'actor', CONTEXT), handle)


# ------------------------------------------------------------------------------------------------------- M2.3 · persistence
# Authored without a shell: none of these tests has been executed by the author.

BAD_MARKER_PATHS = (
    '/work/marker-' + 'a' * 23, '/work/marker-' + 'a' * 25, '/work/marker-' + 'A' * 24, '/work/marker-' + 'g' * 24,
    '/tmp/marker-' + 'a' * 24, '/work/marker-' + 'a' * 24 + '/x', '/work/marker-' + 'a' * 24 + '\n', ' ' + MARKER,
    '/work/../work/marker-' + 'a' * 24, '/work//marker-' + 'a' * 24, 'work/marker-' + 'a' * 24,
    '/work/marker-' + 'a' * 24 + '\x00', '/work/marker-٠' + 'a' * 23, '/work/marker-', '/', '', 5, None, True, [MARKER],
    {'path': MARKER}, DIGEST, RUN)
BAD_DIGESTS = (DIGEST.upper().replace('B', 'C'), 'b' * 63, 'b' * 65, 'g' * 64, DIGEST + '\n', ' ' + DIGEST[:-1], '٠' * 64, '', None, 5,
               [DIGEST], True, MARKER, RUN)
BAD_SIZES = (0, -1, proto.MAX_COPY_SIZE + 1, 2 ** 64, True, False, 1.0, 24.5, '24', None, [24], {'n': 24}, '')


class PersistenceVocabularyTests(DecodeCase):
    def test_pairs_are_closed(self):
        # (M4/M5, invalidated by contract: the rooms and `network` are actor-only levels; the assertion listed the M2.3 three only)
        self.assertEqual({level: tuple(stages) for level, stages in proto.LEVEL_STAGES.items()},
                         {'memory': ('actor',), 'secret': ('actor',), 'persistence': ('actor', 'fresh'), 'processes': ('actor',),
                          'privileges': ('actor',), 'network': ('actor',)})
        valid = {('memory', 'actor'), ('secret', 'actor'), ('persistence', 'actor'), ('persistence', 'fresh'),
                 ('processes', 'actor'), ('privileges', 'actor'), ('network', 'actor')}
        for level in proto.LEVELS:
            for stage in proto.STAGES:
                self.assertEqual(proto.level_stage_valid(level, stage), (level, stage) in valid, (level, stage))
        for level, stage in ((None, 'actor'), ('memory', None), (['memory'], 'actor'), ('memory', ['actor']), ('persistence', 'x'),
                             ('x', 'actor'), (1, 2), ('persistence', True)):
            self.assertFalse(proto.level_stage_valid(level, stage), (level, stage))

    def test_open_and_receipt_decode_for_both_persistence_phases_without_a_variant(self):
        for op in ('open_level', 'level_receipt'):
            for stage in ('actor', 'fresh'):
                request = proto.decode_request(enc({**VALID_LEVEL[op], 'level': 'persistence', 'stage': stage}))
                self.assertEqual((request.op, request.level, request.stage, request.variant), (op, 'persistence', stage, None))
                self.assertEqual(request.context_sha256, CONTEXT)

    def test_fresh_exists_for_persistence_alone_and_the_level_is_judged_first(self):
        for op in ('open_level', 'level_receipt'):
            for level in ('memory', 'secret'):
                self.assertRejects(enc({**VALID_LEVEL[op], 'level': level, 'stage': 'fresh'}), 'invalid_stage')
            for bad in ('x', 'Fresh', 'FRESH', 'fresh ', 'fresh\n', '', None, 1, ['fresh'], 'legitimate'):
                self.assertRejects(enc({**VALID_LEVEL[op], 'level': 'persistence', 'stage': bad}), 'invalid_stage')
            self.assertRejects(enc({**VALID_LEVEL[op], 'level': 'x', 'stage': 'x'}), 'invalid_level')
            self.assertRejects(enc({**VALID_LEVEL[op], 'level': 'Persistence', 'stage': 'fresh'}), 'invalid_level')

    def test_a_request_never_carries_a_predecessor_or_any_authority_for_one(self):
        bodies = [{**VALID_LEVEL[op], 'level': 'persistence', 'stage': stage} for op in ('open_level', 'level_receipt')
                  for stage in ('actor', 'fresh')] + list(VALID_PROBE.values())
        for body in bodies:
            for key in ('predecessor', 'predecessor_intent_id', 'predecessor_container_id', 'previous', 'actor_intent_id', 'pin'):
                for value in ('x', None, {'run_id': RUN}):
                    self.assertIn(self.reason(enc({**body, key: value})), {'unexpected_field', 'forbidden_field'}, (body['op'], key))

    def test_the_m1_operations_gain_nothing(self):
        self.assertEqual({op: set(fields) for op, fields in proto.OP_FIELDS.items()}, CONTRACT_FIELDS)
        self.assertEqual(proto.PROBE_NAMES, ('task_result', 'artifact_capture', 'measure'))
        self.assertEqual({op: set(fields) for op, fields in proto.LEVEL_OP_FIELDS.items()}, CONTRACT_LEVEL_FIELDS)
        for op, body in VALID.items():
            request = proto.decode_request(enc(body))
            self.assertEqual((request.path, request.sha256, request.size, request.exclude), (None, None, None, None), op)


class PersistenceProbeRequestTests(DecodeCase):
    def test_the_field_table_by_name_matches_the_contract(self):
        self.assertEqual({name: set(fields) for name, fields in proto.LEVEL_PROBE_FIELDS.items()}, CONTRACT_PROBE_FIELDS)
        self.assertEqual({name: set(body) for name, body in VALID_PROBE.items()}, CONTRACT_PROBE_FIELDS)
        self.assertEqual(set(proto.LEVEL_PROBE_FIELDS), set(proto.LEVEL_PROBE_NAMES))
        self.assertEqual(proto.MAX_COPY_SIZE, 1048576)

    def test_valid_probe_requests_decode_to_exactly_their_arguments(self):
        for name, body in VALID_PROBE.items():
            request = proto.decode_request(enc(body))
            self.assertEqual((request.op, request.handle, request.name), ('level_probe', HANDLE, name))
            for field in ('path', 'sha256', 'size', 'exclude'):
                self.assertEqual(getattr(request, field), body.get(field), (name, field))
            self.assertEqual((request.command, request.variant, request.level, request.stage), (None, None, None, None))
            self.assertLess(len(enc(body)), 512)

    def test_exclude_may_be_null_or_a_marker_path_and_the_size_edges_are_accepted(self):
        for exclude in (None, MARKER, '/work/marker-' + 'f' * 24, '/work/marker-' + '0123456789abcdef01234567'):
            request = proto.decode_request(enc({**VALID_PROBE['copy_scan'], 'exclude': exclude}))
            self.assertEqual(request.exclude, exclude)
        for size in (1, 2, 24, proto.MAX_COPY_SIZE):
            self.assertEqual(proto.decode_request(enc({**VALID_PROBE['copy_scan'], 'size': size})).size, size)

    def test_extra_and_missing_fields_per_name(self):
        everything = set().union(*CONTRACT_PROBE_FIELDS.values(), *CONTRACT_LEVEL_FIELDS.values(), *CONTRACT_FIELDS.values())
        for name, body in VALID_PROBE.items():
            self.assertRejects(enc({**body, 'foo': 'x'}), 'unexpected_field')
            for other in everything - CONTRACT_PROBE_FIELDS[name]:
                expected = 'forbidden_field' if other in ('container_id', 'path') else 'unexpected_field'
                self.assertRejects(enc({**body, other: 'x'}), expected)  # a path is a field of file_state alone
            for key in CONTRACT_PROBE_FIELDS[name] - {'op', 'name'}:
                self.assertRejects(enc({k: v for k, v in body.items() if k != key}), 'missing_field')
            # without `name` the shape is judged as the base one: the arguments of the probe are then surplus, never a valid request
            self.assertIn(self.reason(enc({k: v for k, v in body.items() if k != 'name'})),
                          {'missing_field', 'unexpected_field', 'forbidden_field'})

    def test_docker_options_scripts_and_other_paths_are_never_fields_of_a_probe(self):
        for name, body in VALID_PROBE.items():
            for key in ('image', 'volumes', 'privileged', 'host_path', 'mounts', 'entrypoint', 'user', 'env', 'workdir', 'cwd',
                        'devices', 'tmpfs', 'socket', 'args', 'options', 'docker', 'container', 'memory', 'network'):
                self.assertRejects(enc({**body, key: 'x'}), 'forbidden_field')
            for key in ('script', 'argv', 'cmd', 'command', 'sh', 'code', 'exec', 'python', 'exclude_path', 'paths', 'roots', 'root',
                        'max_bytes', 'limits', 'depth', 'allowed_levels', 'levels'):
                self.assertIn(self.reason(enc({**body, key: 'x'})), {'unexpected_field', 'forbidden_field'}, (name, key))

    def test_path_is_the_marker_path_and_nothing_else(self):
        for bad in BAD_MARKER_PATHS:
            self.assertRejects(enc({**VALID_PROBE['file_state'], 'path': bad}), 'invalid_path')
        for good in (MARKER, '/work/marker-' + '0123456789abcdef01234567', '/work/marker-' + 'f' * 24):
            self.assertEqual(proto.decode_request(enc({**VALID_PROBE['file_state'], 'path': good})).path, good)

    def test_digest_is_64_lowercase_hex(self):
        for bad in BAD_DIGESTS:
            self.assertRejects(enc({**VALID_PROBE['copy_scan'], 'sha256': bad}), 'invalid_digest')
        self.assertEqual(proto.decode_request(enc({**VALID_PROBE['copy_scan'], 'sha256': 'f' * 64})).sha256, 'f' * 64)

    def test_size_is_an_integer_inside_the_scan_bound_and_bool_is_not_one(self):
        for bad in BAD_SIZES:
            self.assertRejects(enc({**VALID_PROBE['copy_scan'], 'size': bad}), 'invalid_size')

    def test_exclude_is_null_or_a_marker_path(self):
        for bad in ('/work/marker-' + 'a' * 23, '/tmp/marker-' + 'a' * 24, '', '-', '/work', '/work/marker-' + 'a' * 24 + '\n',
                    5, True, False, ['x'], {'path': MARKER}, DIGEST):
            self.assertRejects(enc({**VALID_PROBE['copy_scan'], 'exclude': bad}), 'invalid_exclude')

    def test_values_are_checked_in_a_fixed_order(self):
        body = {**VALID_PROBE['copy_scan'], 'handle': 'x', 'sha256': 'x', 'size': 0, 'exclude': 'x'}
        for reason, key in (('invalid_handle', 'handle'), ('invalid_digest', 'sha256'), ('invalid_size', 'size'),
                            ('invalid_exclude', 'exclude')):
            self.assertRejects(enc(body), reason)
            body[key] = VALID_PROBE['copy_scan'][key]
        self.assertEqual(proto.decode_request(enc(body)).op, 'level_probe')

    def test_requests_are_immutable_and_hide_the_handle_and_the_digest(self):
        request = proto.decode_request(enc(VALID_PROBE['copy_scan']))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.size = 2
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.path = MARKER
        self.assertNotIn(HANDLE, repr(request))
        self.assertNotIn(DIGEST, repr(request))

    def test_duplicates_and_the_request_limit_apply_to_probe_requests(self):
        duplicate = ('{"op":"level_probe","handle":"%s","name":"file_state","path":"%s","path":"%s"}' % (HANDLE, MARKER, MARKER)).encode()
        self.assertRejects(duplicate, 'duplicate_key')
        for body in VALID_PROBE.values():
            base = enc(body)
            exact = base + b' ' * (proto.MAX_REQUEST_BYTES - len(base))
            self.assertEqual(proto.decode_request(exact).op, 'level_probe')
            self.assertRejects(exact + b' ', 'too_large')


class PersistenceLeaseTests(LeaseCase):
    def test_both_phases_hold_distinct_keys_and_share_the_single_plaza(self):
        leases, _ = make(max_sessions=1)
        first = leases.open_level(1000, RUN, 'persistence', 'actor', CONTEXT)
        self.assertEqual(self.reason(leases.open_level, 1000, RUN, 'persistence', 'fresh', CONTEXT), 'capacity_exhausted')
        self.assertEqual(self.reason(leases.open_level, 1000, RUN, 'persistence', 'actor', CONTEXT), 'already_active')
        leases.begin_close(first, 1000)
        leases.retire(first, cleanup_confirmed=True)
        second = leases.open_level(1000, RUN, 'persistence', 'fresh', CONTEXT)
        lease = leases.authorize(second, 1000)
        self.assertEqual((lease.level, lease.stage, lease.variant, lease.context_sha256, lease.run_id),
                         ('persistence', 'fresh', None, CONTEXT, RUN))
        self.assertEqual(self.reason(leases.open_level, 1000, RUN, 'persistence', 'fresh', CONTEXT), 'already_active')
        self.assertEqual(self.reason(leases.open_level, 1001, RUN, 'persistence', 'fresh', CONTEXT), 'already_active')

    def test_fresh_is_refused_for_every_other_level_without_taking_a_slot(self):
        leases, _ = make()
        for level in ('memory', 'secret'):
            self.assertEqual(self.reason(leases.open_level, 1000, RUN, level, 'fresh', CONTEXT), 'invalid_stage')
        self.assertEqual(self.reason(leases.open_level, 1000, RUN, 'persistence', 'x', CONTEXT), 'invalid_stage')
        self.assertEqual(leases.held(), 0)

    def test_a_persistence_phase_never_collides_with_another_level_or_a_variant(self):
        leases, _ = make(max_sessions=4)
        leases.open_level(1000, RUN, 'persistence', 'actor', CONTEXT)
        leases.open_level(1000, RUN, 'memory', 'actor', CONTEXT)
        leases.open_level(1000, run_id(2), 'persistence', 'actor', CONTEXT)
        leases.open(1000, RUN, 'legitimate')
        self.assertEqual(leases.held(), 4)


# ------------------------------------------------------------------------------------------------------- M3.1 · catalog
# Authored without a shell: none of these tests has been executed by the author. The operator runs them.

MISSIONS = ROOT / 'services' / 'agent' / 'missions.py'
CATALOG_ID = 'invoice-unit-cents/v1'
CATALOG_SHA = 'd055653221c49c92490e536dc665349746988bb14749c60757e7a770fc20e79e'
VALID_CATALOG = {
    'catalog_info': {'op': 'catalog_info'},
    'open_catalog': {'op': 'open_catalog', 'run_id': RUN, 'variant': 'legitimate', 'catalog_profile': 'B', 'context_sha256': CONTEXT,
                     'catalog_id': CATALOG_ID, 'catalog_sha256': CATALOG_SHA},
    'catalog_check': {'op': 'catalog_check', 'handle': HANDLE},
    'catalog_receipt': {'op': 'catalog_receipt', 'installation_id': INSTALL, 'run_id': RUN, 'variant': 'legitimate',
                        'catalog_profile': 'B', 'context_sha256': CONTEXT, 'catalog_id': CATALOG_ID, 'catalog_sha256': CATALOG_SHA,
                        'intent_id': INTENT, 'container_id': CONTAINER},
}
# Written independently of the module, from M3-CONTRATO-AGENTE: parity with the contract, not with the implementation.
CONTRACT_CATALOG_FIELDS = {
    'catalog_info': {'op'},
    'open_catalog': {'op', 'run_id', 'variant', 'catalog_profile', 'context_sha256', 'catalog_id', 'catalog_sha256'},
    'catalog_check': {'op', 'handle'},
    'catalog_receipt': {'op', 'installation_id', 'run_id', 'variant', 'catalog_profile', 'context_sha256', 'catalog_id',
                        'catalog_sha256', 'intent_id', 'container_id'},
}
BAD_PROFILES = ('a', 'b', 'AB', 'C', '', 'A ', ' B', 'A\n', None, 1, True, ['A'], {'A': 1}, 'legitimate', 'ordinary', 'catalog')
BAD_CATALOG_IDS = ('invoice-unit-cents/v2', 'Invoice-Unit-Cents/v1', CATALOG_ID + ' ', CATALOG_ID + '\n', ' ' + CATALOG_ID, '', None, 1,
                   True, [CATALOG_ID], {'id': CATALOG_ID}, '/catalog.json', 'invoice-reconcile/v1')
BAD_CATALOG_DIGESTS = (CATALOG_SHA.upper(), CATALOG_SHA[:-1], CATALOG_SHA + '0', 'e' * 64, CATALOG_SHA + '\n', ' ' + CATALOG_SHA[:-1], '',
                       None, 5, True, [CATALOG_SHA], DIGEST, 'g' * 64, '٠' * 64)
CATALOG_BODIES = {'open_catalog': VALID_CATALOG['open_catalog'], 'catalog_receipt': VALID_CATALOG['catalog_receipt']}


class CatalogContractTests(DecodeCase):
    def test_catalog_field_table_matches_the_contract_and_the_other_tables_are_untouched(self):
        self.assertEqual({op: set(fields) for op, fields in proto.CATALOG_OP_FIELDS.items()}, CONTRACT_CATALOG_FIELDS)
        self.assertEqual({op: set(body) for op, body in VALID_CATALOG.items()}, CONTRACT_CATALOG_FIELDS)
        self.assertEqual({op: set(fields) for op, fields in proto.OP_FIELDS.items()}, CONTRACT_FIELDS)  # M1: exactly as before
        self.assertEqual({op: set(fields) for op, fields in proto.LEVEL_OP_FIELDS.items()}, CONTRACT_LEVEL_FIELDS)  # M2: as before
        self.assertFalse(set(proto.CATALOG_OP_FIELDS) & (set(proto.OP_FIELDS) | set(proto.LEVEL_OP_FIELDS)))
        self.assertEqual(proto.CATALOG_PROFILES, ('A', 'B'))
        self.assertEqual(proto.PROBE_NAMES, ('task_result', 'artifact_capture', 'measure'))  # the probes did not grow
        self.assertEqual(proto.LEVEL_PROBE_NAMES, ('cgroup_events', 'file_state', 'copy_scan'))

    def test_the_fixed_catalog_constants_equal_missions_as_source(self):
        # Read as source, not imported: the codec is pure and so is this test. Parity pins the mirror against drift.
        tree = ast.parse(MISSIONS.read_text(encoding='utf-8'))
        found = {}
        for node in tree.body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                if node.targets[0].id in ('CATALOG_ID', 'CATALOG_DESTINATION', 'CATALOG_TEXT', 'CATALOG_SHA256'):
                    found[node.targets[0].id] = ast.literal_eval(node.value)
        self.assertEqual(set(found), {'CATALOG_ID', 'CATALOG_DESTINATION', 'CATALOG_TEXT', 'CATALOG_SHA256'})
        self.assertEqual((proto.CATALOG_ID, proto.CATALOG_SHA256, proto.CATALOG_DESTINATION),
                         (found['CATALOG_ID'], found['CATALOG_SHA256'], found['CATALOG_DESTINATION']))
        self.assertEqual(proto.CATALOG_SIZE, len(found['CATALOG_TEXT'].encode('utf-8')))
        self.assertEqual((proto.CATALOG_ID, proto.CATALOG_SHA256), (CATALOG_ID, CATALOG_SHA))

    def test_valid_catalog_requests_decode_to_exactly_their_fields(self):
        for op, body in VALID_CATALOG.items():
            request = proto.decode_request(enc(body))
            self.assertEqual(request.op, op)
            for name in ('run_id', 'variant', 'handle', 'installation_id', 'intent_id', 'container_id', 'context_sha256',
                         'catalog_profile', 'catalog_id', 'catalog_sha256'):
                self.assertEqual(getattr(request, name), body.get(name), (op, name))
            self.assertEqual((request.command, request.name, request.level, request.stage, request.path), (None,) * 5)

    def test_both_profiles_and_both_variants_are_accepted(self):
        for op in CATALOG_BODIES:
            for profile in proto.CATALOG_PROFILES:
                for variant in proto.VARIANTS:
                    request = proto.decode_request(enc({**VALID_CATALOG[op], 'catalog_profile': profile, 'variant': variant}))
                    self.assertEqual((request.catalog_profile, request.variant), (profile, variant))

    def test_the_other_operations_carry_no_catalog_fields(self):
        for body in (*VALID.values(), *VALID_LEVEL.values(), *VALID_PROBE.values()):
            request = proto.decode_request(enc(body))
            self.assertEqual((request.catalog_profile, request.catalog_id, request.catalog_sha256), (None, None, None), body['op'])

    def test_catalog_info_takes_no_field_at_all(self):
        self.assertEqual(proto.decode_request(enc(VALID_CATALOG['catalog_info'])).op, 'catalog_info')
        for extra in ('catalog_profile', 'catalog_id', 'handle', 'run_id', 'path', 'allowed_catalog', 'policy', 'prepare', 'foo'):
            self.assertIn(self.reason(enc({**VALID_CATALOG['catalog_info'], extra: 'x'})), {'unexpected_field', 'forbidden_field'}, extra)
        self.assertRejects(enc({**VALID_CATALOG['catalog_info'], 'path': '/catalog.json'}), 'forbidden_field')

    def test_extra_fields_are_rejected_for_every_catalog_operation(self):
        everything = set().union(*CONTRACT_CATALOG_FIELDS.values(), *CONTRACT_LEVEL_FIELDS.values(), *CONTRACT_FIELDS.values())
        for op, body in VALID_CATALOG.items():
            self.assertRejects(enc({**body, 'foo': 'x'}), 'unexpected_field')
            for other in everything - CONTRACT_CATALOG_FIELDS[op]:
                expected = 'forbidden_field' if other in ('container_id',) else 'unexpected_field'
                self.assertRejects(enc({**body, other: 'x'}), expected)

    def test_host_paths_flags_scripts_mounts_and_the_private_resource_are_never_fields(self):
        forbidden = ('image', 'volumes', 'privileged', 'network_mode', 'cap_add', 'security_opt', 'host_path', 'hostPath', 'path',
                     'mounts', 'mount', 'source', 'src', 'dest', 'destination', 'bind', 'entrypoint', 'user', 'env', 'workdir',
                     'devices', 'tmpfs', 'socket', 'args', 'options', 'docker', 'container', 'memory')
        for op, body in VALID_CATALOG.items():
            for key in forbidden:
                self.assertRejects(enc({**body, key: 'x'}), 'forbidden_field')
            for key in ('resource_id', 'catalog_path', 'catalog_file', 'file', 'filename', 'content', 'script', 'argv', 'cmd', 'command',
                        'flags', 'catalog_destination', 'allowed_catalog', 'catalog_profile_sha256', 'profile_sha256', 'check_index'):
                if key in CONTRACT_CATALOG_FIELDS[op]:
                    continue
                self.assertIn(self.reason(enc({**body, key: 'x'})), {'unexpected_field', 'forbidden_field'}, (op, key))

    def test_missing_fields_are_rejected_for_every_catalog_operation(self):
        for op, body in VALID_CATALOG.items():
            for key in CONTRACT_CATALOG_FIELDS[op] - {'op'}:
                self.assertRejects(enc({k: v for k, v in body.items() if k != key}), 'missing_field')
        self.assertRejects(enc({'op': 'open_catalog'}), 'missing_field')
        self.assertRejects(enc({'op': 'catalog_receipt'}), 'missing_field')
        self.assertRejects(enc({'op': 'catalog_check'}), 'missing_field')

    def test_catalog_id_and_digest_are_pins_of_the_one_fixed_catalog_not_selectors(self):
        for op in CATALOG_BODIES:
            for bad in BAD_CATALOG_IDS:
                self.assertRejects(enc({**VALID_CATALOG[op], 'catalog_id': bad}), 'invalid_catalog_id')
            for bad in BAD_CATALOG_DIGESTS:
                self.assertRejects(enc({**VALID_CATALOG[op], 'catalog_sha256': bad}), 'invalid_catalog_digest')
            # a well-formed digest or id that is not THE catalog is as invalid as a malformed one: there is no second catalog
            self.assertRejects(enc({**VALID_CATALOG[op], 'catalog_sha256': hashlib_hex('another catalog')}), 'invalid_catalog_digest')
            self.assertRejects(enc({**VALID_CATALOG[op], 'catalog_id': 'invoice-unit-cents/v2'}), 'invalid_catalog_id')

    def test_profile_is_exactly_a_or_b(self):
        for op in CATALOG_BODIES:
            for bad in BAD_PROFILES:
                self.assertRejects(enc({**VALID_CATALOG[op], 'catalog_profile': bad}), 'invalid_catalog_profile')

    def test_run_variant_context_and_ids_are_not_normalized_and_have_their_own_reasons(self):
        for op in CATALOG_BODIES:
            for bad in (RUN.upper(), RUN[:-1], RUN + '0', 'g' * 32, RUN + '\n', '٠' * 32, '', 5, None, [RUN], True, HANDLE):
                self.assertRejects(enc({**VALID_CATALOG[op], 'run_id': bad}), 'invalid_run_id')
            for bad in ('Legitimate', 'legit', '', None, 1, True, ['legitimate'], 'perturbed\n', 'A', 'B'):
                self.assertRejects(enc({**VALID_CATALOG[op], 'variant': bad}), 'invalid_variant')
            for bad in BAD_CONTEXTS:
                self.assertRejects(enc({**VALID_CATALOG[op], 'context_sha256': bad}), 'invalid_context')
        for key, (reason, bad_values) in RECEIPT_BAD.items():
            if key == 'variant':
                continue
            for bad in bad_values:
                self.assertRejects(enc({**VALID_CATALOG['catalog_receipt'], key: bad}), reason)
        for bad in (HANDLE.upper(), HANDLE[:-1], HANDLE + '0', 'g' * 64, HANDLE + '\n', RUN, '', 123, None, [HANDLE], True):
            self.assertRejects(enc({**VALID_CATALOG['catalog_check'], 'handle': bad}), 'invalid_handle')

    def test_values_are_checked_in_a_fixed_order(self):
        reasons = {'installation_id': 'invalid_installation_id', 'run_id': 'invalid_run_id', 'variant': 'invalid_variant',
                   'catalog_profile': 'invalid_catalog_profile', 'context_sha256': 'invalid_context', 'catalog_id': 'invalid_catalog_id',
                   'catalog_sha256': 'invalid_catalog_digest', 'intent_id': 'invalid_intent_id', 'container_id': 'invalid_container_id'}
        for op, order in (('open_catalog', ('run_id', 'variant', 'catalog_profile', 'context_sha256', 'catalog_id', 'catalog_sha256')),
                          ('catalog_receipt', ('installation_id', 'run_id', 'variant', 'catalog_profile', 'context_sha256', 'catalog_id',
                                               'catalog_sha256', 'intent_id', 'container_id'))):
            body = {**VALID_CATALOG[op], **{key: 'x' for key in order}}
            for key in order:
                self.assertRejects(enc(body), reasons[key])
                body[key] = VALID_CATALOG[op][key]
            self.assertEqual(proto.decode_request(enc(body)).op, op)

    def test_a_catalog_request_is_never_read_as_a_workflow_or_level_one_and_vice_versa(self):
        self.assertRejects(enc({**VALID['open'], 'catalog_profile': 'B'}), 'unexpected_field')
        self.assertRejects(enc({**VALID['receipt'], 'catalog_profile': 'B'}), 'unexpected_field')
        self.assertRejects(enc({**VALID['probe'], 'name': 'catalog_check'}), 'invalid_name')
        self.assertRejects(enc({**VALID_LEVEL['open_level'], 'catalog_profile': 'B'}), 'unexpected_field')
        self.assertRejects(enc({**VALID_CATALOG['open_catalog'], 'level': 'memory'}), 'unexpected_field')
        self.assertRejects(enc({**VALID_CATALOG['open_catalog'], 'stage': 'actor'}), 'unexpected_field')
        self.assertRejects(enc({**VALID_CATALOG['catalog_receipt'], 'level': 'memory'}), 'unexpected_field')
        self.assertRejects(enc({**VALID_CATALOG['catalog_check'], 'name': 'task_result'}), 'unexpected_field')
        self.assertRejects(enc({**VALID['close'], 'catalog_profile': 'B'}), 'unexpected_field')
        # the close of a catalog handle is the existing `close {op, handle}`: there is no catalog_close
        self.assertRejects(enc({'op': 'catalog_close', 'handle': HANDLE}), 'unknown_op')
        # a surplus field is judged before the missing ones, so a workflow-shaped open never reads as an open_catalog
        self.assertRejects(enc({'op': 'open_catalog', 'run_id': RUN, 'variant': 'legitimate'}), 'missing_field')
        self.assertRejects(enc({'op': 'open_catalog', 'run_id': RUN, 'variant': 'legitimate', 'level': 'memory'}), 'unexpected_field')

    def test_request_is_immutable_and_hides_the_handle(self):
        request = proto.decode_request(enc(VALID_CATALOG['catalog_check']))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            request.handle = 'x'
        self.assertNotIn(HANDLE, repr(request))
        opened = proto.decode_request(enc(VALID_CATALOG['open_catalog']))
        for name in ('catalog_profile', 'catalog_id', 'catalog_sha256', 'context_sha256'):
            with self.assertRaises(dataclasses.FrozenInstanceError):
                setattr(opened, name, 'A')

    def test_duplicates_size_and_the_request_limit_apply_to_catalog_operations(self):
        duplicate = ('{"op":"open_catalog","run_id":"%s","variant":"legitimate","catalog_profile":"A","catalog_profile":"B",'
                     '"context_sha256":"%s","catalog_id":"%s","catalog_sha256":"%s"}' % (RUN, CONTEXT, CATALOG_ID, CATALOG_SHA)).encode()
        self.assertRejects(duplicate, 'duplicate_key')
        for op, body in VALID_CATALOG.items():
            base = enc(body)
            self.assertLess(len(base), 640, op)
            exact = base + b' ' * (proto.MAX_REQUEST_BYTES - len(base))
            self.assertEqual(proto.decode_request(exact).op, op)
            self.assertRejects(exact + b' ', 'too_large')

    def test_operations_beyond_the_lot_remain_unknown(self):
        for op in ('catalog', 'catalog_open', 'catalog_prepare', 'catalog_release', 'catalog_status', 'open_catalogs', 'prepare_catalog',
                   'release_catalog', 'catalog_run', 'CATALOG_INFO', 'catalog_info '):
            self.assertRejects(enc({'op': op}), 'unknown_op')


def hashlib_hex(text):
    import hashlib  # local: the module under test is pure, the helper only builds a well-formed digest of something else
    return hashlib.sha256(text.encode()).hexdigest()


class CatalogLeaseTests(LeaseCase):
    ARGS = (CONTEXT, CATALOG_ID, CATALOG_SHA)

    def test_open_catalog_binds_variant_context_and_profile_and_has_no_level(self):
        leases, _ = make()
        handle = leases.open_catalog(1000, RUN, 'perturbed', 'B', *self.ARGS)
        lease = leases.authorize(handle, 1000)
        self.assertEqual((lease.run_id, lease.variant, lease.catalog_profile, lease.context_sha256, lease.handle, lease.domain),
                         (RUN, 'perturbed', 'B', CONTEXT, handle, 'catalog'))
        self.assertEqual((lease.level, lease.stage), (None, None))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            lease.catalog_profile = 'A'
        self.assertNotIn(handle, repr(lease))
        self.assertNotIn(handle, repr(leases))

    def test_the_domain_of_every_lease_is_named(self):
        leases, _ = make(max_sessions=3)
        workflow = leases.authorize(leases.open(1000, RUN, 'legitimate'), 1000)
        level = leases.authorize(leases.open_level(1000, RUN, 'memory', 'actor', CONTEXT), 1000)
        catalog = leases.authorize(leases.open_catalog(1000, RUN, 'legitimate', 'A', *self.ARGS), 1000)
        self.assertEqual((workflow.domain, level.domain, catalog.domain), ('workflow', 'level', 'catalog'))
        self.assertEqual((workflow.catalog_profile, level.catalog_profile), (None, None))

    def test_handles_are_random_64_hex_and_distinct(self):
        leases, _ = make(max_sessions=5)
        handles = {leases.open_catalog(1000, run_id(n), 'legitimate', 'A', *self.ARGS) for n in range(5)}
        self.assertEqual(len(handles), 5)
        for handle in handles:
            self.assertRegex(handle, r'\A[0-9a-f]{64}\Z')

    def test_arguments_are_validated_without_taking_a_slot(self):
        leases, _ = make()
        cases = [({'owner': 0}, 'invalid_owner'), ({'owner': True}, 'invalid_owner'), ({'run': RUN.upper()}, 'invalid_run_id'),
                 ({'variant': 'other'}, 'invalid_variant')]
        cases += [({'profile': bad}, 'invalid_catalog_profile') for bad in BAD_PROFILES]
        cases += [({'context': bad}, 'invalid_context') for bad in BAD_CONTEXTS]
        cases += [({'catalog_id': bad}, 'invalid_catalog_id') for bad in BAD_CATALOG_IDS]
        cases += [({'digest': bad}, 'invalid_catalog_digest') for bad in BAD_CATALOG_DIGESTS]
        for patch, reason in cases:
            args = {'owner': 1000, 'run': RUN, 'variant': 'legitimate', 'profile': 'A', 'context': CONTEXT, 'catalog_id': CATALOG_ID,
                    'digest': CATALOG_SHA, **patch}
            self.assertEqual(self.reason(leases.open_catalog, args['owner'], args['run'], args['variant'], args['profile'],
                                         args['context'], args['catalog_id'], args['digest']), reason, patch)
        self.assertEqual(leases.held(), 0)

    def test_replay_of_run_and_variant_is_refused_for_any_owner_profile_and_context(self):
        leases, _ = make()
        first = leases.open_catalog(1000, RUN, 'legitimate', 'B', *self.ARGS)
        for owner, profile, context in ((1000, 'B', CONTEXT), (1001, 'B', CONTEXT), (1000, 'A', CONTEXT), (1000, 'B', '8' * 64),
                                        (1001, 'A', '8' * 64)):
            self.assertEqual(self.reason(leases.open_catalog, owner, RUN, 'legitimate', profile, context, CATALOG_ID, CATALOG_SHA),
                             'already_active', (owner, profile, context))
        self.assertEqual(leases.authorize(first, 1000).handle, first)
        self.assertEqual(leases.held(), 1)

    def test_other_variant_or_run_is_independent(self):
        leases, _ = make(max_sessions=4)
        leases.open_catalog(1000, RUN, 'legitimate', 'A', *self.ARGS)
        leases.open_catalog(1000, RUN, 'perturbed', 'A', *self.ARGS)
        leases.open_catalog(1000, run_id(2), 'legitimate', 'B', *self.ARGS)
        self.assertEqual(leases.held(), 3)

    def test_a_catalog_lease_never_collides_with_a_workflow_or_level_lease_of_the_same_run(self):
        leases, _ = make(max_sessions=4)
        leases.open_catalog(1000, RUN, 'legitimate', 'A', *self.ARGS)
        leases.open(1000, RUN, 'legitimate')  # the same run and variant, another domain (and another diary key)
        leases.open_level(1000, RUN, 'memory', 'actor', CONTEXT)
        self.assertEqual(leases.held(), 3)
        self.assertEqual(self.reason(leases.open, 1000, RUN, 'legitimate'), 'already_active')  # the workflow key is still its own
        self.assertEqual(self.reason(leases.open_catalog, 1000, RUN, 'legitimate', 'B', *self.ARGS), 'already_active')

    def test_workflow_open_keeps_its_exact_semantics_beside_a_catalog_lease(self):
        leases, _ = make(max_sessions=2)
        workflow = leases.open(1000, RUN, 'legitimate')
        self.assertEqual(self.reason(leases.open, 1001, RUN, 'legitimate'), 'already_active')
        leases.open_catalog(1000, RUN, 'legitimate', 'A', *self.ARGS)
        self.assertEqual(self.reason(leases.open, 1000, run_id(3), 'legitimate'), 'capacity_exhausted')
        self.assertEqual(leases.authorize(workflow, 1000).catalog_profile, None)

    def test_there_is_one_plaza_shared_by_workflow_level_and_catalog(self):
        leases, _ = make(max_sessions=1)
        catalog = leases.open_catalog(1000, RUN, 'legitimate', 'A', *self.ARGS)
        self.assertEqual(self.reason(leases.open, 1000, run_id(2), 'legitimate'), 'capacity_exhausted')
        self.assertEqual(self.reason(leases.open_level, 1000, run_id(2), 'memory', 'actor', CONTEXT), 'capacity_exhausted')
        self.assertEqual(self.reason(leases.open_catalog, 1000, run_id(2), 'legitimate', 'B', *self.ARGS), 'capacity_exhausted')
        leases.retire(catalog, cleanup_confirmed=True)
        workflow = leases.open(1000, run_id(2), 'legitimate')
        self.assertEqual(self.reason(leases.open_catalog, 1000, RUN, 'legitimate', 'A', *self.ARGS), 'capacity_exhausted')
        leases.retire(workflow, cleanup_confirmed=True)
        leases.open_catalog(1000, RUN, 'legitimate', 'A', *self.ARGS)

    def test_foreign_owner_cannot_use_or_close_a_catalog_handle(self):
        leases, _ = make()
        handle = leases.open_catalog(1000, RUN, 'legitimate', 'B', *self.ARGS)
        self.assertEqual(self.reason(leases.authorize, handle, 1001), 'foreign_owner')
        self.assertEqual(self.reason(leases.begin_close, handle, 1001), 'foreign_owner')
        self.assertEqual(leases.authorize(handle, 1000).state, proto.ACTIVE)

    def test_expiry_close_and_retire_follow_the_m1_rules_and_keep_the_catalog_binding(self):
        leases, clock = make(max_sessions=1, ttl=60)
        handle = leases.open_catalog(1000, RUN, 'legitimate', 'B', *self.ARGS)
        clock.now += 59
        leases.authorize(handle, 1000)  # using it does not extend it
        clock.now += 1
        self.assertEqual(self.reason(leases.authorize, handle, 1000), 'expired')
        self.assertEqual(self.reason(leases.open_catalog, 1000, RUN, 'legitimate', 'B', *self.ARGS), 'already_active')
        self.assertEqual(self.reason(leases.open_catalog, 1000, run_id(2), 'legitimate', 'B', *self.ARGS), 'capacity_exhausted')
        closing = leases.begin_close(handle, 1000)
        self.assertEqual((closing.state, closing.domain, closing.catalog_profile, closing.context_sha256, closing.variant),
                         (proto.CLOSING, 'catalog', 'B', CONTEXT, 'legitimate'))
        self.assertEqual([item.handle for item in leases.pending_cleanup()], [handle])
        self.assertEqual(self.reason(leases.retire, handle, cleanup_confirmed=False), 'cleanup_not_confirmed')
        self.assertEqual(leases.held(), 1)
        leases.retire(handle, cleanup_confirmed=True)
        self.assertNotEqual(leases.open_catalog(1000, RUN, 'legitimate', 'B', *self.ARGS), handle)  # the lease key, not the diary's


if __name__ == '__main__':
    unittest.main()
