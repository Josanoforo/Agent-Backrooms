"""D5 configuration and suite persistence on isolated SQLite files."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
import sqlite3
from threading import Barrier

import pytest

from services.agent import d5_configuration, d5_store, d5_suite, missions


MODEL = 'fixture-model'
BASELINE_RUN = 'a' * 32
CANDIDATE_RUN = 'b' * 32


@pytest.fixture
def path(tmp_path):
    database = tmp_path / 'd5.sqlite3'
    with closing(sqlite3.connect(database)) as conn:
        d5_store.initialize(conn)
    return database


def configuration(**limits):
    specification = {
        'model_id': MODEL, 'mission_id': 'invoice-reconcile/v1',
        'tool_policy': 'sandbox-shell/v1', 'parameters': {'reasoning_effort': None},
        'limits': {'calls_per_variant': 8, 'max_output_tokens': 1024, 'max_input_chars': 24000,
                   'timeout_seconds_per_variant': 90, **limits},
    }
    return d5_configuration.build_configuration(specification, allowed_models=[MODEL])


def suite_plan(calls=4):
    return d5_suite.build_plan(
        configuration(), configuration(calls_per_variant=calls), baseline_run_id=BASELINE_RUN,
        control_ids={'legitimate': '1' * 64, 'perturbed': '2' * 64}, allowed_models=[MODEL],
    )


def test_idempotent_canonical_write_and_detached_historical_read(path):
    original = configuration()
    configuration_id = original['configuration_id']
    reordered = {key: original[key] for key in reversed(original)}
    with closing(sqlite3.connect(path)) as conn, conn:
        d5_store.initialize(conn)
        returned = d5_store.save_configuration(conn, reordered, allowed_models=[MODEL])
        returned['specification']['limits']['max_output_tokens'] = 1
        assert d5_store.save_configuration(conn, original, allowed_models=[MODEL]) == original

    with closing(sqlite3.connect(path)) as conn:
        assert d5_store.get_configuration(conn, configuration_id) == original
        assert d5_store.get_configuration(conn, 'a' * 64) is None
        assert conn.execute('SELECT document FROM d5_configurations').fetchall() == [(missions.canonical(original),)]
        with pytest.raises(d5_configuration.ConfigurationError, match='configuration_id'):
            d5_store.get_configuration(conn, "' OR 1=1--")


def test_version_change_creates_new_row_and_read_does_not_apply_current_policy(path):
    old, new = configuration(), configuration(calls_per_variant=4)
    assert old['configuration_id'] != new['configuration_id']
    with closing(sqlite3.connect(path)) as conn, conn:
        d5_store.save_configuration(conn, old, allowed_models=[MODEL])
        d5_store.save_configuration(conn, new, allowed_models=[MODEL])
        with pytest.raises(d5_configuration.ConfigurationError, match='model_id'):
            d5_store.save_configuration(conn, old, allowed_models=[])
        smaller_ceilings = {**d5_configuration.HARD_LIMITS, 'calls_per_variant': 4}
        with pytest.raises(d5_configuration.ConfigurationError, match='calls_per_variant'):
            d5_store.save_configuration(conn, old, allowed_models=[MODEL], server_limits=smaller_ceilings)
        assert d5_store.get_configuration(conn, old['configuration_id']) == old
        assert d5_store.get_configuration(conn, new['configuration_id']) == new
        assert conn.execute('SELECT count(*) FROM d5_configurations').fetchone() == (2,)


def test_invalid_incoming_seal_does_not_write_and_caller_can_rollback(path):
    original = configuration()
    corrupted = deepcopy(original)
    corrupted['specification']['limits']['max_output_tokens'] = 200
    with closing(sqlite3.connect(path)) as conn:
        with pytest.raises(d5_configuration.ConfigurationError, match='configuration_id mismatch'):
            d5_store.save_configuration(conn, corrupted, allowed_models=[MODEL])
        assert d5_store.get_configuration(conn, original['configuration_id']) is None
        conn.execute('BEGIN')
        d5_store.save_configuration(conn, original, allowed_models=[MODEL])
        assert d5_store.get_configuration(conn, original['configuration_id']) == original
        conn.rollback()
        assert d5_store.get_configuration(conn, original['configuration_id']) is None


@pytest.mark.parametrize('fault', ['wrong_row_id', 'invalid_seal', 'duplicate_key', 'noncanonical'])
def test_persisted_corruption_is_detected_and_retry_never_overwrites(path, fault):
    original = configuration()
    configuration_id = original['configuration_id']
    if fault == 'wrong_row_id':
        stored = missions.canonical(configuration(calls_per_variant=4))
    elif fault == 'invalid_seal':
        stored = missions.canonical({**original, 'configuration_id': 'a' * 64})
    elif fault == 'duplicate_key':
        stored = missions.canonical(original).replace('"schema":', '"schema":null,"schema":')
    else:
        stored = missions.canonical(original) + '\n'

    with closing(sqlite3.connect(path)) as conn, conn:
        conn.execute('INSERT INTO d5_configurations VALUES (?, ?)', (configuration_id, stored))
        with pytest.raises(d5_store.StoreError):
            d5_store.get_configuration(conn, configuration_id)
        with pytest.raises(d5_store.StoreError):
            d5_store.save_configuration(conn, original, allowed_models=[MODEL])
        assert conn.execute('SELECT document FROM d5_configurations').fetchone() == (stored,)


def test_two_concurrent_connections_preserve_one_row(path):
    original = configuration()
    ready = Barrier(2)

    def save():
        with closing(sqlite3.connect(path, timeout=10)) as conn, conn:
            ready.wait(timeout=10)
            return d5_store.save_configuration(conn, original, allowed_models=[MODEL])

    with ThreadPoolExecutor(max_workers=2) as pool:
        jobs = [pool.submit(save) for _ in range(2)]
        assert [job.result(timeout=10) for job in jobs] == [original, original]
    with closing(sqlite3.connect(path)) as conn:
        assert conn.execute('SELECT count(*) FROM d5_configurations').fetchone() == (1,)


def test_suite_binding_uses_caller_transaction_and_canonical_sealed_plan(path):
    plan = suite_plan()
    plan_id = plan['plan_id']
    binding = {'plan': plan, 'run_id': CANDIDATE_RUN}
    reordered = {key: plan[key] for key in reversed(plan)}
    with closing(sqlite3.connect(path, isolation_level=None)) as writer, closing(sqlite3.connect(path)) as reader:
        writer.execute('BEGIN IMMEDIATE')
        returned = d5_store.record_suite(writer, reordered, CANDIDATE_RUN)
        assert returned == binding
        returned['plan']['specification']['control_ids']['legitimate'] = '3' * 64
        assert d5_store.get_suite(writer, plan_id) == binding
        assert d5_store.get_suite(reader, plan_id) is None
        writer.rollback()
        assert d5_store.get_suite(writer, plan_id) is None

        writer.execute('BEGIN IMMEDIATE')
        d5_store.record_suite(writer, plan, CANDIDATE_RUN)
        writer.commit()
        assert d5_store.get_suite(reader, plan_id) == binding
        assert d5_store.record_suite(writer, plan, CANDIDATE_RUN) == binding
        assert reader.execute('SELECT plan_id, run_id, plan FROM d5_suites').fetchall() == [
            (plan_id, CANDIDATE_RUN, missions.canonical(plan)),
        ]


def test_suite_binding_rejects_invalid_or_reassigned_ids(path):
    original = suite_plan()
    alternative = suite_plan(calls=3)
    with closing(sqlite3.connect(path)) as conn, conn:
        with pytest.raises(d5_suite.SuiteError, match='plan_id mismatch'):
            d5_store.record_suite(conn, {**original, 'plan_id': 'f' * 64}, CANDIDATE_RUN)
        with pytest.raises(d5_store.StoreError, match='plan_id'):
            d5_store.get_suite(conn, "' OR 1=1--")
        with pytest.raises(d5_store.StoreError, match='run_id is invalid'):
            d5_store.record_suite(conn, original, 'invalid')
        with pytest.raises(d5_store.StoreError, match='matches the baseline'):
            d5_store.record_suite(conn, original, BASELINE_RUN)
        assert d5_store.get_suite(conn, original['plan_id']) is None
        d5_store.record_suite(conn, original, CANDIDATE_RUN)
        with pytest.raises(d5_store.StoreError, match='different binding'):
            d5_store.record_suite(conn, original, 'c' * 32)
        with pytest.raises(d5_store.StoreError, match='different binding'):
            d5_store.record_suite(conn, alternative, CANDIDATE_RUN)
        assert d5_store.get_suite(conn, original['plan_id']) == {'plan': original, 'run_id': CANDIDATE_RUN}
        assert d5_store.get_suite(conn, alternative['plan_id']) is None


@pytest.mark.parametrize('fault', ['wrong_row_id', 'invalid_seal', 'duplicate_key', 'noncanonical', 'baseline_run'])
def test_suite_read_rejects_corruption_and_retry_preserves_original_row(path, fault):
    plan = suite_plan()
    plan_id = plan['plan_id']
    run_id = CANDIDATE_RUN
    document = missions.canonical(plan)
    if fault == 'wrong_row_id':
        document = missions.canonical(suite_plan(calls=3))
    elif fault == 'invalid_seal':
        document = missions.canonical({**plan, 'plan_id': 'f' * 64})
    elif fault == 'duplicate_key':
        document = document.replace('"schema":', '"schema":null,"schema":', 1)
    elif fault == 'noncanonical':
        document += '\n'
    else:
        run_id = BASELINE_RUN
    with closing(sqlite3.connect(path)) as conn, conn:
        row = (plan_id, run_id, document)
        conn.execute('INSERT INTO d5_suites VALUES (?, ?, ?)', row)
        with pytest.raises(d5_store.StoreError):
            d5_store.get_suite(conn, plan_id)
        with pytest.raises(d5_store.StoreError):
            d5_store.record_suite(conn, plan, CANDIDATE_RUN)
        assert conn.execute('SELECT plan_id, run_id, plan FROM d5_suites').fetchall() == [row]
