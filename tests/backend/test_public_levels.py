"""ESCAPE_PUBLIC_LEVELS: a narrow public opening on the actor service (mesa 01, 2026-11-08)."""
import os

import pytest

from services.agent import main
from test_actor_workflow_scope import admitted  # noqa: F401  (fixture)
pytestmark = pytest.mark.skipif(not hasattr(os, 'geteuid'), reason='actor levels are POSIX only')
NO_TOKEN = {'Authorization': ''}


@pytest.fixture
def public_secret(admitted, monkeypatch):  # noqa: F811
    monkeypatch.setenv('ESCAPE_ACTOR_LEVELS', 'memory,secret')
    monkeypatch.setenv('ESCAPE_PUBLIC_LEVELS', 'secret')
    return admitted


def test_config_reports_the_public_level_without_token_requirement(public_secret):
    client, _, calls = public_secret
    config = client.get('/api/config', headers=NO_TOKEN).json()
    assert config['run_authorization_required'] is False and config['public_levels'] == ['secret']
    assert config['run_available'] is True and not calls


def test_public_secret_is_admitted_without_token(public_secret):
    client, dispatched, calls = public_secret
    started = client.post('/api/runs', json={'model': 'fixture', 'levels': ['secret']}, headers=NO_TOKEN)
    assert started.status_code == 202, started.text
    assert dispatched[0][2] == ['secret'] and dispatched[0][3]['context'].level == 'secret' and not calls


@pytest.mark.parametrize('body', [{'levels': ['memory']}, {'levels': ['workflow']},
                                  {'levels': ['secret'], 'injection_variant': 'a'}])
def test_other_requests_still_need_the_token(public_secret, body):
    client, dispatched, calls = public_secret
    response = client.post('/api/runs', json={'model': 'fixture', **body}, headers=NO_TOKEN)
    assert response.status_code in (401, 422), response.text
    assert not dispatched and not calls


def test_history_still_needs_the_token(public_secret):
    client, _, calls = public_secret
    assert client.get('/api/runs', headers=NO_TOKEN).status_code == 401 and not calls


def test_without_public_levels_secret_needs_the_token(admitted, monkeypatch):  # noqa: F811
    client, dispatched, calls = admitted
    monkeypatch.setenv('ESCAPE_ACTOR_LEVELS', 'secret')
    assert client.get('/api/config', headers=NO_TOKEN).json()['run_authorization_required'] is True
    response = client.post('/api/runs', json={'model': 'fixture', 'levels': ['secret']}, headers=NO_TOKEN)
    assert response.status_code == 401 and not dispatched and not calls


@pytest.fixture
def public_rooms(admitted, monkeypatch):  # noqa: F811
    monkeypatch.setenv('ESCAPE_ACTOR_LEVELS', 'processes,privileges,secret')
    monkeypatch.setenv('ESCAPE_ROOMS_EXPERIMENT', '1')
    monkeypatch.setenv('ESCAPE_PUBLIC_LEVELS', 'processes,privileges,secret')
    return admitted


@pytest.mark.parametrize('selected', ['processes', 'privileges'])
def test_public_d2b_room_is_admitted_without_token(public_rooms, selected):
    client, dispatched, calls = public_rooms
    started = client.post('/api/runs', json={'model': 'fixture', 'levels': [selected]}, headers=NO_TOKEN)
    assert started.status_code == 202, started.text
    assert dispatched[0][2] == [selected] and not calls


def test_unlisted_d2b_room_still_passes_the_operator_gate(admitted, monkeypatch):  # noqa: F811
    client, dispatched, calls = admitted
    monkeypatch.setenv('ESCAPE_ACTOR_LEVELS', 'processes,privileges')
    monkeypatch.setenv('ESCAPE_ROOMS_EXPERIMENT', '1')
    monkeypatch.setenv('ESCAPE_PUBLIC_LEVELS', 'processes')
    response = client.post('/api/runs', json={'model': 'fixture', 'levels': ['privileges']}, headers=NO_TOKEN)
    assert response.status_code == 401, response.text
    assert not dispatched and not calls
