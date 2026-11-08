"""Persistent daily conservative inference reservations, independent of Claude development spend."""
import contextlib
from contextvars import ContextVar
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import json
import os
import sqlite3

from . import budget

class GuardError(Exception): pass

ROOM_DAY_ENV = 'ESCAPE_D2B_AUTHORIZED_DAY_UTC'
ROOM_DAY_REQUIRED_ENV = 'ESCAPE_D2B_REQUIRE_AUTHORIZED_DAY'
D5_DAY_ENV = 'ESCAPE_D5_AUTHORIZED_DAY_UTC'


def require_d5_day(authorized_day):
    if authorized_day != os.getenv(D5_DAY_ENV) or (authorized_day is not None and authorized_day != day()):
        raise GuardError('D5 inference is outside its authorized UTC day')


@dataclass
class RoomAuthorization:
    authorized_day_utc: str
    db: str
    reserved_day_utc: str | None = None
    exploratory: bool = False
    reserved_calls: int = 0


ROOM_AUTHORIZATION = ContextVar('d2b_room_inference_authorization', default=None)


def room_day_guard_enabled():
    return ROOM_DAY_ENV in os.environ or ROOM_DAY_REQUIRED_ENV in os.environ


def configured_room_day():
    raw = os.getenv(ROOM_DAY_ENV)
    required = os.getenv(ROOM_DAY_REQUIRED_ENV)
    if raw is None and required is None:
        return None
    try:
        if required not in (None, '1') or raw is None or date.fromisoformat(raw).isoformat() != raw:
            raise ValueError
    except ValueError:
        raise GuardError('D2B requires a configured UTC authorization day (YYYY-MM-DD)') from None
    return raw


def require_room_day(authorized_day):
    if authorized_day is None or authorized_day != configured_room_day() or authorized_day != day():
        raise GuardError('D2B inference is outside its authorized UTC day')


@contextlib.contextmanager
def room_authorization(authorized_day, db, *, exploratory=False):
    if type(exploratory) is not bool: raise GuardError('Invalid room tool mode')
    if authorized_day is None and configured_room_day() is None:
        yield None
        return
    require_room_day(authorized_day)
    state = RoomAuthorization(authorized_day, db, exploratory=exploratory)
    token = ROOM_AUTHORIZATION.set(state)
    try:
        yield state
    finally:
        ROOM_AUTHORIZATION.reset(token)


def provider_room_authorization():
    state = ROOM_AUTHORIZATION.get()
    if state is not None or configured_room_day() is not None:
        require_room_day(state.authorized_day_utc if state is not None else None)
    return state

def capacities():
    try:
        concurrency = int(os.getenv('ESCAPE_CONCURRENT_RUNS', '1'))
        queue = int(os.getenv('ESCAPE_QUEUE_CAPACITY', '0'))
        if not 1 <= concurrency <= 3 or not 0 <= queue <= 20: raise ValueError()
        return concurrency, queue
    except ValueError:
        raise GuardError('Invalid concurrency configuration (maximum 3 runs)') from None

def limit():
    raw = os.getenv('ESCAPE_DAILY_USD_LIMIT')
    if raw is None: return None
    try:
        value = Decimal(raw)
        if not value.is_finite() or not 0 <= value <= 100: raise ValueError()
        return int(value * 1000000)
    except (InvalidOperation, ValueError, OverflowError):
        raise GuardError('Invalid daily inference USD limit') from None

def day(): return datetime.now(timezone.utc).date().isoformat()

def initialize(c):
    c.execute('CREATE TABLE IF NOT EXISTS daily_inference_budget (day TEXT PRIMARY KEY, reserved_microusd INTEGER NOT NULL)')

def snapshot(db):
    maximum = limit()
    if maximum is None: return {'enabled': False}
    try:
        with contextlib.closing(sqlite3.connect(db, timeout=10)) as c:
            initialize(c)
            today = day()
            row = c.execute('SELECT reserved_microusd FROM daily_inference_budget WHERE day=?', (today,)).fetchone()
    except sqlite3.Error:
        raise GuardError('Daily inference budget state unavailable') from None
    used = row[0] if row else 0
    return {'enabled': True, 'day_utc': today, 'limit_usd': maximum/1e6, 'reserved_usd': used/1e6,
            'remaining_usd': max(0, maximum-used)/1e6, 'basis': 'conservative reservations, not invoiced charges'}

def check(db):
    state = snapshot(db)
    if state['enabled'] and state['remaining_usd'] <= 0:
        raise GuardError('Daily inference budget exhausted; try after 00:00 UTC')
    return state

def reserve(db, model, messages, *, room=None, d5_day=None, output_tokens=None):
    output_tokens = budget.CALL_OUTPUT_TOKENS if output_tokens is None else output_tokens
    if type(output_tokens) is not int or not 1 <= output_tokens <= 16384:
        raise GuardError('Invalid output reservation')
    if (room is not None or d5_day is not None) and output_tokens != budget.CALL_OUTPUT_TOKENS:
        raise GuardError('Bound inference output reservation cannot change')
    maximum = limit()
    if maximum is None:
        if room is not None:
            raise GuardError('D2B requires a configured daily inference budget')
        return
    try:
        rate = json.loads(os.getenv('ESCAPE_USAGE_RATE_JSON', '{}'))
        from . import external
        custom = external.CURRENT.get()
        if custom and custom['base_url'] != 'https://api.vultrinference.com/v1':
            rate = json.loads(os.getenv('ESCAPE_EXTERNAL_RATES_JSON', '{}')).get(custom['base_url'] + '|' + model, {})
        prices = [Decimal(str(rate[k])) for k in ('input_per_million', 'output_per_million')]
        if rate.get('model') != model or any(not p.is_finite() or p < 0 for p in prices): raise ValueError()
        if room is not None and rate.get('effective_date') != room.authorized_day_utc:
            raise GuardError('D2B requires a configured rate effective on its authorized UTC day')
        # UTF-8 serialized bytes upper-bound ordinary byte-tokenization; 4096 covers framing/tool schema.
        # Reserve the effective provider maximum, including reported reasoning.
        amount = int(((len(json.dumps(messages, ensure_ascii=True).encode()) + 4096)*prices[0] + output_tokens*prices[1]).to_integral_value(rounding=ROUND_CEILING))
    except (KeyError, ValueError, TypeError, InvalidOperation):
        raise GuardError('Daily inference guard requires a configured rate for this provider and model') from None
    try:
        with contextlib.closing(sqlite3.connect(db, timeout=10, isolation_level=None)) as c:
            c.execute('BEGIN IMMEDIATE')
            try:
                if room is not None:
                    if room.reserved_calls >= (8 if room.exploratory else 1) or (room.reserved_day_utc is not None and not room.exploratory):
                        raise GuardError('D2B already reserved its only inference call')
                    require_room_day(room.authorized_day_utc)
                    today = room.authorized_day_utc
                else:
                    today = day()
                    if d5_day is not None and today != d5_day:
                        raise GuardError('D5 inference is outside its authorized UTC day')
                initialize(c)
                row = c.execute('SELECT reserved_microusd FROM daily_inference_budget WHERE day=?', (today,)).fetchone()
                used = row[0] if row else 0
                if used + amount > maximum:
                    raise GuardError('Daily inference budget exhausted for this call; try after 00:00 UTC')
                c.execute('INSERT INTO daily_inference_budget VALUES (?,?) ON CONFLICT(day) DO UPDATE SET reserved_microusd=excluded.reserved_microusd', (today, used+amount))
                if room is not None:
                    budget.reserve_in(c, 'call')
                    require_room_day(today)
                if d5_day is not None:
                    require_d5_day(d5_day)
                c.execute('COMMIT')
                if room is not None:
                    room.reserved_day_utc = today
                    room.reserved_calls += 1
            except BaseException:
                if c.in_transaction: c.execute('ROLLBACK')
                raise
    except sqlite3.Error:
        raise GuardError('Daily inference budget state unavailable') from None
