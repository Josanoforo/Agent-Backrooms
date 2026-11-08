"""Vultr Serverless Inference adapter; the endpoint is deliberately fixed."""
import json
import os
import httpx
from . import budget, d4_context, d5_context, usage, external, guards

ENDPOINT = "https://api.vultrinference.com/v1/chat/completions"
FAILED = "Vultr inference request failed"

# Input limit (characters of str(message) summed over the request). Explicit configuration, never truncation: a request
# above the limit is refused before the budget and the network. The environment may only LOWER the production default;
# the hard maximum is the historical production value, so no setting can enlarge what a single call may send.
INPUT_LIMIT_ENV = "ESCAPE_PROVIDER_INPUT_LIMIT_CHARS"
INPUT_LIMIT_DEFAULT = 40000
INPUT_LIMIT_MIN = 2000
INPUT_LIMIT_HARD_MAX = 40000
INPUT_LIMIT_INVALID = "Provider input limit configuration invalid"

class ProviderError(Exception):
    pass

class D4CompletionError(ProviderError):
    """D4 terminal provider outcome with a stable code for the workflow."""

    def __init__(self, code):
        super().__init__(FAILED)
        self.code = code


class InputLimitError(ValueError):
    """Invalid input-limit configuration. The message never echoes the offending value."""

def resolve_input_limit(environ=None):
    """(limit, source) from the environment: ('default' when unset, 'env' when set). Raises InputLimitError.

    The value must be plain ASCII digits (no sign, spaces inside, decimals or exponents) within
    [INPUT_LIMIT_MIN, INPUT_LIMIT_HARD_MAX]. A variable that is set but blank is invalid, not 'unset'.
    """
    raw = (os.environ if environ is None else environ).get(INPUT_LIMIT_ENV)
    if raw is None:
        return INPUT_LIMIT_DEFAULT, "default"
    text = raw.strip()
    if not (text and text.isascii() and text.isdigit() and len(text) <= 9):
        raise InputLimitError(INPUT_LIMIT_ENV + " must be a whole number of characters")
    value = int(text)
    if not INPUT_LIMIT_MIN <= value <= INPUT_LIMIT_HARD_MAX:
        raise InputLimitError(INPUT_LIMIT_ENV + " must be between " + str(INPUT_LIMIT_MIN) + " and " + str(INPUT_LIMIT_HARD_MAX))
    return value, "env"

def _initial_input_limit():
    try:
        return resolve_input_limit()[0]
    except InputLimitError:
        return 0  # fail closed: configured() is False and complete() refuses until the process restarts with a valid value

# Resolved once at import so experiment.describe() (run snapshot, /api/config) reports the limit actually in force.
# Changing the environment needs a restart. Still assignable (the historical P4 bootstrap sets it to 8000): the
# effective limit is never above this value.
INPUT_LIMIT_CHARS = _initial_input_limit()

def input_limit():
    """Effective limit: the lower of the live environment value and INPUT_LIMIT_CHARS. Raises InputLimitError."""
    value, _ = resolve_input_limit()
    patched = INPUT_LIMIT_CHARS
    if type(patched) is not int or patched < 1:
        raise InputLimitError("Provider input limit is not usable; restart with a valid " + INPUT_LIMIT_ENV)
    return min(value, patched)

# Opt-in reasoning effort (P4). Unset: the request payload is exactly the historical one. Set: the only accepted value is
# 'minimal', and only for the two models whose official catalogue entry (GET /v1/models, 200) lists it in
# reasoning.supported_efforts. Anything else is a configuration error: refused before the budget and the network.
# max_tokens is not touched. The endpoint stays the fixed ENDPOINT.
REASONING_ENV = "ESCAPE_REASONING_EFFORT"
REASONING_VALUE = "minimal"
REASONING_MODELS = ("glm-5.3-flash", "qwen3.8-flash-next", "deepseek-v4.1-flash-1017")
REASONING_INVALID = "Provider reasoning configuration invalid"

class ReasoningConfigError(ValueError):
    """Invalid reasoning configuration. The message never echoes the offending value."""

def resolve_reasoning_effort(model=None, environ=None):
    """None when unset; 'minimal' when set, valid and supported by `model` (default: ESCAPE_MODEL). Raises ReasoningConfigError.

    The comparison is exact: a set-but-blank, differently cased or padded value is invalid, not 'unset'."""
    env = os.environ if environ is None else environ
    raw = env.get(REASONING_ENV)
    if raw is None:
        return None
    if raw != REASONING_VALUE:
        raise ReasoningConfigError(REASONING_ENV + " must be exactly '" + REASONING_VALUE + "' when set")
    model = env.get("ESCAPE_MODEL") if model is None else model
    if model not in REASONING_MODELS:
        raise ReasoningConfigError(REASONING_ENV + " is supported only for: " + ", ".join(REASONING_MODELS))
    return raw

def configured():
    if external.CURRENT.get() is not None:
        return True
    if not (os.getenv("VULTR_INFERENCE_KEY") and os.getenv("ESCAPE_MODEL")):
        return False
    try:
        input_limit()
        resolve_reasoning_effort()
    except (InputLimitError, ReasoningConfigError):
        return False  # runs stay unavailable (create_run -> 503, /api/config run_available false) instead of failing mid-run
    return True


_EVIDENCE_CLAIM={'type':'object','properties':{'text':{'type':'string'},
    'event_ids':{'type':'array','items':{'type':'string'}}},'required':['text','event_ids'],'additionalProperties':False}
EVIDENCE_RESPONSE_FORMAT={'type':'json_schema','json_schema':{'name':'escape_evidence','strict':True,'schema':{
    'type':'object','properties':{
        'task':_EVIDENCE_CLAIM,'boundary':_EVIDENCE_CLAIM,
        'actions':{'type':'array','items':_EVIDENCE_CLAIM},
        'observed_result':_EVIDENCE_CLAIM,
        'uncertainty':{'type':'array','items':_EVIDENCE_CLAIM},
        'fact_assertions':{'type':'array','items':{'type':'object','properties':{
            'event_id':{'type':'string'},
            'field':{'type':'string','enum':['network_socket_count','mismatch_count','task_status','containment_status']},
            'value':{'type':['integer','string']}},
            'required':['event_id','field','value'],'additionalProperties':False}},
        'verdicts':{'type':'array','items':{'type':'object','properties':{k:{'type':'string'} for k in
            ['event_id','outcome','task_status','independent_task_status','containment_status']},
            'required':['event_id'],'additionalProperties':False}}},
    'required':['task','boundary','actions','observed_result','uncertainty','verdicts','fact_assertions'],'additionalProperties':False}}}

GROUNDING_RESPONSE_FORMAT={'type':'json_schema','json_schema':{'name':'escape_grounding_review','strict':True,'schema':{
    'type':'object','properties':{
        'verdict':{'type':'string','enum':['supported','contradiction']},
        'contradictions':{'type':'array','items':{'type':'object','properties':{
            'claim':{'type':'string'},'reason':{'type':'string'},
            'event_ids':{'type':'array','items':{'type':'string'}}},
            'required':['claim','reason','event_ids'],'additionalProperties':False}}},
    'required':['verdict','contradictions'],'additionalProperties':False}}}

def ordinary_generation_configuration(model, *, tools=False, evidence_json=False, review_json=False):
    """Reproducible fixed-provider configuration, without credentials or content.

    Used by the interpreter before its durable claim. Dispatch still resolves and
    enforces the live configuration; no quota is reserved by this inspection.
    """
    return {'schema': 'generation-configuration/v1', 'endpoint': ENDPOINT,
            'model': model, 'max_tokens': evidence_output_tokens() if (evidence_json or review_json) else budget.CALL_OUTPUT_TOKENS,
            'reasoning_effort': resolve_reasoning_effort(model),
            'input_limit_chars': input_limit(), 'timeout_seconds': evidence_timeout_seconds() if (evidence_json or review_json) else 25,
            'tools_offered': tools is not False,
            **({'response_format': GROUNDING_RESPONSE_FORMAT if review_json else EVIDENCE_RESPONSE_FORMAT} if (evidence_json or review_json) else {})}


def evidence_output_tokens():
    """Tool-free explanation profile, independent of the native agent's 1024.

    The scoped-facts contract has room for prose, citations and assertions; its
    default is 4096, independent of the native agent/campaign profile of 1024.
    Operators can select another explicit profile without changing total quotas.
    All operational/USD reservations use the selected value; no size promises quality.
    """
    raw = os.getenv('ESCAPE_EVIDENCE_OUTPUT_TOKENS', '4096')
    if not raw.isascii() or not raw.isdecimal() or not 1 <= int(raw) <= 16384:
        raise ValueError('Invalid evidence output token configuration')
    return int(raw)


def evidence_timeout_seconds():
    # Preserve the original 25s allocation per 1024 output tokens, with an
    # operator override and a finite ceiling; this is not a provider guarantee.
    default = max(25, min(300, (25 * evidence_output_tokens() + 1023) // 1024))
    raw = os.getenv('ESCAPE_EVIDENCE_TIMEOUT_SECONDS', str(default))
    if not raw.isascii() or not raw.isdecimal() or not 5 <= int(raw) <= 300:
        raise ValueError('Invalid evidence timeout configuration')
    return int(raw)


def input_chars(messages):
    """Same character measure for preflight and actual dispatch; no truncation."""
    return sum(len(str(m)) for m in messages)


def generation_metadata(payload, limit, *, timeout_seconds=25):
    config = {'schema': 'generation-configuration/v1',
              'max_tokens': payload['max_tokens'], 'reasoning_effort': payload.get('reasoning_effort'),
              'input_limit_chars': limit, 'timeout_seconds': timeout_seconds,
              'tools_offered': 'tools' in payload,
              'tool_count': len(payload.get('tools', []))}
    if 'response_format' in payload:
        config['response_format'] = payload['response_format']
    return dict(config, input_chars=input_chars(payload['messages']))

def _message(body):
    """The assistant message dict of a decoded response, or None when malformed."""
    try:
        message = body["choices"][0]["message"]
    except (KeyError, IndexError, TypeError):
        return None
    return message if isinstance(message, dict) else None

REJECTION_STATUSES = (400, 422)
# Closed vocabulary for a provider rejection, in priority order: the first group with a matching substring wins. The body is read
# only here, in memory, and only for these statuses; nothing of it is stored, logged or put in an exception. The label comes from
# the words of the provider's own text (which may echo request content), so it is a pointer for the next diagnostic step, not proof
# of the cause, and says nothing about which model is incompatible with what.
REJECTION_CATEGORIES = (
    ("user_message_required", ("user query", "user message", "no user")),
    ("tool_message_order", ("tool_call_id", "tool_calls", "tool message", "tool response", "tool role", "must be followed")),
    ("tool_schema", ("schema", "maxlength", "additionalproperties", "additional properties")),
    ("tools_unsupported", ("tools", "tool_choice", "function calling", "function_call")),
    ("context_length", ("context length", "context window", "too long", "maximum context", "too many tokens")),
    ("max_tokens", ("max_tokens", "max_completion_tokens")),
    ("model_unavailable", ("model not found", "does not exist", "unknown model", "not a valid model")),
    ("parameter_rejected", ("unknown", "unrecognized", "unexpected", "extra field", "not permitted", "invalid")),
)
KNOWN_ROLES = ("system", "user", "assistant", "tool")

def classify_rejection(status, response):
    """Category label for a 400/422 answer, or None for any other status. 'unclassified' when nothing in the vocabulary matches."""
    if status not in REJECTION_STATUSES:
        return None
    try:
        text = str(response.text)[:4000].lower()
    except Exception:
        return "unclassified"
    for name, words in REJECTION_CATEGORIES:
        if any(word in text for word in words):
            return name
    return "unclassified"

def request_shape(payload):
    """Content-free description of an outgoing request: closed-set roles and counts only, never a message, name or argument."""
    messages = payload.get("messages") if isinstance(payload, dict) else None
    messages = messages if isinstance(messages, list) else []
    roles = [m.get("role") if isinstance(m, dict) and m.get("role") in KNOWN_ROLES else "other" for m in messages]
    assistants = [m for m in messages if isinstance(m, dict) and m.get("role") == "assistant"]
    return {"roles": roles[:64], "messages": len(messages), "has_user_message": "user" in roles,
            "assistant_with_tool_calls": sum(1 for m in assistants if m.get("tool_calls")),
            "assistant_content_none": sum(1 for m in assistants if m.get("content") is None),
            "tools_offered": isinstance(payload, dict) and "tools" in payload, "max_tokens": payload.get("max_tokens") if isinstance(payload, dict) and type(payload.get("max_tokens")) is int else None}

def tool_protocol_issues(messages):
    """Structural problems of the tool exchange in a conversation, as closed labels (empty when it is well formed).

    Every tool call of an assistant message needs a non-empty, unique id and exactly one following tool message carrying it; a
    tool message answers only a call that is open. Contents are never read or echoed.
    """
    issues, pending = [], set()
    def note(label):
        if label not in issues: issues.append(label)
    for m in messages:
        role = m.get("role") if isinstance(m, dict) else None
        if role == "tool":
            if isinstance(m.get("tool_call_id"), str) and m.get("tool_call_id") in pending: pending.discard(m.get("tool_call_id"))
            else: note("orphan_tool_message")
            continue
        if pending:
            note("unanswered_tool_calls"); pending = set()
        if role == "assistant" and m.get("tool_calls"):
            calls = m["tool_calls"]
            ids = [c.get("id") if isinstance(c, dict) else None for c in calls] if isinstance(calls, list) else None
            if ids is None: note("tool_calls_malformed")
            elif any(not isinstance(i, str) or not i for i in ids) or len(set(ids)) != len(ids): note("tool_call_id_invalid")
            else: pending = set(ids)
    if pending: note("unanswered_tool_calls")
    return issues

def _record_http_error(attempt, status, category):
    # usage.Attempt.record_http_error has no category parameter (usage.py is outside this lane): its own validated
    # `error_type` slot carries the closed label. Objects without that slot (and the null attempt) use the public call.
    close = getattr(attempt, "_close", None)
    if category and callable(close):
        close("http_error", http_status=status, error_type="provider_rejected_" + category)
    else:
        attempt.record_http_error(status)

def _handle(response, attempt, shape=None, *, d4=False):
    status = response.status_code
    if not 200 <= status < 300:
        if d4 and status == 429:
            category = 'rate_limited'
            error = D4CompletionError(category)
        else:
            category = classify_rejection(status, response)
            error = ProviderError(FAILED)
        _record_http_error(attempt, status, category)
        error.diagnostic = {"http_status": status if type(status) is int else None, "category": category, "request_shape": shape}
        raise error
    try:
        body = response.json()
    except ValueError:
        attempt.record_response(status, None, "malformed_response")
        raise ProviderError(FAILED) from None
    if d4 and usage.d4_finish_reason(body) == 'length':
        attempt.record_response(status, body, 'length')
        error = D4CompletionError('length')
        error.diagnostic = {'http_status': status, 'category': 'length', 'request_shape': shape}
        raise error
    message = _message(body)
    if message is None:
        attempt.record_response(status, body, "malformed_response")
        raise ProviderError(FAILED)
    attempt.record_response(status, body)
    return message

RUN_SHELL_TOOLS = [{"type": "function", "function": {"name": "run_shell", "description": "Run a shell command in the sandbox", "parameters": {"type": "object", "properties": {"command": {"type": "string", "maxLength": 4096}}, "required": ["command"], "additionalProperties": False}}}]

# D2B rooms: ONE fixed tool, no shell and no parameters. The model can only ask the controller to run its own fixed action; it
# chooses no command, path, UID, size or limit. It is a closed, module-owned specification: complete() accepts it by identity
# and refuses any other caller-built tool list, so the offered tools can never be assembled from run or model data.
ROOM_ACTION_TOOLS = [{"type": "function", "function": {"name": "run_room_action", "description": "Ask the controller to run the fixed room exercise once. Takes no arguments.", "parameters": {"type": "object", "properties": {}, "additionalProperties": False}}}]


def _require_campaign_day(authorized_day):
    if (authorized_day is None or authorized_day != os.getenv(d4_context.AUTHORIZED_DAY_ENV)
            or authorized_day != guards.day()):
        raise ValueError('D4 inference is outside its authorized UTC day')


def require_d5_provider(configuration, model, *, tools=True):
    if (type(model) is not str or model != configuration.model_id or tools is not True
            or d4_context.current() is not None or external.CURRENT.get() is not None
            or guards.room_day_guard_enabled() or guards.ROOM_AUTHORIZATION.get() is not None):
        usage.note_rejection('budget')
        raise ProviderError('D5 inference requires its bound model and the Vultr workflow provider')


def _require_d5_dispatch(configuration, variant):
    try:
        if (d5_context.current() is not configuration or variant is None
                or d5_context.current_variant() != variant):
            raise ValueError('D5 variant does not match the bound run')
        collector = usage.require_d5_collector(configuration)
        guards.require_d5_day(configuration.authorized_day_utc)
        live_rate = usage.Rate.from_mapping(json.loads(os.getenv('ESCAPE_USAGE_RATE_JSON', '{}')))
        if live_rate.to_exact_dict() != configuration.rate or guards.limit() is None:
            raise ValueError('D5 daily budget or tariff no longer matches admission')
    except (ValueError, TypeError, RecursionError, guards.GuardError):
        usage.note_rejection('budget')
        raise ProviderError('D5 dispatch requires the bound variant, usage collector and daily tariff') from None
    return collector


async def complete(model, messages, *, tools=True, evidence_json=False, review_json=False):
    """One chat completion. tools=False sends neither `tools` nor `tool_choice` (tasks that must not offer run_shell).

    tools=True offers run_shell (historical); tools=ROOM_ACTION_TOOLS offers the one fixed D2B room tool. Anything else is refused
    before the budget and the network.
    """
    if tools is True: offered = RUN_SHELL_TOOLS
    elif tools is False: offered = None
    elif tools is ROOM_ACTION_TOOLS: offered = ROOM_ACTION_TOOLS
    else: raise ProviderError("Provider request refused: unknown tool specification")
    campaign = d4_context.current()
    variant = d4_context.current_variant()
    configuration = d5_context.current()
    d5_variant = d5_context.current_variant()
    execution = campaign or configuration
    custom = external.CURRENT.get()
    # Fixed opt-in for ordinary, tool-free interpretation. It neither changes
    # agent/campaign payloads nor accepts a schema from untrusted evidence.
    if type(evidence_json) is not bool or type(review_json) is not bool or (evidence_json and review_json) or ((evidence_json or review_json) and (
            tools is not False or execution is not None or custom is not None
            or guards.ROOM_AUTHORIZATION.get() is not None)):
        raise ProviderError('JSON response format requires ordinary tool-free inference')
    try:
        ordinary_output = evidence_output_tokens() if (evidence_json or review_json) else budget.CALL_OUTPUT_TOKENS
        ordinary_timeout = evidence_timeout_seconds() if (evidence_json or review_json) else 25
    except ValueError:
        usage.note_rejection('budget')
        raise ProviderError('Invalid evidence output token configuration') from None
    if configuration is not None:
        require_d5_provider(configuration, model, tools=tools)
    elif campaign is not None:
        if (model != campaign.model_id or tools is not True or variant is None or custom is not None
                or guards.room_day_guard_enabled() or guards.ROOM_AUTHORIZATION.get() is not None):
            usage.note_rejection('budget')
            raise ProviderError('D4 inference requires its bound model, workflow variant and Vultr provider')
    elif offered is not ROOM_ACTION_TOOLS and guards.room_day_guard_enabled() and not (
            os.getenv('ESCAPE_ROOMS_AGENT_SHELL')=='1' and (
                guards.ROOM_AUTHORIZATION.get() is None or (tools is True and guards.ROOM_AUTHORIZATION.get().exploratory))):
        usage.note_rejection("budget")
        raise ProviderError("D2B service inference requires the fixed room tool")
    key = custom["api_key"] if custom else os.getenv("VULTR_INFERENCE_KEY")
    endpoint = custom["base_url"] + "/chat/completions" if custom else ENDPOINT
    if not key:
        usage.note_rejection("not_configured")
        raise ProviderError("Vultr API key is not configured")
    try:
        if execution is not None:
            effort = execution.reasoning_effort
        else:
            effort = None if custom and custom["base_url"] != "https://api.vultrinference.com/v1" else resolve_reasoning_effort(model)
    except ReasoningConfigError:
        usage.note_rejection("reasoning_config")  # counted as 'other'; no reservation, no network
        raise ProviderError(REASONING_INVALID) from None
    try:
        limit = campaign.max_input_chars if campaign is not None else input_limit()
    except InputLimitError:
        usage.note_rejection("input_limit")
        raise ProviderError(INPUT_LIMIT_INVALID) from None
    if configuration is not None:
        if configuration.max_input_chars > limit or configuration.max_output_tokens > budget.CALL_OUTPUT_TOKENS:
            usage.note_rejection('input_limit')
            raise ProviderError('D5 provider cannot honor the bound limits')
        limit = configuration.max_input_chars
    if input_chars(messages) > limit:
        usage.note_rejection("input_limit")
        raise ProviderError('Provider input limit exceeded')
    issues = tool_protocol_issues(messages)
    if issues:
        # A conversation the provider is bound to refuse is refused here: no reservation, no network, no consumption.
        usage.note_rejection("tool_protocol")
        error = ProviderError("Provider request refused: invalid tool protocol")
        error.issues = issues
        raise error
    attempt = usage.NULL_ATTEMPT
    try:
        room = guards.provider_room_authorization() if (offered is ROOM_ACTION_TOOLS or (
            tools is True and guards.ROOM_AUTHORIZATION.get() is not None and guards.ROOM_AUTHORIZATION.get().exploratory)) else None
        client_options = {}
        if campaign is not None:
            async def authorize_campaign_dispatch(request):
                # HTTPX has serialized the body. This hook does not yield between
                # the committed reservation, attempt registration and local dispatch.
                nonlocal attempt
                request_bytes = len(request.content)
                if request_bytes > campaign.max_request_bytes:
                    usage.note_rejection('input_limit')
                    raise ProviderError('D4 serialized request byte limit exceeded')
                authorized_day = os.getenv(d4_context.AUTHORIZED_DAY_ENV)
                try:
                    _require_campaign_day(authorized_day)
                    collector = usage.require_d4_collector(campaign)
                    campaign.reserve_dispatch(variant, request_bytes)
                    _require_campaign_day(authorized_day)
                    attempt = collector.begin_d4_attempt(campaign, variant)
                    attempt.record_generation(generation_metadata(payload, limit))
                    _require_campaign_day(authorized_day)
                except ValueError:
                    if attempt is not usage.NULL_ATTEMPT:
                        collector.discard_before_dispatch(attempt)
                    attempt = usage.NULL_ATTEMPT
                    usage.note_rejection('budget')
                    raise ProviderError('D4 dispatch reservation rejected') from None
                if attempt is usage.NULL_ATTEMPT:
                    raise ProviderError('D4 attempt registration failed')

            client_options['event_hooks'] = {'request': [authorize_campaign_dispatch]}
        elif configuration is not None:
            collector = _require_d5_dispatch(configuration, d5_variant)

            async def authorize_d5_dispatch(_request):
                # Reserve against the admitted tariff and register immediately before local transport.
                nonlocal attempt
                require_d5_provider(configuration, model, tools=tools)
                if _require_d5_dispatch(configuration, d5_variant) is not collector:
                    raise ProviderError('D5 usage collector changed before dispatch')
                db = os.getenv('ESCAPE_DB', 'escape-room.sqlite3')
                guards.reserve(db, model, messages, d5_day=configuration.authorized_day_utc)
                budget.reserve(db, 'call')
                if _require_d5_dispatch(configuration, d5_variant) is not collector:
                    raise ProviderError('D5 usage collector changed before dispatch')
                attempt = collector.begin_d5_attempt(configuration, d5_variant)
                attempt.record_generation(generation_metadata(payload, limit))
                if attempt is usage.NULL_ATTEMPT:
                    raise ProviderError('D5 attempt registration failed')
                try:
                    if _require_d5_dispatch(configuration, d5_variant) is not collector:
                        raise ProviderError('D5 usage collector changed before transport')
                except ProviderError:
                    collector.discard_before_dispatch(attempt)
                    attempt = usage.NULL_ATTEMPT
                    raise

            client_options['event_hooks'] = {'request': [authorize_d5_dispatch]}
        elif room is None:
            if evidence_json or review_json:
                guards.reserve(os.getenv('ESCAPE_DB', 'escape-room.sqlite3'), model, messages, output_tokens=ordinary_output)
                budget.reserve(os.getenv('ESCAPE_DB', 'escape-room.sqlite3'), 'call', output_tokens=ordinary_output)
            else:
                guards.reserve(os.getenv('ESCAPE_DB', 'escape-room.sqlite3'), model, messages)
                budget.reserve(os.getenv('ESCAPE_DB', 'escape-room.sqlite3'), 'call')
        else:
            if custom is not None:
                raise guards.GuardError('D2B inference requires the configured Vultr provider')

            async def authorize_dispatch(_request):
                # HTTPX invokes the hook after building the request and before handing it to transport.
                # There is no await inside the hook. A veto leaves committed reservations intact.
                nonlocal attempt
                guards.require_room_day(room.authorized_day_utc)
                attempt = usage.begin_attempt(model)
                attempt.record_generation(generation_metadata(payload, limit))
                try:
                    guards.require_room_day(room.authorized_day_utc)
                except guards.GuardError:
                    usage.discard_before_dispatch(attempt)
                    attempt = usage.NULL_ATTEMPT
                    raise

            client_options['event_hooks'] = {'request': [authorize_dispatch]}
        async with httpx.AsyncClient(timeout=ordinary_timeout, follow_redirects=False, trust_env=False, **client_options) as client:
            max_tokens = execution.max_output_tokens if execution is not None else ordinary_output
            payload = {"model": model, "messages": messages, "max_tokens": max_tokens}
            if evidence_json or review_json: payload['response_format'] = GROUNDING_RESPONSE_FORMAT if review_json else EVIDENCE_RESPONSE_FORMAT
            if offered is not None: payload["tools"] = offered
            if effort: payload["reasoning_effort"] = effort
            headers = {"Authorization": "Bearer " + key}
            if execution is None and room is None:
                attempt = usage.begin_attempt(model)
                attempt.record_generation(generation_metadata(payload, limit, timeout_seconds=ordinary_timeout))
            elif room is not None:
                guards.reserve(room.db, model, messages, room=room)
            response = await client.post(endpoint, headers=headers, json=payload)
            if custom:
                response = httpx.Response(response.status_code, content=response.content.replace(key.encode(), b"[redacted]"))
            return _handle(response, attempt, request_shape(payload), d4=campaign is not None)
    except ProviderError:
        raise
    except (budget.BudgetError, guards.GuardError) as exc:
        usage.note_rejection("budget")
        raise ProviderError(str(exc)) from exc
    except httpx.TimeoutException as exc:
        attempt.fail("timeout", exc)
        if campaign is not None:
            raise D4CompletionError('timeout') from exc
        raise ProviderError(FAILED) from exc
    except httpx.HTTPError as exc:
        attempt.fail("network_error", exc)
        if campaign is not None:
            raise D4CompletionError('network_error') from exc
        raise ProviderError(FAILED) from exc
    except (ValueError, KeyError, IndexError, TypeError) as exc:
        attempt.fail("malformed_response", exc)
        raise ProviderError(FAILED) from exc
    finally:
        attempt.abandon()  # no-op if closed; marks cancellation/unexpected exit as unknown usage


def initial_messages(prompt):
    """Explicit user turn required by Qwen; system rules retain authority."""
    return [{"role":"system","content":prompt},{"role":"user","content":"Please complete the task."}]
