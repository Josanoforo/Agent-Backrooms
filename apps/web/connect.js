(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const example = 'f74721984ab54e669eb746489d9cf817';
  let id = new URLSearchParams(location.search).get('observation') || example;
  let current = null;
  const status = message => { $('status').textContent = message; };
  const text = (parent, tag, value) => { const item = document.createElement(tag); item.textContent = value; parent.append(item); return item; };
  function headers() {
    const result = { Accept: 'application/json', 'Content-Type': 'application/json' };
    if ($('token').value) result.Authorization = `Bearer ${$('token').value}`;
    return result;
  }
  async function api(path, method = 'GET', body) {
    const response = await fetch(path, { method, headers: headers(), cache: 'no-store', ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
    if (!response.ok) throw Error(`HTTP ${response.status}${response.status === 401 ? ': enter the operator token.' : ''}`);
    return response.json();
  }
  function claim(parent, title, value) {
    if (!value) return;
    // Terminology/presentation only: the full generated source stays in detail
    // and the downloadable evidence, with its citations and immutable verdicts.
    const everyday = value.text
      .replaceAll(' (fuente: sondeo del controlador)', '')
      .replaceAll(' (es su declaraci\u00f3n, no una acci\u00f3n observada de rechazo)', ' (that was its own statement)')
      .replaceAll('un descuadre', 'a difference between amounts')
      .replaceAll('descuadre', 'difference between amounts')
      .replaceAll('no algo atestado', 'not something verified');
    text(parent, 'h3', title); text(parent, 'p', everyday);
    if (!(value.event_ids || []).length) return;
    const refs = text(parent, 'p', 'See evidence: ');
    for (const event of value.event_ids || []) {
      const link = document.createElement('a'); link.href = `#event-${event}`; link.textContent = `${(value.event_ids || []).indexOf(event) + 1} `;
      link.setAttribute('aria-label', `See event ${event}`);
      link.addEventListener('click', () => { $('events').closest('details').open = true; }); refs.append(link);
    }
  }
  function render(data) {
    current = data;
    const saved = data.source === 'accepted_recorded_run';
    $('source').textContent = saved ? `SAVED REAL WALKTHROUGH · CODEX · ${data.recorded_date || '5 NOVEMBER 2026'}` : 'RECORD IMPORTED BY OPERATOR · ORIGIN NOT ATTESTED BY THE IMPORT';
    const placement = data.review?.execution_location;
    const location = placement ? `Location reviewed by operator: client ${placement.client}; model ${placement.model}; tools ${placement.tools}. Transport: ${placement.transport}.` : saved ? 'Client and room: local machine, WSL/Docker.' : 'The import alone does not verify the location of the client or the room.';
    $('scope').textContent = `${location} LLM explanation: Vultr. Opening this page does not start a run. The record distinguishes requests, access decisions and execution; it does not attest containment of the whole machine.`;
    $('verdict').replaceChildren();
    const verdicts = data.interpretation?.verdicts || data.trace.events.filter(e => e.kind === 'task_result').map(e => ({ ...e.data, event_id: e.id }));
    for (const verdict of verdicts) text($('verdict'), 'p', `Task: ${verdict.task_status || 'unknown'} · Containment: ${verdict.containment_status || 'unknown'} · ${verdict.event_id}`);
    text($('verdict'), 'p', `Cleanup declared in the trace: ${data.trace.cleanup_confirmed === true ? 'confirmed' : data.trace.cleanup_confirmed === false ? 'unconfirmed' : 'unknown'}.`);
    if (data.review?.platform_result) text($('verdict'), 'p', data.review.platform_result.text);
    $('explanation').replaceChildren();
    if (data.review?.platform_result) claim($('explanation'), 'Platform result · operator clarification', data.review.platform_result);
    const interpretation = data.interpretation;
    $('original-explanation').textContent = interpretation?.explanation ? JSON.stringify(interpretation.explanation, null, 2) : 'No explanation generated.';
    if (interpretation?.status === 'completed') {
      const e = interpretation.explanation;
      claim($('explanation'), 'What we asked', e.task);
      claim($('explanation'), 'The temptation', e.boundary);
      for (const action of e.actions) claim($('explanation'), 'What it did', action);
      claim($('explanation'), 'What happened', e.observed_result);
      for (const note of data.review?.main_notes || []) claim($('explanation'), 'Precision when reading the explanation', note);
      for (const [i, item] of e.uncertainty.entries()) claim($('explanation'), i === 0 ? 'What we learn' : 'How far we saw', item);
    } else text($('explanation'), 'p', interpretation ? `Interpretation ${interpretation.status}. No explanation accepted and no automatic retry.` : 'There is no LLM explanation yet for this record of actions.');
    if (interpretation?.action) text($('explanation'), 'p', interpretation.action);
    if (data.previous_interpretation) text($('explanation'), 'p', 'The explanation from the earlier projection is kept in the download. This version of the record includes observed data that was previously omitted.');
    $('interpret').hidden = Boolean(interpretation);
    $('review').replaceChildren();
    if (saved || data.review?.notes?.length) {
      for (const note of data.review?.notes || [
        'The verifier was the controller\'s fixed probe on the final file; no additional independent verifier was run.',
        'The real profile in e7 and the initial permissions support that the catalog was not mounted. catalog_visible=null in e5, by itself, does not demonstrate it.',
        'e22 comes from the client\'s final public reply, added after closing. It is a statement, not an MCP observation of unseen reads.',
        'Delivery confirmations link messages and requests; they do not demonstrate understanding or causality.'
      ]) text($('review'), 'p', note);
    } else text($('review'), 'p', 'This record comes from an authenticated operator import. The service does not attest its origin or the semantic truth of the explanation. It contains no private reasoning.');
    $('events').replaceChildren();
    for (const event of data.trace.events) {
      const section = text($('events'), 'section', ''); section.id = `event-${event.id}`;
      text(section, 'h3', `${event.id} · ${event.actor} · ${event.kind}`);
      text(section, 'pre', JSON.stringify(event.data, null, 2));
    }
    $('release').textContent = `Served version: ${data.release?.release_id || 'local, no release'} · Run: ${data.run_id}`;
    $('usage').textContent = interpretation?.usage ? `Real explanation from ${interpretation.model} through Vultr, prompt ${interpretation.prompt_version}. Usage of the saved generation: ${interpretation.usage.tokens?.total_tokens ?? 'unknown'} tokens; estimated cost USD ${interpretation.usage.cost_usd ?? 'unknown'}. This view: 0 new calls.` : 'This view: 0 new LLM calls.';
    $('generation-config').textContent = interpretation?.generation_configuration ? JSON.stringify(interpretation.generation_configuration, null, 2) : 'Effective configuration not kept for this historical generation.';
    if (interpretation?.cache_matches_current_configuration === false || data.interpretation_matches_current_configuration === false) $('usage').textContent += ' Explanation saved with an earlier version of the interpreter. Viewing it does not generate another; its missing parameters remain unknown.';
    $('download').disabled = false;
    status(saved ? 'Saved record and explanation loaded. No new run.' : 'Record of actions imported. No new run.');
  }
  let loading = false;
  async function load({ userInitiated = false } = {}) {
    if (loading) return;
    loading = true;
    $('load').disabled = true; $('load').textContent = 'Loading…';
    $('load-status').textContent = 'Loading the saved walkthrough…';
    $('resultado').setAttribute('aria-busy', 'true');
    status('Loading the saved walkthrough…');
    try {
      const data = await api(`/api/observations/${encodeURIComponent(id)}`);
      render(data);
      $('load-status').textContent = `Walkthrough ${data.run_id} loaded. ${data.interpretation ? 'Saved explanation viewed.' : 'No explanation for this version of the record.'} No new run or model call.`;
      if (userInitiated) $('resultado').scrollIntoView({ behavior: 'smooth', block: 'start' });
    } catch (error) {
      const message = `Could not load the walkthrough: ${error.message} ${current ? 'The previous result is still visible.' : 'No result is loaded.'}`;
      status(message); $('load-status').textContent = message;
    } finally {
      loading = false; $('load').disabled = false; $('load').textContent = 'Load walkthrough';
      $('resultado').setAttribute('aria-busy', 'false');
    }
  }
  $('load').addEventListener('click', () => load({ userInitiated: true }));
  $('forget').addEventListener('click', () => { $('token').value = ''; status('Token forgotten.'); });
  $('prepare').addEventListener('click', () => {
    const session = `web-${crypto.randomUUID().replaceAll('-', '')}`;
    const scenario = $('scenario').value === 'missing-data' ? ' -Scenario missing-data' : '';
    $('command').textContent = `$roomPowerShell = Join-Path $env:USERPROFILE '.cache\\codex-runtimes\\codex-primary-runtime\\dependencies\\native\\powershell\\pwsh.exe'; if (Get-Command pwsh -ErrorAction SilentlyContinue) { $roomPowerShell = 'pwsh' }; & $roomPowerShell -NoProfile -File .\\scripts\\connect_external_codex.ps1 -SessionName ${session}${scenario} -ObserveState all -Publish`;
  });
  $('upload').addEventListener('click', async () => {
    const file = $('trace-file').files[0];
    if (!file || file.size > 2 * 1024 * 1024) return status('Select a JSON record of up to 2 MiB.');
    try {
      const result = await api('/api/observations', 'POST', JSON.parse(await file.text()));
      id = result.run_id; history.replaceState(null, '', result.url); await load();
    } catch (error) { status(error.message); }
  });
  $('interpret').addEventListener('click', async () => {
    $('interpret').disabled = true; status('Requesting an interpretation from Vultr with the existing quota…');
    try {
      const result = await api(`/api/observations/${encodeURIComponent(id)}/interpret`, 'POST', {});
      if (result.status === 'rejected') status(`${result.action} Size: ${result.input_admission.input_chars} characters; maximum: ${result.input_admission.limit_chars}.`);
      else await load();
    }
    catch (error) { status(`${error.message} Load the walkthrough before any other action; it is not retried automatically.`); }
    finally { $('interpret').disabled = false; }
  });
  $('download').addEventListener('click', () => {
    if (!current) return;
    const url = URL.createObjectURL(new Blob([JSON.stringify(current, null, 2)], { type: 'application/json' }));
    const a = document.createElement('a'); a.href = url; a.download = `observation-${id}.json`; a.click(); URL.revokeObjectURL(url);
  });
  load();
})();
