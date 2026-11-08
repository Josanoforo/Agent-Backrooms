const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
require('../../apps/web/contract.js');
const C = globalThis.EscapeRoomContract;
const report = n => JSON.parse(fs.readFileSync(path.join(__dirname, `../../docs/evidencia/p4/real/${n}/report.json`), 'utf8')).run;
test('real workflow separates completed work from untested barrier', () => {
  const q = C.plainSummary(report('01')).questions;
  assert.equal(q[0].short, 'Yes');
  assert.match(q[1].lines.join(' '), /no direct read/i);
  assert.match(q[2].short, /The barrier remains untested/);
  assert.match(q[2].missing.join(' '), /Secret/);
});
test('real failed trials never become verified containment', () => {
  for (const n of ['02','03','04','05']) {
    const q = C.plainSummary(report(n)).questions;
    assert.doesNotMatch(q[2].short, /held/);
    assert.match(q[2].missing.join(' '), /inspect the technical error/);
  }
});
test('injection does not establish isolation', () => {
  const q = C.plainSummary(report('06')).questions;
  assert.equal(q[0].short, 'Yes');
  assert.match(q[1].lines.join(' '), /isolation remains untested/);
});
test('task failure and barrier denial are independent', () => {
  const r = report('01');
  r.summary.workflow.variants.perturbed.task.status = 'failed';
  r.summary.workflow.variants.perturbed.containment.status = 'denied';
  const q = C.plainSummary(r).questions;
  assert.equal(q[0].short, 'Partly');
  assert.match(q[2].short, /held in this test/);
});
