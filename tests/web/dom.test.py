"""Browser DOM contract tests; all /api and EventSource messages are explicit fakes."""
import errno
import functools
import io
import os
import http.server
import json
import re
import threading
import unittest
from pathlib import Path
from time import monotonic, sleep
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlparse

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[2]
WEB = ROOT / "apps" / "web"


ARTIFACT_PATH = '/api/runs/run-1/artifacts/legitimate'
ARTIFACT_BODY = b'{"accepted_ids":["I001"]}'


def read_download_bytes(download):
    # Playwright waits for Chromium to finish, but Windows can still briefly deny opening the file.
    path = download.path()
    deadline = monotonic() + 5
    while True:
        try:
            stream = path.open('rb')
        except PermissionError as exc:
            if os.name != 'nt' or exc.errno != errno.EACCES or monotonic() >= deadline:
                raise
            sleep(0.05)
        else:
            with stream:
                return stream.read()


class DownloadReadTests(unittest.TestCase):
    def test_windows_waits_for_access_to_the_same_file_then_returns_its_bytes(self):
        download = Mock()
        path = download.path.return_value
        path.open.side_effect = [PermissionError(errno.EACCES, 'temporarily denied'), io.BytesIO(b'original bytes')]
        with (
            patch.object(os, 'name', 'nt'),
            patch(__name__ + '.monotonic', return_value=0),
            patch(__name__ + '.sleep') as wait,
        ):
            self.assertEqual(read_download_bytes(download), b'original bytes')
        download.path.assert_called_once_with()
        self.assertEqual(path.open.call_count, 2)
        wait.assert_called_once()

    def test_windows_stops_waiting_and_surfaces_persistent_access_denial(self):
        download = Mock()
        path = download.path.return_value
        path.open.side_effect = PermissionError(errno.EACCES, 'still denied')
        with (
            patch.object(os, 'name', 'nt'),
            patch(__name__ + '.monotonic', side_effect=[0, 0, 5]),
            patch(__name__ + '.sleep') as wait,
        ):
            with self.assertRaisesRegex(PermissionError, 'still denied'):
                read_download_bytes(download)
        download.path.assert_called_once_with()
        self.assertEqual(path.open.call_count, 2)
        wait.assert_called_once()


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        # Chromium downloads are handled by the browser and can bypass page.route.
        if self.path != ARTIFACT_PATH:
            return super().do_GET()
        self.server.artifact_reads += 1
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Disposition', 'attachment; filename="invoice-reconciliation-legitimate.json"')
        self.end_headers()
        self.wfile.write(ARTIFACT_BODY)


class EscapeRoomDOMTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        handler = functools.partial(QuietHandler, directory=str(WEB))
        cls.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        cls.server.artifact_reads = 0
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.playwright = sync_playwright().start()
        cls.browser = cls.playwright.chromium.launch(headless=True, executable_path=os.environ.get("CHROMIUM_PATH") or None)

    @classmethod
    def tearDownClass(cls):
        cls.browser.close()
        cls.playwright.stop()
        cls.server.shutdown()
        cls.thread.join(timeout=3)
        cls.server.server_close()

    def make_page(self, config, post_status="queued", post_http=202, health_http=200, demo_report=None, post_raw=None,
                  path="", setup=None, post_hold=None, post_abort=False):
        """path: ruta+consulta a abrir (p. ej. '/?run=x'). setup(page): registra rutas antes de navegar.
        post_hold: lista; si se da, el POST de inicio queda retenido (route) hasta que la prueba lo resuelva.
        post_abort: el POST de inicio se corta sin respuesta (respuesta perdida)."""
        context = self.browser.new_context()
        page = context.new_page()
        requests = []
        methods = []

        def on_request(request):
            requests.append(request.url)
            methods.append((request.method, request.url))

        page.on("request", on_request)
        page._requests = requests
        page._methods = methods
        page.add_init_script("""
          window.__sources = [];
          window.EventSource = class {
            constructor(url) { this.url=url; this.listeners={}; this.closed=false; window.__sources.push(this); }
            addEventListener(name, fn) { (this.listeners[name] ||= []).push(fn); }
            emit(name, data) { for (const fn of this.listeners[name] || []) fn({data:JSON.stringify(data)}); }
            close() { this.closed=true; }
          };
        """)
        posts = []
        auth_headers = []
        demo_reads = []

        def config_route(route):
            route.fulfill(status=200, content_type="application/json", body=json.dumps(config))

        def run_route(route):
            posts.append(route.request.post_data_json)
            auth = route.request.headers.get("authorization")
            auth_headers.append(auth)
            if config.get("run_authorization_required") and auth != "Bearer operator-secret":
                route.fulfill(status=401, content_type="application/json", body=json.dumps({"detail":"Unauthorized"}))
                return
            if post_abort:
                route.abort()
                return
            if post_hold is not None:
                post_hold.append(route)
                return
            if post_raw is not None:
                route.fulfill(status=post_http, content_type="text/html", body=post_raw)
                return
            body={"id":"run-1","status":post_status} if post_http < 400 else {"detail":"Request rejected"}
            route.fulfill(status=post_http, content_type="application/json", body=json.dumps(body))

        def health_route(route):
            body={"status":"ok"} if health_http == 200 else {"status":"unavailable"}
            route.fulfill(status=health_http, content_type="application/json", body=json.dumps(body))

        def demo_route(route):
            demo_reads.append(True)
            route.fulfill(status=200, content_type="application/json", body=json.dumps(demo_report or {"run":{"id":"recorded-run","status":"completed","model":"glm-5.3-flash","levels":["secret"],"summary":{"secret":{"outcome":"blocked","evidence":"stored verifier evidence"}},"receipts":[]},"experiment":{"provider":"Vultr Serverless Inference"},"provenance":{"inference":"real Vultr API","host":"Ubuntu WSL; Docker Desktop Linux","report_hash_verified":True,"deployed_to_vultr":False}}))

        page.route("**/api/config", config_route)
        page.route("**/api/runs", run_route)
        page.route("**/healthz", health_route)
        
        # Por defecto el reporte final de una partida terminada no existe (404 explícito); las pruebas lo sustituyen con su propia ruta.
        page.route(re.compile(r"/api/runs/[^/?]+/report\?format=json$"),
                   lambda route: route.fulfill(status=404, content_type="application/json", body=json.dumps({"detail":"sin reporte simulado"})))
        page.route(re.compile(r"/api/runs/b9cd5cbfe05c4a2abf0ce1f3ebd79435/report\?format=json$"), demo_route)
        if setup is not None:
            setup(page)
        page.goto(self.base + path)
        page.locator("#notice").wait_for()
        page.wait_for_function("document.getElementById('operations').textContent.includes('Service healthy') || document.getElementById('operations').textContent.includes('Health check failed') || document.getElementById('operations').textContent.includes('Live runs are paused') || document.getElementById('operations').textContent.includes('Daily inference budget exhausted')")
        page.wait_for_function("document.querySelector('#model option[value=\"test-model\"]') !== null")
        page._auth_headers = auth_headers
        page._demo_reads = demo_reads
        return context, page, posts

    def config(self, configured=True):
        return {"models":["test-model"], "levels":["secret", "network", "custom-a"],
                "available_levels":["secret", "custom-a"], "configured":configured,
                "execution_mode":"fixture explícito","run_available":True,"quota_exhausted":False,
                "run_authorization_required":False}

    def test_run_receipt_terminal_summary_and_adversarial_text(self):
        context, page, posts = self.make_page(self.config())
        try:
            self.assertFalse(page.locator('input[value="secret"]').is_disabled())
            self.assertTrue(page.locator('input[value="network"]').is_disabled())
            self.assertFalse(page.locator('input[value="custom-a"]').is_disabled())
            self.assertEqual(page.locator('label').filter(has=page.locator('input[value="custom-a"]')).inner_text(), "custom-a")
            page.locator("#start").click()
            page.wait_for_function("window.__sources.length === 1")
            self.assertEqual(posts, [{"model":"test-model", "levels":["secret"]}])
            self.assertTrue(page.locator("#start").is_disabled())
            page.locator("#run-form").evaluate("el => el.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))")
            page.wait_for_timeout(80)
            self.assertEqual(len(posts), 1, "an active run must not submit twice")

            evil = "<img src=x onerror=window.__xss=true><script>window.__xss=true</script>"
            page.evaluate("([receipt]) => window.__sources[0].emit('receipt', receipt)", [{
                "id":"receipt-1", "run_id":"run-1", "level":"custom-a", "step":1,
                "tool":"run_shell", "args":{"command":evil}, "stdout":evil,
                "stderr":"", "exit_code":0, "outcome":"exhausted", "evidence":evil,
            }])
            self.assertIn(evil, page.locator("#receipts").inner_text())
            self.assertEqual(page.locator("#receipts img, #receipts script").count(), 0)
            self.assertFalse(page.evaluate("window.__xss === true"))

            page.evaluate("([run]) => window.__sources[0].emit('run', run)", [{
                "id":"run-1", "status":"completed",
                "summary":{"secret":{"outcome":"not_run"},"custom-a":{"outcome":"blocked","evidence":evil}},
            }])
            self.assertEqual(page.locator("#results .result").count(), 2)
            self.assertIn("Not run", page.locator("#results").inner_text())
            self.assertIn("Contained · verified block", page.locator("#results").inner_text())
            self.assertIn(evil, page.locator("#results").inner_text())
            self.assertEqual(page.locator("#results img, #results script").count(), 0)
            self.assertFalse(page.evaluate("window.__xss === true"))
            self.assertTrue(page.locator("#start").is_enabled(), "terminal event releases the active-run guard")
            self.assertTrue(page.evaluate("window.__sources[0].closed"))
        finally:
            context.close()

    def test_unconfigured_run_blocks_post_but_saved_report_is_read_only(self):
        context, page, posts = self.make_page(self.config(configured=False))
        try:
            self.assertTrue(page.locator("#start").is_disabled())
            self.assertTrue(page.locator('input[value="network"]').is_disabled())
            page.locator("#run-form").evaluate("el => el.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))")
            self.assertEqual(posts, [])
            self.assertTrue(page.locator("#start").is_disabled())
            page.locator("#load-demo").click()
            page.wait_for_function("document.getElementById('demo-output').textContent.includes('SAVED EXAMPLE')")
            self.assertIn("SAVED EXAMPLE", page.locator("#demo-output").inner_text())
            page.locator("#demo-output details summary").click()
            self.assertIn("real Vultr API", page.locator("#demo-output").inner_text())
            self.assertIn("Outside Vultr", page.locator("#demo-output").inner_text())
            self.assertEqual(len(page._demo_reads), 2)
            self.assertEqual(posts, [])
            self.assertIn("No run yet", page.locator("#summary").inner_text())
        finally:
            context.close()

    def test_saved_report_does_not_overwrite_live_report_and_global_errors_are_visible(self):
        context, page, posts = self.make_page(self.config())
        try:
            page.locator("#start").click()
            page.wait_for_function("window.__sources.length === 1")
            page.locator("#load-demo").click()
            page.wait_for_function("document.getElementById('demo-output').textContent.includes('SAVED EXAMPLE')")
            self.assertIn("Live run run-1 · queued", page.locator("#summary").inner_text())
            self.assertIn("SAVED EXAMPLE", page.locator("#demo-output").inner_text())
            page.evaluate("() => window.__sources[0].emit('run',{id:'run-1',status:'failed',summary:{error:'late <svg onload=window.__xss=true>'}})")
            self.assertIn("Run error", page.locator("#summary").inner_text())
            self.assertNotIn("Run error", page.locator("#demo-output").inner_text())
            self.assertFalse(page.evaluate("window.__xss === true"))
            page.evaluate("() => window.__sources[0].emit('run',{id:'run-1',status:'failed',summary:{error:'provider <b>failure</b>'}})")
            self.assertIn("Run error: provider <b>failure</b>", page.locator("#summary").inner_text())
            self.assertEqual(page.locator("#summary b").count(), 0)
            self.assertFalse(page.locator("#start").is_disabled())
            self.assertEqual(len(posts), 1)
        finally:
            context.close()

    def test_ola2_measurements_verification_and_level_specific_verdicts(self):
        config = {"models":["test-model"], "levels":["secret","network","memory","persistence","injection"],
                  "available_levels":["secret","network","memory","persistence","injection"], "configured":True,
                  "run_available":True,"quota_exhausted":False,"run_authorization_required":False}
        context, page, _posts = self.make_page(config)
        try:
            page.locator("#start").click()
            page.wait_for_function("window.__sources.length === 1")
            page.evaluate("([receipts]) => receipts.forEach(r => window.__sources[0].emit('receipt',r))", [[
                {"id":"net-r","run_id":"run-1","level":"network","step":1,"outcome":"error","evidence":"canary unavailable","verification":{"source":"probe","scope":"attempt","checks":[{"name":"canary","passed":False,"evidence":{"before":"offline","after":"offline","exit_code":7}}]}},
                {"id":"mem-r","run_id":"run-1","level":"memory","step":1,"outcome":"exhausted","memory_peak_bytes":None,"memory_observed_max_bytes":524288,"memory_measurement":{"source":"cgroup sample","scope":"container","kind":"sampled_max","available":True},"cleanup_confirmed":None},
                {"id":"mem-null","run_id":"run-1","level":"memory","step":2,"outcome":"error","memory_peak_bytes":None,"memory_observed_max_bytes":None,"memory_measurement":{"source":"unavailable","scope":"container","kind":"peak","available":False}},
                {"id":"inj-r","run_id":"run-1","level":"injection","step":1,"outcome":"escaped","evidence":"oracle","sandbox_containment":"not_tested","memory_peak_bytes":None},
            ]])
            page.evaluate("() => window.__sources[0].emit('run',{id:'run-1',status:'completed',levels:['secret','network','memory','persistence','injection'],summary:{secret:{outcome:'not_run',evidence:'not selected by runner'},network:{outcome:'error',evidence:'canary unavailable',verification:{source:'canary oracle',scope:'attempt',checks:[{name:'request observation',passed:false,evidence:{before:'offline',after:'offline',exit_code:7}}]}},memory:{outcome:'exhausted',evidence:'no memory target verified',memory_peak_bytes:null,memory_observed_max_bytes:524288,memory_measurement:{source:'cgroup_v2_memory.peak',scope:'level_container',kind:'peak',available:true},cleanup_confirmed:null},persistence:{outcome:'not_run',evidence:'not requested'},injection:{outcome:'escaped',adversarial_obedience:true,legitimate_task_completed:false,sandbox_containment:'not_tested',cleanup_confirmed:false}}})")
            results = page.locator("#results").inner_text()
            self.assertEqual(page.locator("#results .result").count(), 5)
            self.assertIn("Not run", results)
            self.assertIn("Level error · no verified block", results)
            self.assertNotIn("Canary unreachable", results)
            self.assertIn("Measured peak: Not measured", results)
            self.assertIn("Observed maximum: 524288 bytes", results)
            self.assertIn("Measurement available: Yes", results)
            self.assertIn("Scope: Level / container", results)
            self.assertIn("Source: cgroup_v2_memory.peak", results)
            self.assertIn("including verification probes", results)
            injection = page.locator("#results .result").filter(has=page.locator("h3").filter(has_text="Injection"))
            self.assertIn("Adversarial instruction followed", injection.inner_text())
            self.assertIn("Sandbox containment remains untested", injection.inner_text())
            self.assertNotIn("verified escape", injection.inner_text())
            self.assertIn("Cleanup: Unverified", results)
            self.assertIn("Cleanup: Failed / unconfirmed", results)
            receipts = page.locator("#receipts").inner_text()
            self.assertIn("Measured peak: Not measured", receipts)
            self.assertIn("Observed maximum: Not measured", receipts)
            self.assertIn("Measurement available: No", receipts)
            self.assertIn("Scope: Attempt", receipts)
            injection_receipt = page.locator("#receipts .receipt").filter(has=page.locator("h3").filter(has_text="Injection"))
            self.assertIn("Sandbox containment remains untested", injection_receipt.inner_text())
            self.assertNotIn("Memory measurement", injection_receipt.inner_text())
            self.assertIn("Source: canary oracle", results)
            self.assertIn('"before":"offline"', results)
            self.assertIn('"after":"offline"', results)
            self.assertIn('"exit_code":7', results)
        finally:
            context.close()

    def test_operator_token_is_memory_only_bearer_and_401_is_clear(self):
        config={**self.config(),"run_authorization_required":True}
        context,page,posts=self.make_page(config)
        try:
            self.assertTrue(page.locator("#auth-group").is_visible())
            self.assertTrue(page.locator("#start").is_disabled())
            self.assertEqual(page.evaluate("localStorage.length"),0)
            page.locator("#operator-token").fill("wrong-secret")
            self.assertFalse(page.locator("#start").is_disabled())
            page.locator("#start").click()
            page.wait_for_function("document.getElementById('notice').textContent.includes('Authorization required')")
            self.assertEqual(page._auth_headers,["Bearer wrong-secret"])
            self.assertIn("Authorization required or invalid operator token",page.locator("#notice").inner_text())
            self.assertEqual(page.locator("#operator-token").input_value(),"")
            self.assertEqual(page.evaluate("localStorage.length"),0)
            self.assertEqual(len(posts),1)
        finally:
            context.close()

    def test_quota_429_and_health_503_stop_live_attempts_without_retry(self):
        context,page,posts=self.make_page(self.config(),post_http=429)
        try:
            page.locator("#start").click()
            page.wait_for_function("document.getElementById('notice').textContent.includes('Operational limit')")
            self.assertNotIn("Operational quota exhausted",page.locator("#operations").inner_text(),"429 alone is not proof of quota exhaustion")
            self.assertEqual(len(posts),1)
        finally:
            context.close()
        quota={**self.config(),"run_available":False,"quota_exhausted":True}
        context,page,posts=self.make_page(quota)
        try:
            self.assertIn("Finished receipts are open to read",page.locator("#operations").inner_text())
            self.assertTrue(page.locator("#start").is_disabled())
            page.locator("#run-form").evaluate("el => el.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))")
            self.assertEqual(posts,[])
        finally:
            context.close()
        context,page,posts=self.make_page(self.config(),health_http=503)
        try:
            self.assertIn("Health check failed",page.locator("#operations").inner_text())
            self.assertTrue(page.locator("#start").is_disabled())
            page.locator("#run-form").evaluate("el => el.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))")
            self.assertEqual(posts,[])
        finally:
            context.close()

    # Ola 4/5: attempt/observation/verdict, formularios, memory nula, histórico vs real.
    def start_run(self, page):
        page.locator("#start").click()
        page.wait_for_function("window.__sources.length === 1")

    @staticmethod
    def dd(section, term):
        return section.locator("dt", has_text=term).locator("xpath=following-sibling::dd[1]").inner_text()

    def test_receipt_separates_attempt_observation_verdict_and_never_turns_null_memory_into_zero(self):
        context, page, _posts = self.make_page(self.config())
        try:
            self.start_run(page)
            page.evaluate("([receipts]) => receipts.forEach(r => window.__sources[0].emit('receipt', r))", [[
                {"id":"r-null","run_id":"run-1","level":"network","step":1,"tool":"run_shell","args":{"command":"nc 10.0.0.5 80"},
                 "stdout":"","stderr":None,"exit_code":None,"duration_ms":None,"memory_peak_bytes":None,"outcome":"error","evidence":"canary unavailable"},
                {"id":"r-zero","run_id":"run-1","level":"memory","step":1,"tool":"run_shell","args":{},"stdout":"ok","stderr":"",
                 "exit_code":0,"duration_ms":5,"memory_peak_bytes":0,
                 "memory_measurement":{"source":"cgroup_v2_memory.peak","scope":"container","kind":"peak","available":True},"outcome":"exhausted"},
                {"id":"r-class","run_id":"run-1","level":"secret","step":1,"outcome":"blocked hidden skip"},
                {"id":"r-none","run_id":"run-1","level":"secret","step":2,"outcome":None},
            ]])
            receipts = page.locator("#receipts .receipt")
            self.assertEqual(receipts.count(), 4)

            first = receipts.nth(0)
            self.assertEqual(first.locator("section.phase > h4").all_inner_texts(), ["1 · Attempt", "2 · Observation", "3 · Verdict"])
            attempt, observation, verdict = [first.locator("section.phase").nth(i) for i in range(3)]
            self.assertIn("nc 10.0.0.5 80", attempt.inner_text())
            self.assertNotIn("nc 10.0.0.5 80", observation.inner_text())
            self.assertNotIn("nc 10.0.0.5 80", verdict.inner_text())
            self.assertEqual(self.dd(observation, "Exit code"), "Unavailable")
            self.assertEqual(self.dd(observation, "Duration"), "Not measured")
            self.assertEqual(self.dd(observation, "Peak memory"), "Not measured")
            self.assertEqual(observation.locator("pre").nth(0).inner_text(), "(empty)", "stdout vacío no es stdout no capturado")
            self.assertEqual(observation.locator("pre").nth(1).inner_text(), "Not captured")
            self.assertIn("Level error · no verified block", verdict.inner_text())
            self.assertNotIn("Contained · verified block", verdict.inner_text())
            self.assertEqual(verdict.locator(".status").get_attribute("class"), "status error")
            self.assertEqual(page.locator("#receipts pre[tabindex='0']").count(), 8, "stdout/stderr desplazables son alcanzables por teclado")

            zero = receipts.nth(1).locator("section.phase").nth(1).inner_text()
            self.assertIn("Measured peak: 0 bytes (0.00 MiB)", zero)
            self.assertNotIn("Measured peak: Not measured", zero)

            unknown = receipts.nth(2).locator("section.phase").nth(2)
            self.assertEqual(unknown.locator(".status").get_attribute("class"), "status unknown", "un resultado remoto no se usa como clase CSS")
            self.assertIn("Unrecognized verdict", unknown.inner_text())
            missing = receipts.nth(3).locator("section.phase").nth(2)
            self.assertIn("No verdict", missing.inner_text())
            self.assertEqual(missing.locator(".status").get_attribute("class"), "status unknown")
        finally:
            context.close()

    def test_levels_without_verdict_are_pending_while_run_is_active(self):
        context, page, _posts = self.make_page(self.config())
        try:
            self.start_run(page)
            page.evaluate("() => window.__sources[0].emit('receipt',{id:'r1',run_id:'run-1',level:'secret',step:1,outcome:'blocked'})")
            page.evaluate("() => window.__sources[0].emit('run',{id:'run-1',status:'running',model:'test-model',levels:['secret','custom-a'],summary:{secret:{outcome:'blocked',evidence:'verifier'}}})")
            summary = page.locator("#summary").inner_text()
            self.assertIn("Status: Running", summary)
            self.assertIn("Receipts: 1", summary)
            self.assertIn("Awaiting a final verdict", summary)
            pending = page.locator("#results .result").filter(has=page.locator("h3", has_text="custom-a"))
            self.assertIn("Pending · no verdict yet", pending.inner_text())
            self.assertNotIn("Not run", pending.inner_text())
            self.assertIn("Recorded attempts: 0", pending.inner_text())
            done = page.locator("#results .result").filter(has=page.locator("h3", has_text="Secret"))
            self.assertIn("Recorded attempts: 1", done.inner_text())
            self.assertIn("Level verdict", done.inner_text())

            page.evaluate("() => window.__sources[0].emit('run',{id:'run-1',status:'completed',summary:{'custom-a':{outcome:'not_run'}}})")
            final = page.locator("#results .result").filter(has=page.locator("h3", has_text="custom-a")).inner_text()
            self.assertIn("Not run", final)
            self.assertNotIn("Pendiente", final)
            self.assertIn("Check each room for its verdict", page.locator("#summary").inner_text())
        finally:
            context.close()

    def test_form_labels_states_and_start_reason_are_exposed(self):
        context, page, posts = self.make_page(self.config())
        try:
            self.assertEqual(page.get_by_label("Model", exact=True).get_attribute("id"), "model")
            self.assertEqual(page.locator("fieldset legend").inner_text(), "Rooms")
            self.assertEqual(page.locator("fieldset").get_attribute("aria-describedby"), "levels-help")
            self.assertEqual(page.locator('label').filter(has=page.locator('input[value="network"]')).inner_text(), "Network · unavailable")
            self.assertEqual(page.locator("#start").get_attribute("type"), "submit")
            self.assertEqual(page.locator("#start").get_attribute("aria-describedby"), "start-help")
            self.assertIn("Starting a run may consume operational quota", page.locator("#start-help").inner_text())
            self.assertEqual(page.locator("a.skip").get_attribute("href"), "#main")
            self.assertEqual(page.locator("#main").count(), 1)
            page.keyboard.press("Tab")
            self.assertEqual(page.evaluate("document.activeElement.className"), "skip")

            page.locator('input[value="secret"]').uncheck()
            page.locator('input[value="custom-a"]').uncheck()
            self.assertTrue(page.locator("#start").is_disabled())
            self.assertIn("Select at least one room", page.locator("#start-help").inner_text())
            page.locator('input[value="secret"]').check()
            self.assertTrue(page.locator("#start").is_enabled())
            self.assertEqual(posts, [])
        finally:
            context.close()
        context, page, _posts = self.make_page(self.config(), health_http=503)
        try:
            self.assertIn("The service health check failed", page.locator("#start-help").inner_text())
        finally:
            context.close()

    def test_private_room_requires_one_selection_and_uses_operator_token(self):
        config = self.config()
        config.update(levels=["secret", "processes", "privileges"],
                      available_levels=["secret", "processes", "privileges"],
                      run_authorization_required=True)
        context, page, posts = self.make_page(config)
        try:
            page.locator("#operator-token").fill("operator-secret")
            page.get_by_label("Processes", exact=True).check()
            self.assertTrue(page.locator("#start").is_disabled())
            self.assertIn("single-room run", page.locator("#start-help").inner_text())
            self.assertEqual(posts, [])

            page.get_by_label("Secret", exact=True).uncheck()
            page.locator("#start").click()
            page.wait_for_function("window.__sources.length === 1")
            self.assertEqual(posts, [{"model": "test-model", "levels": ["processes"]}])
            self.assertEqual(page._auth_headers, ["Bearer operator-secret"])
        finally:
            context.close()

    def test_level_selection_survives_config_refresh_after_terminal_run(self):
        context, page, posts = self.make_page(self.config())
        try:
            page.locator('input[value="custom-a"]').uncheck()
            self.start_run(page)
            self.assertEqual(posts, [{"model":"test-model", "levels":["secret"]}])
            with page.expect_response("**/api/config"):
                page.evaluate("() => window.__sources[0].emit('run',{id:'run-1',status:'completed',summary:{secret:{outcome:'blocked'}}})")
            page.wait_for_timeout(100)
            self.assertFalse(page.locator('input[value="custom-a"]').is_checked(), "el refresco no debe rehacer la selección del usuario")
            self.assertTrue(page.locator('input[value="secret"]').is_checked())
        finally:
            context.close()

    def test_token_error_marks_field_invalid_and_returns_focus_without_leaking_token(self):
        config = {**self.config(), "run_authorization_required": True}
        context, page, posts = self.make_page(config)
        try:
            self.assertEqual(page.locator("#operator-token").get_attribute("aria-required"), "true")
            self.assertIn("operator token", page.locator("#start-help").inner_text())
            page.locator("#operator-token").fill("wrong-secret")
            page.locator("#start").click()
            page.wait_for_function("document.getElementById('notice').textContent.includes('Authorization required')")
            self.assertEqual(page.locator("#operator-token").get_attribute("aria-invalid"), "true")
            self.assertEqual(page.evaluate("document.activeElement.id"), "operator-token")
            self.assertEqual(page.locator("#operator-token").input_value(), "")
            self.assertEqual(page.locator("#notice").get_attribute("aria-live"), "assertive")
            page.locator("#operator-token").fill("x")
            self.assertIsNone(page.locator("#operator-token").get_attribute("aria-invalid"))
            self.assertNotIn("wrong-secret", " ".join(page._requests))
            self.assertNotIn("wrong-secret", page.locator("body").inner_text())
            self.assertEqual(page.evaluate("localStorage.length + sessionStorage.length"), 0)
            self.assertEqual(len(posts), 1)
        finally:
            context.close()

    def test_non_json_http_errors_are_not_reported_as_offline_and_unreadable_success_is_not_a_run(self):
        context, page, posts = self.make_page(self.config(), post_http=502, post_raw="<html><b>Bad gateway</b></html>")
        try:
            page.locator("#start").click()
            page.wait_for_function("document.getElementById('notice').textContent.includes('HTTP 502')")
            self.assertNotIn("Could not reach", page.locator("#notice").inner_text())
            self.assertEqual(page.locator("#notice b").count(), 0)
            self.assertTrue(page.locator("#start").is_enabled())
            self.assertEqual(len(posts), 1)
        finally:
            context.close()
        context, page, posts = self.make_page(self.config(), post_http=202, post_raw="not json")
        try:
            page.locator("#start").click()
            page.wait_for_function("document.getElementById('notice').textContent.includes('unreadable response')")
            self.assertEqual(page.evaluate("window.__sources.length"), 0, "sin id válido no se abre seguimiento")
            self.assertIn("No run yet", page.locator("#summary").inner_text())
            self.assertTrue(page.locator("#start").is_enabled())
            self.assertEqual(len(posts), 1, "no se reintenta")
        finally:
            context.close()

    def test_saved_report_is_labelled_historical_and_never_invents_provenance(self):
        report = {"run":{"id":"hist-1","status":"completed","model":"m-h","levels":["secret"],
                         "summary":{"secret":{"outcome":"blocked","evidence":"stored"}},
                         "receipts":[{"id":"h-r1","run_id":"hist-1","level":"secret","step":1,"tool":"run_shell","args":{"command":"cat /canary"},
                                      "stdout":"","stderr":"denied","exit_code":1,"duration_ms":12,"memory_peak_bytes":None,
                                      "outcome":"blocked","evidence":"probe denied"}]}}
        context, page, posts = self.make_page(self.config(), demo_report=report)
        try:
            page.locator("#load-demo").click()
            page.wait_for_function("document.getElementById('demo-output').textContent.includes('SAVED EXAMPLE')")
            self.assertIn("demo-badge", page.evaluate("document.activeElement.className"))
            page.locator("#demo-output details summary").click()
            out = page.locator("#demo-output").inner_text()
            for text in ["historical evidence", "replay", "provider not reported",
                         "Source: Not reported", "Inference: Not reported",
                         "Environment: Not reported", "Deployment: Not reported",
                         "Hash verified: Not reported", "Date: Not reported",
                         "This recording describes the profile tested", "Recorded attempts: 1"]:
                self.assertIn(text, out)
            for invented in ["WSL", "Docker Desktop", "ola 1", "Ola 1", "03 nov 2026", "Vultr Serverless Inference"]:
                self.assertNotIn(invented, out)
            self.assertEqual(page.locator("#demo-output .receipt h4").count(), 1)
            self.assertEqual(page.locator("#demo-output .receipt section.phase > h5").count(), 3)
            self.assertEqual(page.locator("#receipts .receipt").count(), 0, "lo histórico no entra en los recibos de la corrida viva")
            self.assertIn("No run yet", page.locator("#summary").inner_text())
            self.assertTrue(page.locator("#download-json").is_disabled())
            self.assertEqual(posts, [])
        finally:
            context.close()

    def test_comparison_is_an_explicit_empty_state_without_a_leaderboard_request(self):
        context, page, _posts = self.make_page(self.config())
        try:
            page.locator("#load-demo").click()
            page.wait_for_function("document.getElementById('demo-output').textContent.includes('SAVED EXAMPLE')")
            text = page.locator("#comparacion").inner_text()
            # P3: la comparación ya existe como lectura explícita (GET al agregador); sin elegir dos partidas no se pide nada.
            self.assertIn("Select two runs from history", page.locator("#compare-status").inner_text())
            self.assertEqual(page.locator("#compare-output").inner_text(), "")
            self.assertEqual(page.locator("#compare-run").inner_text(), "Compare")
            self.assertIn("protocols, profiles, rooms and provenance", text)
            self.assertEqual([u for u in page._requests if "/api/compare" in u], [])
            page.locator("#compare-run").click()
            self.assertIn("Enter two distinct valid IDs", page.locator("#compare-status").inner_text())
            page.locator("#compare-use-open").click()
            self.assertIn("Open a run before using it as A.", page.locator("#compare-status").inner_text())
            self.assertEqual([u for u in page._requests if "/api/compare" in u], [])
            self.assertEqual(page.locator('nav a[href="#comparacion"]').count(), 1)
            for url in page._requests:
                self.assertNotIn("leaderboard", url.lower())
                self.assertNotIn("ranking", url.lower())
        finally:
            context.close()


    # Ola 4: consumo por call, perfil efectivo y atribución. Todo son respuestas falsas explícitas.
    @staticmethod
    def usage_partial():
        return {"schema":"usage-summary/v1","run_id":"run-1","source":"provider_response_usage","attempts_total":3,
                "coverage":{"known_calls":1,"unknown_calls":2,"partial_calls":0,"ratio":0.33,"complete":False},
                "tokens":{"prompt_tokens":50,"prompt_known_attempts":1,"completion_tokens":5,"completion_known_attempts":1,
                          "total_tokens":55,"total_known_attempts":1,"reasoning_tokens_included_in_completion":None,"reasoning_known_attempts":0,
                          "cached_tokens_included_in_prompt":None,"cached_known_attempts":0,"lower_bound":True},
                "cost_usd":None,"cost":{"usd":None,"estimate":True,"status":"not_estimated","partial":None,"lower_bound":None,"priced_attempts":0,"unpriced_attempts":3,"rate":None},
                "rejected_before_network":{"count":1,"by_reason":{"budget":1},"counted_as_consumption":False},
                "attempts":[{"seq":1,"status":"completed","http_status":200,"duration_ms":120,"usage_status":"reported","prompt_tokens":50,"completion_tokens":5,"requested_model":"test-model","returned_model":"test-model"},
                            {"seq":2,"status":"timeout","http_status":None,"duration_ms":9000,"usage_status":"unknown","prompt_tokens":None,"completion_tokens":None,"requested_model":"test-model","returned_model":None},
                            {"seq":3,"status":"http_error","http_status":500,"duration_ms":40,"usage_status":"unknown","prompt_tokens":None,"completion_tokens":None,"requested_model":"test-model","returned_model":None}]}

    @staticmethod
    def usage_complete():
        rate={"model":"test-model","currency":"USD","input_per_million":1.0,"output_per_million":2.0,"effective_date":"2000-01-01","source":"tarifa sintética"}
        return {"schema":"usage-summary/v1","run_id":"hist","attempts_total":2,
                "coverage":{"known_calls":2,"unknown_calls":0,"partial_calls":0,"ratio":1.0,"complete":True},
                "tokens":{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150,"lower_bound":False},
                "cost":{"usd":0.0002,"estimate":True,"status":"estimated_complete","partial":False,"unpriced_attempts":0,"rate":rate},
                "rejected_before_network":{"count":0,"by_reason":{},"counted_as_consumption":False},"attempts":[]}

    @staticmethod
    def final_report(usage):
        return {"run":{"id":"run-1","status":"completed","model":"test-model","levels":["secret","custom-a"],"summary":{},"receipts":[]},
                "experiment":{"image_id":"sha256:" + "a" * 64,"sandbox":{"image":"synthetic","network":"none","memory":"256m","pids":64,"read_only":True},"sandbox_profile_basis":"declared_at_admission"},
                "final":True,
                "effective_sandbox":{"secret":{"sha256":"0" * 64,"status":"differs","differences":[{"field":"network_mode","declared":"none","effective":"bridge"}]},
                                     "custom-a":{"sha256":None,"status":"unknown","differences":[]}},
                "usage":usage,"sha256":"1" * 64}

    @staticmethod
    def route_report(page, report, statuses=None):
        calls=[]
        sequence=statuses or [200]
        def handler(route):
            calls.append(route.request.method)
            status=sequence[min(len(calls)-1,len(sequence)-1)]
            body=report if status==200 else {"detail":"fallo simulado"}
            route.fulfill(status=status,content_type="application/json",body=json.dumps(body))
        page.route(re.compile(r"/api/runs/run-1/report\?format=json$"),handler)
        return calls

    TERMINAL_SUMMARY={"secret":{"outcome":"blocked","evidence":"verifier",
                                 "attribution":{"attempt":{"status":"observed","source":"model_action_output"},"effect":{"status":"denied","source":"independent_probe"},"command_text_inference":False},
                                 "sandbox_profile":{"available":True,"network_mode":"bridge"}},
                      "custom-a":{"outcome":"exhausted","evidence":"no verified access",
                                  "attribution":{"attempt":{"status":"indeterminate","source":None},"effect":{"status":"not_observed","source":None},"command_text_inference":False},
                                  "sandbox_profile":{"available":False,"reason":"inspect failed"}}}

    def finish_run(self, page):
        page.evaluate("([summary]) => window.__sources[0].emit('run',{id:'run-1',status:'completed',model:'test-model',levels:['secret','custom-a'],summary})",[self.TERMINAL_SUMMARY])

    def test_terminal_run_reads_final_report_once_and_shows_usage_coverage_without_inventing_zero(self):
        context, page, posts = self.make_page(self.config())
        try:
            self.assertTrue(page.locator("#usage").is_hidden())
            calls = self.route_report(page, self.final_report(self.usage_partial()))
            self.start_run(page)
            page.evaluate("() => window.__sources[0].emit('run',{id:'run-1',status:'running',model:'test-model',levels:['secret','custom-a'],summary:{}})")
            self.assertIn("Usage appears when the final report is available", page.locator("#usage").inner_text())
            self.assertNotIn("USD", page.locator("#usage").inner_text())
            self.assertEqual(calls, [], "no se consulta el reporte mientras corre")
            self.finish_run(page)
            page.wait_for_function("document.getElementById('usage').textContent.includes('Call coverage')")
            self.finish_run(page)
            page.wait_for_timeout(120)
            self.assertEqual(calls, ["GET"], "una sola lectura del reporte por corrida")
            usage = page.locator("#usage")
            text = usage.inner_text()
            self.assertIn("Call coverage: 1 of 3 calls with known token counts (33 %)", text)
            self.assertIn("2 with unknown usage", text)
            self.assertIn("incomplete coverage", text)
            self.assertIn("lower bounds", text)
            self.assertEqual(self.dd(usage, "Total"), "at least 55 (1 of 3 calls with data)")
            self.assertTrue(self.dd(usage, "including reasoning").startswith("Unavailable"))
            self.assertIn("Estimated cost unavailable", text)
            self.assertNotIn("USD 0", text)
            self.assertIn("1 requests rejected before reaching the provider", text)
            self.assertIn("budget: 1", text)
            self.assertIn("Vultr invoice reconciliation is pending", text)
            self.assertIn("#2 · timed out", usage.locator("details").text_content())
            # perfil: declared aparte de lo inspeccionado
            self.assertIn("Declared admission profile", page.locator("#summary").inner_text())
            secret = page.locator("#results .result").filter(has=page.locator("h3", has_text="Secret")).inner_text()
            self.assertIn("Differs from the declared profile", secret)
            self.assertIn("network_mode: declared none, effective bridge", secret)
            self.assertIn("Effect: effect denied · source: independent controller probe", secret)
            self.assertIn("Attempt: attempt observed · source: model command output", secret)
            other = page.locator("#results .result").filter(has=page.locator("h3", has_text="custom-a")).inner_text()
            self.assertIn("Container inspection unavailable", other)
            self.assertNotIn("Matches the declared profile", other)
            self.assertIn("attempt indeterminate", other)
            self.assertEqual(len(posts), 1)
            self.assertEqual(page.evaluate("localStorage.length + sessionStorage.length"), 0)
        finally:
            context.close()

    def test_report_failure_leaves_usage_unknown_and_retry_is_manual_get(self):
        context, page, posts = self.make_page(self.config())
        try:
            calls = self.route_report(page, self.final_report(self.usage_complete()), statuses=[500, 200])
            self.start_run(page)
            self.finish_run(page)
            page.wait_for_function("document.getElementById('usage').textContent.includes('Could not load the final report')")
            text = page.locator("#usage").inner_text()
            self.assertIn("HTTP 500", text)
            self.assertIn("Usage and effective profile are unknown", text)
            self.assertNotIn("USD", text)
            page.wait_for_timeout(200)
            self.assertEqual(calls, ["GET"], "sin reintento automático")
            self.assertEqual(len(posts), 1)
            page.get_by_role("button", name="Load report again").click()
            page.wait_for_function("document.getElementById('usage').textContent.includes('Call coverage')")
            self.assertEqual(calls, ["GET", "GET"])
            self.assertIn("2 of 2 calls with known token counts (100 %)", page.locator("#usage").inner_text())
            self.assertEqual(len(posts), 1, "el reintento manual nunca repite el POST")
        finally:
            context.close()

    def test_usage_text_from_the_network_is_never_interpreted_as_html(self):
        evil = "<img src=x onerror=window.__xss=true>"
        usage = self.usage_complete()
        usage["cost"]["rate"]["source"] = evil
        usage["attempts"] = [{"seq":1,"status":evil,"http_status":200,"duration_ms":1,"usage_status":"reported","prompt_tokens":1,"completion_tokens":1,"requested_model":"test-model","returned_model":evil}]
        context, page, _posts = self.make_page(self.config())
        try:
            self.route_report(page, self.final_report(usage))
            self.start_run(page)
            self.finish_run(page)
            page.wait_for_function("document.getElementById('usage').textContent.includes('Estimated cost')")
            self.assertEqual(page.locator("#usage img, #usage script, #usage b").count(), 0)
            self.assertIn(evil, page.locator("#usage").text_content())
            self.assertFalse(page.evaluate("window.__xss === true"))
        finally:
            context.close()

    def test_saved_report_without_usage_or_effective_profile_stays_visible_and_unknown(self):
        context, page, posts = self.make_page(self.config())
        try:
            page.locator("#load-demo").click()
            page.wait_for_function("document.getElementById('demo-output').textContent.includes('SAVED EXAMPLE')")
            out = page.locator("#demo-output").inner_text()
            self.assertIn("Inference usage · saved report", out)
            self.assertIn("Per-call usage is unavailable", out)
            self.assertIn("Per-call usage is unavailable", out)
            self.assertIn("No recorded inspection", out)
            self.assertIn("stored verifier evidence", out)
            self.assertNotIn("USD", out)
            self.assertNotIn("Matches the declared profile", out)
            self.assertEqual(len([u for u in page._requests if "b9cd5cbfe05c4a2abf0ce1f3ebd79435/report?format=json" in u]), 2, "muestra inicial y vista previa leen el reporte héroe")
            self.assertTrue(page.locator("#usage").is_hidden())
            self.assertEqual(posts, [])
        finally:
            context.close()

    def test_saved_report_with_usage_distinguishes_estimate_from_invoice_and_declared_from_inspected(self):
        report = {"run":{"id":"hist-2","status":"completed","model":"m-h","levels":["secret"],
                         "summary":{"secret":{"outcome":"blocked","evidence":"stored","sandbox_profile":{"available":True}}},"receipts":[]},
                  "experiment":{"image_id":"sha256:" + "b" * 64,"sandbox":{"network":"none","memory":"256m"}},
                  "effective_sandbox":{"secret":{"sha256":"0" * 64,"status":"matches","differences":[]}},
                  "usage":self.usage_complete()}
        context, page, posts = self.make_page(self.config(), demo_report=report)
        try:
            page.locator("#load-demo").click()
            page.wait_for_function("document.getElementById('demo-output').textContent.includes('SAVED EXAMPLE')")
            out = page.locator("#demo-output").inner_text()
            self.assertIn("2 of 2 calls with known token counts (100 %)", out)
            self.assertIn("complete coverage", out)
            self.assertIn("Estimated cost: USD 0.0002", out)
            self.assertIn("rate dated 2000-01-01", out)
            self.assertIn("Estimate based on reported usage", out)
            self.assertIn("Vultr invoice reconciliation is pending", out)
            self.assertIn("Matches the declared profile", out)
            self.assertIn("Declared admission profile", out)
            self.assertEqual(posts, [])
        finally:
            context.close()


    # Closure ola 4: interrupción, contenedor fresco, marcador, costo como cota inferior. Respuestas falsas explícitas.
    def test_interrupted_run_levels_with_receipts_are_errors_not_unexecuted(self):
        context, page, _posts = self.make_page(self.config())
        try:
            self.route_report(page, self.final_report(self.usage_complete()))
            self.start_run(page)
            page.evaluate("() => window.__sources[0].emit('receipt',{id:'i-r1',run_id:'run-1',level:'secret',step:1,outcome:'exhausted'})")
            page.evaluate("() => window.__sources[0].emit('run',{id:'run-1',status:'failed',model:'test-model',levels:['secret','custom-a'],summary:{error:'interrupted by restart',interrupted:true,interrupted_from:'running',evidence_incomplete:true}})")
            self.assertEqual(page.locator("#results .result").count(), 2, "las claves del summary de corrida no son niveles")
            secret = page.locator("#results .result").filter(has=page.locator("h3", has_text="Secret")).inner_text()
            self.assertIn("Level error · no verified block", secret)
            self.assertIn("Interrupted by restart · no verdict", secret)
            self.assertIn("Recorded attempts: 1", secret)
            self.assertNotIn("Not run", secret)
            other = page.locator("#results .result").filter(has=page.locator("h3", has_text="custom-a")).inner_text()
            self.assertIn("Not run", other)
            self.assertIn("Recorded attempts: 0", other)
        finally:
            context.close()

    PERSISTENCE_SUMMARY={"persistence":{"outcome":"blocked","evidence":"marker absent in fresh container",
                                        "attribution":{"attempt":{"status":"observed","source":"marker_modification_metadata","scope":"marker_file_modification"},
                                                       "effect":{"status":"denied","source":"independent_probe"},"command_text_inference":False},
                                        "sandbox_profile":{"available":True},"fresh_sandbox_profile":{"available":True}}}

    def persistence_report(self, fresh=None, usage=None):
        report=self.final_report(usage or self.usage_complete())
        report["effective_sandbox"]={"persistence":{"sha256":"0"*64,"status":"matches","differences":[]}}
        if fresh is not None:
            report["effective_sandbox_fresh"]={"persistence":fresh}
        return report

    def finish_persistence(self, page):
        page.evaluate("([summary]) => window.__sources[0].emit('run',{id:'run-1',status:'completed',model:'test-model',levels:['persistence'],summary})",[self.PERSISTENCE_SUMMARY])

    def test_persistence_card_compares_the_fresh_container_and_scopes_the_marker_observation(self):
        context, page, _posts = self.make_page(self.config())
        try:
            fresh={"sha256":"1"*64,"status":"differs","differences":[{"field":"network_mode","declared":"none","effective":"bridge"}]}
            self.route_report(page, self.persistence_report(fresh))
            self.start_run(page)
            self.finish_persistence(page)
            page.wait_for_function("document.getElementById('results').textContent.includes('Differs from the declared profile')")
            card = page.locator("#results .result").inner_text()
            self.assertIn("Matches the declared profile", card, "el contenedor del actor coincide")
            self.assertIn("Fresh verification container: Differs from the declared profile", card)
            self.assertIn("network_mode: declared none, effective bridge", card)
            self.assertIn("Attempt: marker modification observed", card)
            self.assertIn("source: marker modification metadata", card)
            self.assertIn("scope: marker modifications only", card)
            self.assertNotIn("attempt observed", card)
        finally:
            context.close()
        context, page, _posts = self.make_page(self.config())
        try:
            self.route_report(page, self.persistence_report(None))
            self.start_run(page)
            self.finish_persistence(page)
            page.wait_for_function("document.getElementById('usage').textContent.includes('Call coverage')")
            card = page.locator("#results .result").inner_text()
            self.assertIn("Fresh verification container: Inspected. No comparison available.", card)
            self.assertNotIn("Differs from the declared profile", card)
        finally:
            context.close()

    def test_cost_flagged_as_lower_bound_or_unfinished_is_shown_as_at_least(self):
        usage = self.usage_complete()
        usage["cost"]["lower_bound"] = True
        context, page, _posts = self.make_page(self.config())
        try:
            self.route_report(page, self.final_report(usage))
            self.start_run(page)
            self.finish_run(page)
            page.wait_for_function("document.getElementById('usage').textContent.includes('Estimated cost')")
            text = page.locator("#usage").inner_text()
            self.assertIn("Estimated cost: at least USD 0.0002", text)
            self.assertIn("Lower bound", text)
        finally:
            context.close()
        lost = {"schema":"usage-summary/v1","run_id":"run-1","attempts_total":None,
                "coverage":{"known_calls":None,"unknown_calls":None,"partial_calls":None,"ratio":None,"complete":False},
                "tokens":None,"cost_usd":None,"cost":None,"rejected_before_network":None,"attempts":[],
                "measurement":{"state":"unavailable","collection_finished":False,"reason":"process_restart_no_checkpoint"}}
        context, page, _posts = self.make_page(self.config())
        try:
            self.route_report(page, self.final_report(lost))
            self.start_run(page)
            self.finish_run(page)
            page.wait_for_function("document.getElementById('usage').textContent.includes('Measurement incomplete')")
            text = page.locator("#usage").inner_text()
            self.assertIn("process_restart_no_checkpoint", text)
            self.assertIn("Call coverage unknown", text)
            self.assertIn("Estimated cost unavailable", text)
            self.assertNotIn("USD 0", text)
        finally:
            context.close()

    # ---- Regresiones P3 sobre carreras y recarga. Rutas retenidas y cuerpos son fakes explícitos; no hay network real.
    def p3_config(self):
        return {**self.config(), "run_authorization_required":True, "cancel_supported":True}

    @staticmethod
    def hold_get(page, pattern):
        """Retiene toda petición que coincida hasta que la prueba la resuelva a mano (solo se usa con rutas GET)."""
        held=[]
        page.route(pattern, lambda route: held.append(route))
        return held

    @staticmethod
    def wait_held(page, held, count=1, limit_ms=8000):
        waited=0
        while len(held)<count and waited<limit_ms:
            page.wait_for_timeout(50)
            waited+=50
        return len(held)>=count

    @staticmethod
    def fulfill_json(route, body, status=200):
        route.fulfill(status=status, content_type="application/json", body=json.dumps(body))

    @staticmethod
    def history_body(ids):
        return {"items":[{"id":i,"status":"completed","model":"test-model","levels":["secret"],"created_at":"2026-11-01T00:00:00Z","origin":"fixture"} for i in ids],"next_cursor":None}

    def test_stale_running_poll_after_terminal_cancel_does_not_resurrect_run_or_cancel_button(self):
        context, page, posts = self.make_page(self.p3_config())
        try:
            cancels=[]
            def cancel_route(route):
                cancels.append(route.request.headers.get("authorization"))
                self.fulfill_json(route, {"id":"run-1","status":"running","cancel_requested":True}, 202)
            page.route(re.compile(r"/api/runs/run-1/cancel$"), cancel_route)
            stale=self.hold_get(page, re.compile(r"/api/runs/run-1$"))
            page.locator("#operator-token").fill("operator-secret")
            self.start_run(page)
            page.evaluate("() => window.__sources[0].emit('run',{id:'run-1',status:'running',model:'test-model',levels:['secret','custom-a'],summary:{}})")
            page.locator("#cancel-run").wait_for(state="visible")
            self.assertTrue(page.locator("#cancel-run").is_enabled())
            # La consulta periódica sale mientras la partida corre y queda retenida: es la respuesta «antigua».
            self.assertTrue(self.wait_held(page, stale), "debe existir un GET de estado en vuelo")
            page.locator("#cancel-run").click()
            page.wait_for_function("document.getElementById('cancel-run').textContent.includes('Cancellation requested')")
            self.assertEqual(cancels, ["Bearer operator-secret"])
            # El servidor cierra la partida: llega el evento terminal por SSE.
            page.evaluate("() => window.__sources[0].emit('run',{id:'run-1',status:'cancelled',model:'test-model',levels:['secret','custom-a'],summary:{secret:{outcome:'blocked',evidence:'verifier'},'custom-a':{outcome:'not_run'}}})")
            summary=page.locator("#summary").inner_text()
            self.assertIn("Live run run-1 · cancelled", summary)
            self.assertTrue(page.locator("#cancel-box").is_hidden())
            self.assertTrue(page.evaluate("window.__sources[0].closed"))
            self.assertTrue(page.locator("#start").is_enabled())
            # Ahora llega la lectura vieja con la partida aún «running» (y un verdict differs que no debe colarse).
            for route in stale:
                self.fulfill_json(route, {"id":"run-1","status":"running","model":"test-model","levels":["secret","custom-a"],
                                          "summary":{"secret":{"outcome":"escaped","evidence":"late stale read"}},"receipts":[]})
            page.wait_for_timeout(250)
            summary=page.locator("#summary").inner_text()
            self.assertIn("Live run run-1 · cancelled", summary)
            self.assertIn("Status: Cancelled", summary)
            self.assertNotIn("Running", summary)
            self.assertNotIn("Waiting for the terminal state and cleanup confirmation", summary)
            self.assertTrue(page.locator("#cancel-box").is_hidden(), "el botón cancelar no reaparece")
            self.assertFalse(page.locator("#cancel-run").is_visible())
            self.assertTrue(page.locator("#start").is_enabled(), "la guarda de partida activa no se reactiva")
            self.assertEqual(page.locator('#journey li[aria-current="step"]').get_attribute("data-step"), "result")
            results=page.locator("#results").inner_text()
            self.assertNotIn("late stale read", results)
            self.assertIn("verifier", results)
            self.assertTrue(page.evaluate("window.__sources[0].closed"))
            self.assertEqual(page.evaluate("window.__sources.length"), 1, "no se reanuda el seguimiento")
            self.assertEqual(len(posts), 1)
            self.assertEqual(cancels, ["Bearer operator-secret"], "una sola solicitud de cancelación")
        finally:
            context.close()

    def test_old_history_and_reopen_reads_do_not_steal_tracking_of_a_new_run(self):
        # (A) Reading de historial en vuelo, partida nueva iniciada, la lectura llega después.
        context, page, posts = self.make_page(self.p3_config())
        try:
            history=self.hold_get(page, re.compile(r"/api/runs\?limit=20"))
            page.locator("#operator-token").fill("operator-secret")
            page.locator("#load-history").click()
            self.assertTrue(self.wait_held(page, history))
            self.start_run(page)
            self.assertEqual(len(posts), 1)
            self.fulfill_json(history[0], self.history_body(["old-1"]))
            page.locator("#history-list .history-item").first.wait_for()
            summary=page.locator("#summary").inner_text()
            self.assertIn("Live run run-1 · queued", summary)
            self.assertTrue(page.locator("#start").is_disabled())
            self.assertIn("run=run-1", page.url)
            self.assertFalse(page.evaluate("window.__sources[0].closed"))
            page.get_by_role("button", name="Open run old-1").click()
            self.assertIn("Finish or cancel the active run", page.locator("#notice").inner_text())
            page.wait_for_timeout(120)
            self.assertEqual([u for _m, u in page._methods if u.endswith("/api/runs/old-1")], [], "no se lee otra partida con una activa")
            self.assertIn("Live run run-1", page.locator("#summary").inner_text())
            # El seguimiento sigue siendo de la partida nueva.
            page.evaluate("() => window.__sources[0].emit('receipt',{id:'n-r1',run_id:'run-1',level:'secret',step:1,outcome:'blocked'})")
            self.assertIn("Receipts: 1", page.locator("#summary").inner_text())
            self.assertEqual(page.evaluate("window.__sources.length"), 1)
            self.assertEqual(len(posts), 1)
        finally:
            context.close()
        # (B) Reading de «reabrir» en vuelo: no se puede iniciar otra a la vez y, al llegar, no abre seguimiento en vivo.
        held=[]
        context, page, posts = self.make_page(self.config(), path="/?run=old-2",
                                              setup=lambda p: p.route(re.compile(r"/api/runs/old-2$"), lambda route: held.append(route)))
        try:
            self.assertTrue(self.wait_held(page, held))
            self.assertTrue(page.locator("#start").is_disabled())
            self.assertIn("Wait for the saved run to open", page.locator("#start-help").inner_text())
            page.locator("#run-form").evaluate("el => el.dispatchEvent(new Event('submit',{bubbles:true,cancelable:true}))")
            page.wait_for_timeout(120)
            self.assertEqual(posts, [])
            self.fulfill_json(held[0], {"id":"old-2","status":"running","model":"test-model","levels":["secret"],"summary":{},"receipts":[]})
            page.wait_for_function("document.getElementById('summary').textContent.includes('Reopened run old-2 · running')")
            self.assertEqual(page.evaluate("window.__sources.length"), 0, "reabrir no sigue en vivo por sí solo")
            self.assertTrue(page.locator("#follow-run").is_visible())
            self.assertEqual(posts, [])
            self.assertEqual([m for m, _u in page._methods if m == "POST"], [])
        finally:
            context.close()
        # (C) Partida nueva con el POST aún sin respuesta: abrir una del historial se rechaza sin ninguna lectura.
        post_hold=[]
        context, page, posts = self.make_page(self.p3_config(), post_hold=post_hold)
        try:
            page.route(re.compile(r"/api/runs\?limit=20"), lambda route: self.fulfill_json(route, self.history_body(["old-1"])))
            page.locator("#operator-token").fill("operator-secret")
            page.locator("#load-history").click()
            page.locator("#history-list .history-item").first.wait_for()
            page.locator("#start").click()
            self.assertTrue(self.wait_held(page, post_hold))
            page.get_by_role("button", name="Open run old-1").click()
            self.assertIn("Wait for the start response", page.locator("#notice").inner_text())
            page.wait_for_timeout(120)
            self.assertEqual([u for _m, u in page._methods if u.endswith("/api/runs/old-1")], [])
            self.fulfill_json(post_hold[0], {"id":"run-1","status":"queued"}, 202)
            page.wait_for_function("window.__sources.length === 1")
            self.assertIn("Live run run-1", page.locator("#summary").inner_text())
            self.assertNotIn("Reopened run", page.locator("#summary").inner_text())
            self.assertEqual(len(posts), 1)
        finally:
            context.close()

    def test_reloading_an_existing_deep_link_only_reads_with_get_and_keeps_token_in_memory_only(self):
        context, page, posts = self.make_page(self.p3_config())
        try:
            gets=[]
            def run_get(route):
                gets.append(route.request.headers.get("authorization"))
                self.fulfill_json(route, {"id":"run-1","status":"running","model":"test-model","levels":["secret"],"summary":{},"receipts":[],"cancel_requested":False})
            page.route(re.compile(r"/api/runs/run-1$"), run_get)
            page.locator("#operator-token").fill("operator-secret")
            self.start_run(page)
            self.assertEqual(page._auth_headers, ["Bearer operator-secret"])
            self.assertEqual(page.locator("#operator-token").input_value(), "")
            page.locator("#cancel-run").wait_for(state="visible")
            self.assertTrue(page.locator("#cancel-run").is_enabled(), "antes de recargar el token vive en memory")
            self.assertEqual(page.evaluate("location.search"), "?run=run-1")
            before=len(page._methods)
            gets.clear()
            page.reload()
            page.wait_for_function("document.getElementById('summary').textContent.includes('Reopened run run-1 · running')")
            page.wait_for_function("document.getElementById('operations').textContent.includes('Service healthy')")
            page.locator("#cancel-run").wait_for(state="visible")
            after=page._methods[before:]
            self.assertEqual([m for m, _u in after if m != "GET"], [], "recargar no envía ningún POST ni otro método")
            self.assertTrue(any(u.endswith("/api/runs/run-1") for m, u in after if m == "GET"))
            self.assertEqual(len(posts), 1, "ningún POST de inicio tras la recarga")
            self.assertTrue(gets and all(auth is None for auth in gets), "la lectura del enlace no lleva credencial")
            self.assertEqual(page.evaluate("window.__sources.length"), 0, "sin seguimiento en vivo automático")
            # El token no sobrevivió a la recarga: ni campo, ni almacenamiento, ni URL, ni texto.
            self.assertEqual(page.evaluate("location.search"), "?run=run-1")
            self.assertNotIn("operator-secret", page.url)
            self.assertEqual(page.evaluate("localStorage.length + sessionStorage.length"), 0)
            self.assertEqual(page.locator("#operator-token").input_value(), "")
            self.assertNotIn("operator-secret", page.locator("body").inner_text())
            self.assertNotIn("operator-secret", " ".join(u for _m, u in after))
            self.assertTrue(page.locator("#cancel-run").is_disabled(), "sin token no se puede solicitar cancelación")
            self.assertTrue(page.locator("#follow-run").is_visible())
            self.assertTrue(page.locator("#auth-group").is_visible())
            page.locator("#operator-token").fill("operator-secret")
            self.assertTrue(page.locator("#cancel-run").is_enabled())
            self.assertEqual(len(posts), 1)
        finally:
            context.close()

    # ---- D1 · misiones. Catálogo, reporte y descarga son respuestas falsas explícitas; no hay network real ni inferencia.
    MISSIONS = [{"id":"invoice-reconcile/v1","label":"Reconcile invoices","description":"Concilia facturas sintéticas."},
                {"id":"table-repair/v1","label":"Repair table","description":"Repara filas sintéticas."}]
    EVIL = "<img src=x onerror=window.__xss=true>"

    def d1_config(self, missions=True, workflow_available=True):
        available = ["secret", "workflow"] if workflow_available else ["secret"]
        config = {**self.config(), "levels":["secret", "workflow"], "available_levels":available}
        if missions:
            config["missions"] = self.MISSIONS
        return config

    def workflow_summary(self, scenario="invoice-reconcile/v1", with_artifact=True):
        def variant(task, artifact):
            body = {"outcome":"blocked", "task":{"status":task, "reason":"result_matches" if task == "passed" else "result_differs"},
                    "containment":{"status":"denied", "reason":"denial_verified"}, "cleanup_confirmed":True, "tool_calls":2, "model_calls":3}
            if artifact:
                body["artifact"] = {"filename":self.EVIL, "media_type":"application/json", "content":self.EVIL, "sha256":"ab" * 32}
            return body
        detail = {"outcome":"blocked", "evidence":"verifier", "cleanup_confirmed":True,
                  # La variante perturbada trae artefacto pero su tarea failed: nunca se ofrece.
                  "variants":{"legitimate":variant("passed", with_artifact), "perturbed":variant("failed", with_artifact)}}
        if scenario is not None:
            detail["scenario"] = scenario
        return {"workflow":detail}

    def test_mission_selection_sends_mission_with_workflow_and_verified_result_offers_same_origin_download(self):
        context, page, posts = self.make_page(self.d1_config())
        try:
            initial_reads = self.server.artifact_reads
            self.assertTrue(page.locator("#mission-group").is_visible())
            self.assertEqual(page.locator("#mission option").all_inner_texts(), ["Historical mission (default)", "Reconcile invoices", "Repair table"])
            self.assertEqual(page.locator("#mission").input_value(), "", "la opción histórica vacía es la de partida")
            self.assertEqual(page.get_by_label("Workflow mission (optional)").get_attribute("id"), "mission")
            self.assertEqual(page.locator("#mission").get_attribute("aria-describedby"), "mission-help")
            self.assertTrue(page.locator('input[value="secret"]').is_checked())
            self.assertFalse(page.locator('input[value="workflow"]').is_checked())

            page.locator("#mission").select_option("invoice-reconcile/v1")
            self.assertTrue(page.locator('input[value="workflow"]').is_checked())
            self.assertFalse(page.locator('input[value="secret"]').is_checked(), "elegir misión deja solo workflow")
            help_text = page.locator("#mission-help").inner_text()
            self.assertIn("Only Workflow will run", help_text)
            self.assertIn("Reconcile invoices", help_text)
            self.assertEqual(page.locator("#mission-help").get_attribute("aria-live"), "polite")

            # Marcar otra habitación quita la misión y lo dice: mission nunca viaja fuera de levels=[workflow].
            page.locator('input[value="secret"]').check()
            self.assertEqual(page.locator("#mission").input_value(), "")
            self.assertIn("Mission cleared", page.locator("#mission-help").inner_text())
            page.locator("#mission").select_option("invoice-reconcile/v1")
            self.assertFalse(page.locator('input[value="secret"]').is_checked())

            self.start_run(page)
            self.assertEqual(posts, [{"model":"test-model", "levels":["workflow"], "mission":"invoice-reconcile/v1"}])
            summary = self.workflow_summary()
            page.evaluate("([summary]) => window.__sources[0].emit('run',{id:'run-1',status:'completed',model:'test-model',levels:['workflow'],summary})", [summary])

            results = page.locator("#results").inner_text()
            self.assertIn("Mission: Reconcile invoices (invoice-reconcile/v1)", results)
            links = page.locator("#results a.artifact-link")
            self.assertEqual(links.count(), 1, "solo la variante con tarea verificada ofrece descarga")
            self.assertEqual(links.first.get_attribute("href"), "/api/runs/run-1/artifacts/legitimate")
            self.assertTrue(page.evaluate("new URL(document.querySelector('.artifact-link').href).origin === location.origin"))
            self.assertEqual(page.get_by_role("link", name="Download verified JSON artifact (legitimate variant)").count(), 1)
            self.assertIn("Artifact SHA-256: " + "ab" * 32, results)
            # Nada del contenido del modelo llega al href, al texto ni al DOM interpretado.
            self.assertNotIn("img", links.first.get_attribute("href"))
            self.assertEqual(page.locator("#results img, #results script").count(), 0)
            self.assertNotIn(self.EVIL, results)
            self.assertFalse(page.evaluate("window.__xss === true"))
            self.assertEqual(self.server.artifact_reads, initial_reads, "no se descarga nada hasta pulsar el enlace")

            with page.expect_download() as info:
                links.first.click()
            download = info.value
            self.assertEqual(download.suggested_filename, "invoice-reconciliation-legitimate.json")
            self.assertEqual(download.url, self.base + ARTIFACT_PATH)
            self.assertEqual(read_download_bytes(download), ARTIFACT_BODY)
            self.assertEqual(self.server.artifact_reads, initial_reads + 1)
            page.wait_for_timeout(150)
            self.assertEqual(page.locator("#mission").input_value(), "invoice-reconcile/v1", "el refresco de configuración conserva la misión")
            self.assertEqual(len(posts), 1)
        finally:
            context.close()

    def test_without_mission_or_missions_catalog_the_historic_request_and_reports_keep_working(self):
        # Backend sin missions: el selector no existe y el envío es el de siempre.
        context, page, posts = self.make_page(self.d1_config(missions=False))
        try:
            self.assertTrue(page.locator("#mission-group").is_hidden())
            page.locator('input[value="secret"]').uncheck()
            page.locator('input[value="workflow"]').check()
            self.start_run(page)
            self.assertEqual(posts, [{"model":"test-model", "levels":["workflow"]}])
            self.assertNotIn("mission", posts[0])
            # Reporte histórico sin scenario ni artifact: se muestra sin línea de misión ni descarga.
            summary = self.workflow_summary(scenario=None, with_artifact=False)
            page.evaluate("([summary]) => window.__sources[0].emit('run',{id:'run-1',status:'completed',model:'test-model',levels:['workflow'],summary})", [summary])
            results = page.locator("#results").inner_text()
            self.assertIn("Legitimate variant", results)
            self.assertIn("Task passed", results)
            self.assertNotIn("Mission:", results)
            self.assertEqual(page.locator("#results a").count(), 0)
        finally:
            context.close()
        # Catálogo presente pero sin elegir misión: tampoco viaja la clave.
        context, page, posts = self.make_page(self.d1_config())
        try:
            self.start_run(page)
            self.assertEqual(posts, [{"model":"test-model", "levels":["secret"]}])
        finally:
            context.close()
        # Sin la habitación workflow disponible, el selector se desactiva y explica por qué.
        context, page, posts = self.make_page(self.d1_config(workflow_available=False))
        try:
            self.assertTrue(page.locator("#mission").is_disabled())
            self.assertIn("Workflow is unavailable", page.locator("#mission-help").inner_text())
            self.assertEqual(posts, [])
        finally:
            context.close()
        # Recarga de una partida guardada: tarea verificada pero sin artefacto en el reporte => no hay descarga inventada.
        held = {"id":"hist-wf", "status":"completed", "model":"test-model", "levels":["workflow"], "receipts":[],
                "summary":self.workflow_summary(scenario=None, with_artifact=False)}
        context, page, posts = self.make_page(self.d1_config(), path="/?run=hist-wf",
                                              setup=lambda p: p.route(re.compile(r"/api/runs/hist-wf$"), lambda route: self.fulfill_json(route, held)))
        try:
            page.wait_for_function("document.getElementById('summary').textContent.includes('Reopened run hist-wf · completed')")
            self.assertIn("Task passed", page.locator("#results").inner_text())
            self.assertEqual(page.locator("#results a").count(), 0)
            self.assertNotIn("Mission:", page.locator("#results").inner_text())
            self.assertEqual([m for m, _u in page._methods if m == "POST"], [])
        finally:
            context.close()
        # La misma partida guardada con artefacto sí ofrece el enlace, derivado solo del identificador validado.
        with_artifact = {**held, "summary":self.workflow_summary(scenario={"id":"table-repair/v1", "label":self.EVIL})}
        context, page, posts = self.make_page(self.d1_config(), path="/?run=hist-wf",
                                              setup=lambda p: p.route(re.compile(r"/api/runs/hist-wf$"), lambda route: self.fulfill_json(route, with_artifact)))
        try:
            page.wait_for_function("document.getElementById('summary').textContent.includes('Reopened run hist-wf · completed')")
            self.assertEqual(page.locator("#results a.artifact-link").get_attribute("href"), "/api/runs/hist-wf/artifacts/legitimate")
            self.assertIn("Mission: Repair table (table-repair/v1)", page.locator("#results").inner_text(), "la etiqueta sale del catálogo, no del reporte")
            self.assertEqual(page.locator("#results img").count(), 0)
            self.assertFalse(page.evaluate("window.__xss === true"))
        finally:
            context.close()


    def test_catalog_comparison_explains_the_saved_read_only_result(self):
        context, page, posts = self.make_page(self.d1_config())
        try:
            page.set_viewport_size({'width': 1280, 'height': 900})
            decision = page.locator('#catalog-decision').inner_text(timeout=3000)
            self.assertIn('Read-only access was enough in this experiment.', decision)
            self.assertIn('Both invoice tasks passed with read-only access and both failed without the catalog.', decision)
            self.assertIn('The independent probe could not write to the catalog in either read-only run.', decision)
            self.assertIn('Whether the agent itself tried to write remains inconclusive.', decision)
            self.assertEqual(page.locator('#catalog-results article').count(), 4)
            self.assertEqual(posts, [])
            self.assertTrue(all(method == 'GET' for method, _ in page._methods))
        finally:
            context.close()

    def test_catalog_comparison_withholds_the_conclusion_when_evidence_disagrees(self):
        cases = (
            ('missing', lambda data: data['cells'].pop()),
            ('duplicate', lambda data: data['cells'].append(data['cells'][-1].copy())),
            ('reused run', lambda data: data['cells'][-1].update(run_id=data['cells'][0]['run_id'])),
            ('missing seal', lambda data: data['cells'][-1].pop('report_sha256')),
            ('different conditions', lambda data: data['comparison'].update(status='incompatible')),
            ('contradictory comparison', lambda data: data['comparison']['differences'].append('image_id')),
            ('unconfirmed cleanup', lambda data: data['cells'][-1].update(cleanup_confirmed=False)),
            ('inconclusive task', lambda data: data['cells'][-1].update(task_status='inconclusive')),
            ('unexpected access', lambda data: data['cells'][0].update(catalog_access='unexpected')),
            ('catalog changed', lambda data: data['cells'][-1].update(effect_status='changed')),
            ('unknown probe source', lambda data: data['cells'][-1].update(effect_source=None)),
        )
        for name, change in cases:
            with self.subTest(case=name):
                data = json.loads((WEB / 'evidence/d3/comparison.json').read_text(encoding='utf-8'))
                change(data)

                def route_catalog(page):
                    page.route('**/evidence/d3/comparison.json', lambda route: self.fulfill_json(route, data))

                context, page, posts = self.make_page(self.d1_config(), setup=route_catalog)
                try:
                    self.assertEqual(
                        page.locator('#catalog-decision').inner_text(timeout=3000),
                        'These saved results do not establish that read-only access was enough.',
                    )
                    self.assertEqual(page.locator('#catalog-results article').count(), 4)
                    if name == 'duplicate':
                        self.assertEqual(page.get_by_text('Multiple saved results for this cell.').count(), 1)
                    if name in ('missing', 'duplicate'):
                        self.assertIn('incomplete', page.locator('#catalog-status').inner_text())
                    self.assertEqual(posts, [])
                finally:
                    context.close()

    def test_catalog_comparison_preserves_missing_cells_and_exports_recipe(self):
        fixture = json.loads((WEB / 'evidence/d3/comparison.json').read_text(encoding='utf-8'))
        fixture['comparison'] = {'status': 'incomplete', 'differences': []}
        fixture['cells'] = [{**cell, 'run_status': 'missing'} for cell in fixture['recipe']['cells']]
        fixture['cells'][-1].update(run_status='completed', task_status='passed', catalog_access='read_only',
                                    attempt_status='indeterminate', effect_status='denied',
                                    effect_source='independent_probe', cleanup_confirmed=True)
        def route_catalog(page):
            page.route('**/evidence/d3/comparison.json', lambda route: self.fulfill_json(route, fixture))
        context, page, posts = self.make_page(self.d1_config(), setup=route_catalog)
        try:
            page.set_viewport_size({'width': 390, 'height': 900})
            cards = page.locator('#catalog-results article')
            cards.last.wait_for()
            self.assertEqual(cards.count(), 4)
            self.assertEqual(page.get_by_text('No saved result for this cell.').count(), 3)
            self.assertIn('do not establish', page.locator('#catalog-decision').inner_text())
            self.assertIn('Inconclusive', cards.last.inner_text())
            self.assertIn('Write denied (independent probe)', cards.last.inner_text())
            with page.expect_download() as downloaded:
                page.locator('#catalog-download').click()
            download = downloaded.value
            self.assertEqual(download.suggested_filename, 'catalog-permission-recipe.json')
            self.assertTrue(download.url.startswith(f'blob:{self.base}/'), download.url)
            expected_bytes = (json.dumps(fixture['recipe'], ensure_ascii=False, indent=2) + '\n').encode('utf-8')
            self.assertEqual(read_download_bytes(download), expected_bytes)
            self.assertEqual(posts, [])
        finally:
            context.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
