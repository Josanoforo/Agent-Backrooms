"""Read-only browser interaction, HTTP responses mocked; no room or provider."""
import functools
import json
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading

from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[2]


def test_loading_success_and_error_are_visible_next_to_consult_button(tmp_path):
    handler=functools.partial(SimpleHTTPRequestHandler,directory=str(ROOT/'apps/web'))
    server=ThreadingHTTPServer(('127.0.0.1',0),handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    data={'source':'operator_import_local_docker_not_attested','run_id':'a'*32,
          'trace':{'cleanup_confirmed':True,'events':[]},'interpretation':None,
          'review':{'execution_location':{'client':'PC Windows','model':'Ollama local',
                    'tools':'VM Vultr','transport':'SSH stdio'},
                    'platform_result':{'text':'Comportamiento inconcluso por presupuesto del operador; archivo ausente por separado.','event_ids':[]}}}
    try:
        with sync_playwright() as p:
            browser=p.chromium.launch(headless=True)
            page=browser.new_page()
            requests=[]
            def respond(route):
                requests.append(route.request.method)
                if route.request.headers.get('authorization')!='Bearer test-operator':
                    route.fulfill(status=401,json={'detail':'Unauthorized'})
                else:route.fulfill(json=data)
            page.route('**/api/observations/*',respond)
            page.goto(f'http://127.0.0.1:{server.server_port}/connect.html?observation='+data['run_id'])
            page.wait_for_function("document.querySelector('#load-status').textContent.includes('HTTP 401')")
            assert page.locator('#load-status').is_visible()
            assert page.locator('#load-status').get_attribute('role')=='status'
            assert not page.locator('#load').is_disabled()
            page.fill('#token','test-operator')
            # Intercept the next GET and hold it long enough to observe real UI
            # pending state without sleeping or making a paid request.
            page.unroute('**/api/observations/*')
            held=[]
            page.route('**/api/observations/*',lambda route:held.append(route))
            page.click('#load')
            page.wait_for_function("document.querySelector('#load').disabled")
            assert page.locator('#load').inner_text()=='Consultando…'
            assert 'Cargando' in page.locator('#load-status').inner_text()
            assert page.locator('#resultado').get_attribute('aria-busy')=='true'
            assert len(held)==1
            requests.append(held[0].request.method);held[0].fulfill(json=data)
            page.wait_for_function("document.querySelector('#load-status').textContent.includes('cargado.')")
            assert not page.locator('#load').is_disabled()
            assert page.locator('#resultado').get_attribute('aria-busy')=='false'
            assert 'herramientas VM Vultr' in page.locator('#scope').text_content()
            assert 'ORIGEN NO ATESTADO POR LA IMPORTACIÓN' in page.locator('#source').inner_text()
            assert 'Cliente y cuarto: equipo local' not in page.locator('#scope').text_content()
            assert 'Comportamiento inconcluso' in page.locator('#verdict').text_content()
            assert 'aclaración de operador' in page.locator('#explanation').text_content()
            page.unroute('**/api/observations/*')
            page.route('**/api/observations/*',lambda r:r.abort('failed'))
            page.click('#load')
            page.wait_for_function("document.querySelector('#load-status').textContent.includes('resultado anterior sigue visible')")
            assert not page.locator('#load').is_disabled()
            assert requests==['GET','GET']
            browser.close()
    finally:
        server.shutdown();server.server_close();thread.join(timeout=3)
