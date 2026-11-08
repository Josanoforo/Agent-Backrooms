from fastapi.testclient import TestClient
from services.agent import main


def test_web_and_api_share_application(tmp_path, monkeypatch):
    monkeypatch.setattr(main, 'DB', str(tmp_path / 'integration.sqlite3'))
    monkeypatch.delenv('VULTR_INFERENCE_KEY', raising=False)
    with TestClient(main.app) as client:
        for path, content_type in [('/', 'text/html'), ('/app.js', 'javascript'), ('/contract.js', 'javascript'),
                                   ('/app.css', 'text/css')]:
            response = client.get(path)
            assert response.status_code == 200
            assert content_type in response.headers['content-type']
        config = client.get('/api/config')
        assert config.status_code == 200
        assert config.json()['configured'] is False
        assert client.get('/api/runs/absent').status_code == 404
        assert client.get('/tablero/').status_code == 404
        assert client.post('/api/runs', json={'model': 'unconfigured', 'levels': ['secret']}).status_code == 503
