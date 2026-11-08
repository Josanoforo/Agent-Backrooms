import asyncio
from services.agent.request_limits import RequestLimitMiddleware


def test_chunked_body_is_rejected_before_app():
    calls = []
    sent = []
    async def app(*args): calls.append(True)
    chunks = iter([{'type':'http.request', 'body':b'a'*10000,'more_body':True},
                   {'type':'http.request', 'body':b'b'*7000,'more_body':False}])
    async def receive(): return next(chunks)
    async def send(message): sent.append(message)
    asyncio.run(RequestLimitMiddleware(app)({'type':'http','method':'POST','headers':[]},receive,send))
    assert not calls and sent[0]['status'] == 413


def test_declared_oversize_rejected_without_reading():
    sent = []
    async def app(*args): raise AssertionError('app should not be called')
    async def receive(): raise AssertionError('body should not be read')
    async def send(message): sent.append(message)
    asyncio.run(RequestLimitMiddleware(app)({'type':'http','method':'POST','headers':[(b'content-length',b'17000')]},receive,send))
    assert sent[0]['status'] == 413
