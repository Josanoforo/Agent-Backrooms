"""Bound incoming POST bodies before validation or inference admission."""
import asyncio
from starlette.responses import JSONResponse


MAX_BODY_BYTES = 16384


class RequestLimitMiddleware:
    def __init__(self, app, max_bytes=MAX_BODY_BYTES):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http' or scope.get('method') != 'POST':
            return await self.app(scope, receive, send)
        maximum = 2 * 1024 * 1024 if scope.get('path') == '/api/observations' else self.max_bytes
        # Preserve the previous observation upload throughput allowance: the
        # body ceiling grew 8x (256 KiB -> 2 MiB), so its finite read window does too.
        body_timeout = 80 if scope.get('path') == '/api/observations' else 10
        async def reject(status, detail):
            await JSONResponse({'detail': detail}, status_code=status)(scope, receive, send)
        headers = dict(scope.get('headers', []))
        try:
            length = int(headers.get(b'content-length', b'0'))
            if length < 0: raise ValueError()
        except ValueError:
            return await reject(400, 'Invalid content length')
        if length > maximum:
            return await reject(413, 'Request body exceeds route limit')
        body = bytearray()
        try:
            async with asyncio.timeout(body_timeout):
                while True:
                    message = await receive()
                    if message['type'] == 'http.disconnect': return
                    chunk = message.get('body', b'')
                    if len(body) + len(chunk) > maximum:
                        return await reject(413, 'Request body exceeds route limit')
                    body.extend(chunk)
                    if not message.get('more_body'): break
        except TimeoutError:
            return await reject(408, 'Request body timed out')
        delivered = False
        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
            return await receive()
        await self.app(scope, replay, send)
