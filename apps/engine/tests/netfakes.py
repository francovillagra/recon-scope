"""Piezas para probar la guarda de red sin salir a Internet: un servidor TCP local que cuenta conexiones y un
backend de red falso que sirve respuestas HTTP fijas y anota a qué dirección se le pidió conectarse."""
import asyncio

import httpcore

OK_PAGE = b"<title>hi</title>"
OK_RESPONSE = (
    b"HTTP/1.1 200 OK\r\nServer: lab/1.0\r\nContent-Type: text/html\r\n"
    + b"Content-Length: " + str(len(OK_PAGE)).encode() + b"\r\nConnection: close\r\n\r\n" + OK_PAGE
)


def redirect_response(location: str) -> bytes:
    return (
        b"HTTP/1.1 302 Found\r\nServer: lab/1.0\r\nLocation: " + location.encode()
        + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )


class LocalServer:
    """Servidor en 127.0.0.1 que responde HTTP o manda un banner, y cuenta cuántas conexiones recibió.

    `connections` sube apenas se acepta la conexión, antes de leer nada: si queda en 0, el motor ni siquiera abrió el socket."""

    def __init__(self, reply: bytes = OK_RESPONSE, banner: bytes = b"") -> None:
        self.reply, self.banner = reply, banner
        self.connections = 0
        self.requests: list[bytes] = []
        self.port = 0
        self._server: asyncio.AbstractServer | None = None

    async def __aenter__(self) -> "LocalServer":
        self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self._server.sockets[0].getsockname()[1]
        return self

    async def __aexit__(self, *exc) -> None:
        self._server.close()
        await self._server.wait_closed()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            if self.banner:
                writer.write(self.banner)
                await writer.drain()
            else:
                self.requests.append(await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2))
                writer.write(self.reply)
                await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()


class FakeStream(httpcore.AsyncNetworkStream):
    def __init__(self, response: bytes) -> None:
        self._response = response
        self.written = b""

    async def read(self, max_bytes, timeout=None):
        data, self._response = self._response[:max_bytes], self._response[max_bytes:]
        return data

    async def write(self, buffer, timeout=None):
        self.written += bytes(buffer)

    async def aclose(self):
        pass

    async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
        raise NotImplementedError("las pruebas usan http://")

    def get_extra_info(self, info):
        return None


class FakeBackend(httpcore.AsyncNetworkBackend):
    """Reemplaza al backend real de httpcore: no abre sockets. `responses` va por dirección IP de destino."""

    def __init__(self, responses: dict[str, bytes] | None = None, default: bytes = OK_RESPONSE) -> None:
        self.responses, self.default = responses or {}, default
        self.calls: list[tuple[str, int]] = []
        self.streams: list[FakeStream] = []

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        self.calls.append((host, port))
        stream = FakeStream(self.responses.get(host, self.default))
        self.streams.append(stream)
        return stream

    async def connect_unix_socket(self, path, timeout=None, socket_options=None):
        raise NotImplementedError

    async def sleep(self, seconds):
        await asyncio.sleep(seconds)


def fake_dns(monkeypatch, table: dict[str, list[str]], counter: list | None = None):
    """Reemplaza la resolución del sistema por una tabla nombre -> direcciones. `counter` anota cada consulta."""
    from app.recon import netguard

    async def lookup(host, port):
        if counter is not None:
            counter.append(host)
        if host not in table:
            import socket

            raise socket.gaierror(socket.EAI_NONAME, "unknown host")
        return list(table[host])

    monkeypatch.setattr(netguard, "_lookup", lookup)
