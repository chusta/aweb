#!/usr/bin/env python3
import argparse
import asyncio
import base64
import collections
import email.utils
import hashlib
import logging
import os
import random
import ssl
import string
import sys
import tempfile

import magic
import OpenSSL


log = logging.getLogger("aweb")


def random_string(n):
    return "".join([random.choice(string.ascii_uppercase) for _ in range(n)])


def certificate():
    cert = OpenSSL.SSL.X509()
    x509 = cert.get_subject()
    x509.C = random_string(2)
    x509.L = random_string(10)
    x509.O = random_string(10)
    x509.ST = random_string(10)
    x509.OU = random_string(10)
    x509.CN = random_string(10)
    pkey = OpenSSL.crypto.PKey()
    pkey.generate_key(OpenSSL.crypto.TYPE_RSA, 4096)
    cert.set_issuer(x509)
    cert.set_pubkey(pkey)
    cert.sign(pkey, "sha256")

    year = 31536000
    before = random.randint(-year, 0)
    cert.set_serial_number(random.randint(0, 1000))
    cert.gmtime_adj_notBefore(before)
    cert.gmtime_adj_notAfter(before + 2 * year)

    pem = OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
    key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, pkey)
    temp = tempfile.NamedTemporaryFile(mode="a+b", prefix="crt_", suffix=".pem")
    temp.write(key+pem)
    temp.seek(0)
    return temp


def parse_b64(path):
    if path and path.startswith("/?b="):
        p = path.split("?b=")
        try:
            data = base64.b64decode(p[-1]).strip().decode()
            log.info(f"[B64] {data}")
            return data
        except Exception as e:
            log.error(f"[!] base64 decode error - {e}")


class Http(object):
    server = "Apache"
    protocol = "HTTP/1.1"
    status = {200: "OK"}
    timeout = 30

    def __init__(self, reader, writer, loop, data=b""):
        self.data = data
        self.loop = loop
        self.reader = reader
        self.writer = writer
        self.transport = writer.transport

    async def __call__(self):
        try:
            line = await self.reader.readline()
            headers = await self._get_headers()

            verb, path, proto = [x.decode() for x in line.split() if x]
            log.info(f"[+] {self.peer} - {verb} {path}")
            coro = getattr(self, f"handle_{verb}", None)
            if coro and proto == self.protocol:
                output = await coro(path=path, headers=headers)
            else:
                output = await self.send_response(500)
        except Exception as e:
            log.warning(f"[-] {self.peer} - {line.decode()}")
            output = await self.send_response(500)
        finally:
            self.transport.close()
        return output

    async def _get_headers(self):
        lines = await self.reader.readuntil(b"\r\n\r\n")
        lines = lines.strip().decode().split("\r\n")
        headers = {}
        for line in lines:
            k, v = line.split(":", 1)
            headers[k.lower()] = v.strip()
        return headers

    async def _write(self, response):
        self.writer.write(response)
        await self.writer.drain()

    def _response_header(self, data=b"", **kw):
        header = collections.OrderedDict([
            ("Server", self.server),
            ("Date", email.utils.formatdate(usegmt=True)),
            ("Content-Length", "0"),
            ("Content-Type", "text/html")
        ])
        size = len(data)
        if size:
            header["Content-Length"] = str(size)
        for k, v in kw.items():
            header[k] = v
        return header

    async def send_response(self, code, data=b"", **kw):
        if isinstance(data, str):
            data = data.encode()

        header = self._response_header(data, **kw)
        try:
            status = self.status[code]
        except KeyError:
            code, status = 500, "Internal Server Error"

        response = bytearray(f"{self.protocol} {code} {status}\r\n".encode())
        for kv in header.items():
            response += "{}: {}\r\n".format(*kv).encode()

        if data:
            response += b"\r\n"
            response += data
        await self._write(response)
        return response

    @property
    def peer(self):
        info = self.transport.get_extra_info("peername")
        return "{}:{}".format(*info)

    def _save(self, path, data):
        name = os.path.basename(path)[:16]
        if not name:
            name = "data"
        filename = f"{name}.{hashlib.md5(data).hexdigest()}"
        filepath = os.path.join(os.path.abspath("."), filename)
        with open(filepath, "wb") as fp:
            fp.write(data)
        return filename

    def _mime(self, data):
        m = magic.Magic(mime=True).from_buffer(data)
        if m == "text/plain":
            m = "text/html"
        return m

    async def handle_GET(self, path, headers):
        parse_b64(path)
        if self.data:
            kw = collections.OrderedDict()
            kw["Content-Length"] = len(self.data)
            try:
                kw["Content-Type"] = self._mime(self.data)
            except Exception:
                log.debug("[-] Unable to identify MIME type")
            response = await self.send_response(200, data=self.data, **kw)
        else:
            response = await self.send_response(200)
        return response

    async def handle_PUT(self, path, headers):
        size = int(headers["content-length"])
        data = await self.reader.read(size)
        name = await self.loop.run_in_executor(None, self._save, path, data)
        response = await self.send_response(200)
        log.info(f"[PUT] {name}")
        return response


class Server(object):
    def __init__(self, handler, host, port, loop, data=b"", context=None):
        self.handler = handler
        self.context = context
        self.loop = loop

        self.server = None
        self.data = data
        self.host = host
        self.port = port

        self.requests = 0

    async def _connection_cb(self, reader, writer):
        self.requests += 1
        session = self.handler(reader, writer, self.loop, self.data)
        return await session()

    def start(self):
        if self.server is not None:
            return False
        proto = "https" if self.context else "http"
        info = f"{proto}://{self.host}:{self.port}"
        log.info(info)
        try:
            coro = asyncio.start_server(
                client_connected_cb = self._connection_cb,
                host = self.host,
                port = self.port,
                ssl = self.context,
                loop = self.loop,
            )
            self.server = self.loop.run_until_complete(coro)
            self.loop.run_forever()
        except Exception as e:
            log.warning(f"[!] {e}")
        self.stop()
        return info

    def stop(self):
        if self.server is None:
            return False
        self.server.close()
        self.loop.stop()
        self.loop.close()


def main():     # pragma: no cover
    args = _args()
    loop = asyncio.get_event_loop()

    if args.data:
        data = args.data
    elif args.file:
        with open(args.file, "rb") as fp:
            data = fp.read()
    else:
        data = bytes()

    ctx = None
    crt = None
    if args.ssl:
        crt = certificate()
        ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ctx.load_cert_chain(crt.name)

    server = Server(
        handler = Http,
        data = data,
        host = args.addr,
        port = args.port,
        loop = loop,
        context = ctx
    )
    try:
        server.start()
    except KeyboardInterrupt:
        pass

    server.stop()
    if crt:
        crt.close()

def _args():    # pragma: no cover
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", help="input file")
    parser.add_argument("-d", "--data", help="input data")
    parser.add_argument("-a", "--addr", default="0.0.0.0")
    parser.add_argument("-p", "--port", default=8080, type=int)
    parser.add_argument("--ssl", action="store_true")
    args = parser.parse_args()
    if not sys.stdin.isatty():
        args.data = sys.stdin.buffer.read()
    return args


if __name__ == "__main__":  # pragma: no cover
    main()
