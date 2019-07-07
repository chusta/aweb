import asyncio
import base64
import io
import os
import unittest
from unittest import mock

import OpenSSL.crypto

import aweb.aweb as aweb


class TestWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # md5(TEST)
        cls.EXPECT_MD5SUM = "033bd94b1168d7e4f0d644c3c95e35bf"
        cls.EXPECT_BASE64 = base64.b64encode(b"TEST").decode()
        cls.BASE_PATH = os.path.abspath(".")

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.http = self._http()

    def tearDown(self):
        self.loop.close()
        del self.http

    def _read(self, req, hdr, dat):
        reader = mock.MagicMock()
        reader.readline.return_value = asyncio.Future()
        reader.readline.return_value.set_result(req)
        reader.readuntil.return_value = asyncio.Future()
        reader.readuntil.return_value.set_result(hdr)
        reader.read.return_value = asyncio.Future()
        reader.read.return_value.set_result(dat)
        return reader

    def _http(self):
        reader = self._read(
            req = b"TEST /test/path PROTO/9.9",
            hdr = b"Host: test.test\r\nUser-Agent: curl\r\nAccept: *.*\r\n\r\n",
            dat = b"TEST"
        )
        writer = mock.MagicMock()
        writer.transport.get_extra_info.return_value = ("1.2.3.4", 1234)
        writer.drain.return_value = asyncio.Future()
        writer.drain.return_value.set_result(None)

        http = aweb.Http(
            reader = reader,
            writer = writer,
            loop = self.loop
        )

        http.data = b"TEST"
        http.server = "TestServer"
        return http

    @unittest.mock.patch("random.choice")
    def test_random_string(self, mock_random):
        """Test aweb random string"""
        mock_random.return_value = "A"
        for i in [ 1, 2, 10 ]:
            self.assertEqual("A"*i, aweb.random_string(i))

    @unittest.mock.patch("tempfile.NamedTemporaryFile")
    @unittest.mock.patch("random.randint")
    @unittest.mock.patch("random.choice")
    def test_certificate(self, m_choice, m_int, m_tmp):
        """Test aweb certificate"""
        m_choice.return_value = "A"
        m_int.return_value = 0
        m_tmp.return_value = io.BytesIO()

        bio = aweb.certificate()
        dat = bio.read()

        cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, dat)
        x509 = cert.get_subject()
        self.assertEqual(x509.C, "A"*2)
        self.assertEqual(x509.L, "A"*10)
        self.assertEqual(x509.O, "A"*10)
        self.assertEqual(x509.ST, "A"*10)
        self.assertEqual(x509.OU, "A"*10)
        self.assertEqual(x509.CN, "A"*10)
        self.assertEqual(cert.get_serial_number(), 0)

    def test_http_peer(self):
        """Test aweb Http peer"""
        self.assertEqual("1.2.3.4:1234", self.http.peer)

    def test_http_base64_path(self):
        """Test aweb Http base64 path"""
        has_path = f"/?b={self.EXPECT_BASE64}"
        self.assertEqual("TEST", aweb.parse_b64(has_path))

    def test_http_base64_no_path(self):
        """Test aweb Http base64 no path"""
        self.assertIsNone(aweb.parse_b64(self.EXPECT_BASE64))

    def test_http_base64_decode_error(self):
        """Test aweb Http base64 decode error"""
        self.assertIsNone(aweb.parse_b64("/?b=TEST"))

    def test_http_response_header(self):
        """Test aweb Http response header"""
        expect = {
            "Server": "TestServer",
            "Date": "123",
            "Content-Length": "0",
            "Content-Type": "text/html"
        }
        no_data = self.http._response_header(data=b"", Date="123")
        self.assertDictEqual(no_data, expect)

        expect["Content-Length"] = "4"
        kw = {"data": b"TEST", "Date": "123"}
        has_data = self.http._response_header(**kw)
        self.assertDictEqual(has_data, expect)

        expect["A"] = "1"
        expect["B"] = "2"
        kw = {"data": b"TEST", "A": "1", "B": "2", "Date": "123"}
        kw_data = self.http._response_header(**kw)
        self.assertDictEqual(kw_data, expect)

    def test_http_send_response_200(self):
        """Test aweb Http response 200"""
        coro = self.http.send_response(code=200, data=b"", Date="123")
        actual = self.loop.run_until_complete(coro)
        expect = "HTTP/1.1 200 OK\r\n"
        expect += "Server: TestServer\r\n"
        expect += "Date: 123\r\n"
        expect += "Content-Length: 0\r\n"
        expect += "Content-Type: text/html\r\n"
        self.assertEqual(actual, expect.encode())

        coro = self.http.send_response(code=200, data=b"TEST", Date="123")
        actual = self.loop.run_until_complete(coro)
        expect = "HTTP/1.1 200 OK\r\n"
        expect += "Server: TestServer\r\n"
        expect += "Date: 123\r\n"
        expect += "Content-Length: 4\r\n"
        expect += "Content-Type: text/html\r\n\r\nTEST"
        self.assertEqual(actual, expect.encode())

        coro = self.http.send_response(code=200, data="TEST", Date="123")
        actual = self.loop.run_until_complete(coro)
        self.assertEqual(actual, expect.encode())

    def test_http_send_response_500(self):
        """Test aweb Http response 500"""
        coro = self.http.send_response(code=100, data=b"", Date="123")
        actual = self.loop.run_until_complete(coro)
        expect = "HTTP/1.1 500 Internal Server Error\r\n"
        expect += "Server: TestServer\r\n"
        expect += "Date: 123\r\n"
        expect += "Content-Length: 0\r\n"
        expect += "Content-Type: text/html\r\n"
        self.assertEqual(actual, expect.encode())

        coro = self.http.send_response(code=100, data=b"TEST", Date="123")
        actual = self.loop.run_until_complete(coro)
        expect = "HTTP/1.1 500 Internal Server Error\r\n"
        expect += "Server: TestServer\r\n"
        expect += "Date: 123\r\n"
        expect += "Content-Length: 4\r\n"
        expect += "Content-Type: text/html\r\n\r\nTEST"
        self.assertEqual(actual, expect.encode())

        coro = self.http.send_response(code=100, data="TEST", Date="123")
        actual = self.loop.run_until_complete(coro)
        self.assertEqual(actual, expect.encode())

    def test_http_get_headers(self):
        """Test aweb Http get headers"""
        coro = self.http._get_headers()
        actual = self.loop.run_until_complete(coro)
        expect = {"host": "test.test", "user-agent": "curl", "accept": "*.*"}
        self.assertDictEqual(actual, expect)

    def test_http_mime_text_html(self):
        """Test aweb Http mime text/html"""
        actual = self.http._mime(b"<html>TEST</html>")
        self.assertEqual("text/html", actual)

        actual = self.http._mime(b"TEST")
        self.assertEqual("text/html", actual)

    @mock.patch("email.utils.formatdate")
    def test_http_handle_get_data(self, mock_date):
        """Test aweb Http handle GET data"""
        mock_date.return_value = "123"
        coro = self.http.handle_GET("/test", {})
        actual = self.loop.run_until_complete(coro)

        expect = "HTTP/1.1 200 OK\r\n"
        expect += "Server: TestServer\r\n"
        expect += "Date: 123\r\n"
        expect += "Content-Length: 4\r\n"
        expect += "Content-Type: text/html\r\n\r\nTEST"
        self.assertEqual(actual, expect.encode())

    @mock.patch("email.utils.formatdate")
    def test_http_handle_get_no_data(self, mock_date):
        """Test aweb Http handle GET no data"""
        mock_date.return_value = "123"
        self.http.data = b""
        coro = self.http.handle_GET("/test", {})
        actual = self.loop.run_until_complete(coro)

        expect = "HTTP/1.1 200 OK\r\n"
        expect += "Server: TestServer\r\n"
        expect += "Date: 123\r\n"
        expect += "Content-Length: 0\r\n"
        expect += "Content-Type: text/html\r\n"
        self.assertEqual(actual, expect.encode())

    @mock.patch("email.utils.formatdate")
    def test_http_handle_get_error(self, mock_date):
        """Test aweb Http handle GET error"""
        def _mime(data): raise Exception()
        self.http._mime = _mime
        mock_date.return_value = "123"
        coro = self.http.handle_GET("/test", {})
        actual = self.loop.run_until_complete(coro)

        expect = "HTTP/1.1 200 OK\r\n"
        expect += "Server: TestServer\r\n"
        expect += "Date: 123\r\n"
        expect += "Content-Length: 4\r\n"
        expect += "Content-Type: text/html\r\n\r\nTEST"
        self.assertEqual(actual, expect.encode())

    @mock.patch("builtins.open")
    def test_http_save_path_none(self, mock_open):
        """Test aweb Http save path none"""
        path = "/path/" + "A"*0
        name_hash = self.http._save(path, self.http.data)
        name, hash = name_hash.split(".")
        self.assertEqual(hash, self.EXPECT_MD5SUM)
        self.assertEqual(name, "data")

        n = f"data.{self.EXPECT_MD5SUM}"
        c = mock.call(os.path.join(self.BASE_PATH, n), "wb")
        self.assertTrue(c in mock_open.call_args_list)

    @mock.patch("builtins.open")
    def test_http_save_path_long(self, mock_open):
        """Test aweb Http save path long"""
        path = "/path/" + "A"*17
        name_hash = self.http._save(path, self.http.data)
        name, hash = name_hash.split(".")
        self.assertEqual(hash, self.EXPECT_MD5SUM)
        self.assertEqual(name, "A"*16)

        n = "{}.{}".format("A"*16, self.EXPECT_MD5SUM)
        c = mock.call(os.path.join(self.BASE_PATH, n), "wb")
        self.assertTrue(c in mock_open.call_args_list)

    @mock.patch("builtins.open")
    @mock.patch("email.utils.formatdate")
    def test_http_handle_put(self, mock_date, mock_open):
        """Test aweb Http handle PUT"""
        mock_date.return_value = "123"
        _save = mock.MagicMock()
        _save.return_value = "data"
        self.http._save = _save

        header = {"content-length": len(self.http.data)}
        coro = self.http.handle_PUT("/path/name", header)
        actual = self.loop.run_until_complete(coro)

        c = mock.call("/path/name", b"TEST")
        self.assertTrue(c in self.http._save.call_args_list)

        expect = "HTTP/1.1 200 OK\r\n"
        expect += "Server: TestServer\r\n"
        expect += "Date: 123\r\n"
        expect += "Content-Length: 0\r\n"
        expect += "Content-Type: text/html\r\n"
        self.assertEqual(actual, expect.encode())

    @mock.patch("email.utils.formatdate")
    def test_http_call_proto_mismatch(self, mock_date):
        """Test aweb Http call protocol mismatch"""
        mock_date.return_value = "123"
        async def test(self, path, headers): return path, headers
        setattr(self.http, "handle_TEST", test)
        coro = self.http()
        actual = self.loop.run_until_complete(coro)

        expect = "HTTP/1.1 500 Internal Server Error\r\n"
        expect += "Server: TestServer\r\n"
        expect += "Date: 123\r\n"
        expect += "Content-Length: 0\r\n"
        expect += "Content-Type: text/html\r\n"
        self.assertEqual(actual, expect.encode())

    @mock.patch("email.utils.formatdate")
    def test_http_call_proto_match(self, mock_date):
        """Test aweb Http call protocol match"""
        mock_date.return_value = "123"
        self.http.protocol = "PROTO/9.9"
        async def test(path, headers): return path, headers
        setattr(self.http, "handle_TEST", test)
        coro = self.http()
        path, header = self.loop.run_until_complete(coro)

        self.assertEqual(path, "/test/path")
        expect = {"host": "test.test", "user-agent": "curl", "accept": "*.*"}
        self.assertDictEqual(header, expect)

    @mock.patch("email.utils.formatdate")
    def test_http_call_parse_error(self, mock_date):
        """Test aweb Http call parse error"""
        mock_date.return_value = "123"
        self.http.reader = self._read(
            req = b"TEST TEST TEST TEST",
            hdr = b"Host: test.test\r\nUser-Agent: curl\r\nAccept: *.*\r\n\r\n",
            dat = b"TEST"
        )
        coro = self.http()
        actual = self.loop.run_until_complete(coro)
        expect = "HTTP/1.1 500 Internal Server Error\r\n"
        expect += "Server: TestServer\r\n"
        expect += "Date: 123\r\n"
        expect += "Content-Length: 0\r\n"
        expect += "Content-Type: text/html\r\n"
        self.assertEqual(actual, expect.encode())
