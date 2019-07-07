import asyncio
import unittest
from unittest import mock

import OpenSSL.crypto

import aweb.aweb as aweb


class TestServer(unittest.TestCase):

    def setUp(self):
        self.loop = asyncio.new_event_loop()
        self.server = self._server()

    def tearDown(self):
        self.loop.close()
        del self.server

    def _server(self):
        def test_handler(r, w, l, d):
            async def session(): return (r, w, l, d)
            return session

        return aweb.Server(
            handler = test_handler,
            host = "1.2.3.4",
            port = "1234",
            loop = self.loop,
            data = b"TEST",
            context = None
        )

    def test_server_connection(self):
        """Test aweb Server connection"""
        coro = self.server._connection_cb("READER", "WRITER")
        reader, writer, loop, data = self.loop.run_until_complete(coro)
        self.assertEqual(reader, "READER")
        self.assertEqual(writer, "WRITER")
        self.assertEqual(loop, self.loop)
        self.assertEqual(data, b"TEST")

    def test_server_connection_counter(self):
        """Test aweb Server connection counter"""
        self.assertEqual(self.server.requests, 0)
        self.loop.run_until_complete(self.server._connection_cb("R", "W"))
        self.assertEqual(self.server.requests, 1)
        self.loop.run_until_complete(self.server._connection_cb("R", "W"))
        self.assertEqual(self.server.requests, 2)

    @mock.patch("asyncio.start_server")
    def test_server_start_http(self, mock_server):
        """Test aweb Server start http"""
        mock_server.return_value = asyncio.Future()
        mock_server.return_value.set_result("SERVER")
        self.server.loop = mock.MagicMock()
        actual = self.server.start()
        self.assertEqual(actual, "http://1.2.3.4:1234")

    @mock.patch("asyncio.start_server")
    def test_server_start_https(self, mock_server):
        """Test aweb Server start https"""
        mock_server.return_value = asyncio.Future()
        mock_server.return_value.set_result("SERVER")
        self.server.loop = mock.MagicMock()
        self.server.context = True
        actual = self.server.start()
        self.assertEqual(actual, "https://1.2.3.4:1234")

    def test_server_start_again(self):
        """Test aweb Server start again"""
        self.server.server = True
        self.assertFalse(self.server.start())

    def test_server_stop(self):
        """Test aweb Server stop"""
        self.server.server = mock.MagicMock()
        self.server.loop = mock.MagicMock()
        self.server.stop()

        self.server.server.close.assert_called_once()
        self.server.loop.close.assert_called_once()

    def test_server_stop_again(self):
        """Test aweb Server stop again"""
        self.server.server = None
        self.assertFalse(self.server.stop())
