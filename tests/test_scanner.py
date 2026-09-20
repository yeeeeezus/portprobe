"""Tests for the scan engine against real local servers."""

import asyncio
import socket
import unittest

from portprobe.scanner import probe, scan, classify_connect_error


def free_port() -> int:
    """Grab an ephemeral port that is (almost certainly) unbound."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


async def start_banner_server(banner: bytes) -> asyncio.AbstractServer:
    async def handler(reader, writer):
        writer.write(banner)
        await writer.drain()
        writer.close()

    return await asyncio.start_server(handler, "127.0.0.1", 0)


class ProbeTests(unittest.IsolatedAsyncioTestCase):
    async def test_open_port_with_banner(self):
        server = await start_banner_server(b"PORTPROBE-TEST-SERVER v1.0\r\n")
        port = server.sockets[0].getsockname()[1]
        try:
            result = await probe("127.0.0.1", port, timeout=2.0)
        finally:
            server.close()
            await server.wait_closed()
        self.assertEqual(result["port"], port)
        self.assertEqual(result["state"], "open")
        self.assertTrue(result["banner"].startswith("PORTPROBE-TEST-SERVER"))

    async def test_open_port_silent(self):
        async def handler(reader, writer):
            writer.close()

        server = await asyncio.start_server(handler, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        try:
            result = await probe("127.0.0.1", port, timeout=2.0)
        finally:
            server.close()
            await server.wait_closed()
        self.assertEqual(result["state"], "open")
        self.assertEqual(result["banner"], "")

    async def test_closed_port(self):
        port = free_port()
        result = await probe("127.0.0.1", port, timeout=2.0)
        self.assertEqual(result["state"], "closed")

    async def test_unroutable_address_is_filtered(self):
        # TEST-NET-3 (RFC 5737) — guaranteed to not answer.
        result = await probe("203.0.113.1", 81, timeout=0.4)
        self.assertEqual(result["state"], "filtered")


class ScanTests(unittest.IsolatedAsyncioTestCase):
    async def test_scan_mixed_ports(self):
        server = await start_banner_server(b"MIXED-TEST\r\n")
        open_port = server.sockets[0].getsockname()[1]
        closed_port = free_port()
        try:
            results = await scan(
                "127.0.0.1",
                [open_port, closed_port],
                timeout=2.0,
                concurrency=2,
            )
        finally:
            server.close()
            await server.wait_closed()

        self.assertEqual(len(results), 2)
        by_port = {r["port"]: r for r in results}
        self.assertEqual(by_port[closed_port]["state"], "closed")
        self.assertEqual(by_port[open_port]["state"], "open")
        self.assertEqual(by_port[open_port]["banner"], "MIXED-TEST")

    async def test_concurrency_cap(self):
        # 24 probes through a semaphore of 8 complete without deadlock.
        server = await start_banner_server(b"C\r\n")
        open_port = server.sockets[0].getsockname()[1]
        try:
            ports = [open_port] * 1 + [free_port() for _ in range(23)]
            results = await scan(
                "127.0.0.1", ports, timeout=2.0, concurrency=8
            )
        finally:
            server.close()
            await server.wait_closed()
        self.assertEqual(len(results), 24)
        self.assertEqual(sum(1 for r in results if r["state"] == "open"), 1)


class ClassifyTests(unittest.TestCase):
    def test_refused_is_closed(self):
        self.assertEqual(classify_connect_error(ConnectionRefusedError()), "closed")

    def test_timeout_is_filtered(self):
        self.assertEqual(classify_connect_error(TimeoutError()), "filtered")

    def test_oserror_is_filtered(self):
        self.assertEqual(classify_connect_error(OSError("no route")), "filtered")


if __name__ == "__main__":
    unittest.main()
