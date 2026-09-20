"""Tests for CLI behavior and the top-ports table."""

import io
import json
import socket
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

from portprobe.cli import main, parse_ports, resolve_host, _clean_banner
from portprobe.topports import TOP_PORTS, SERVICE_NAMES, top_ports, service_name


class ParsePortsTests(unittest.TestCase):
    def test_simple_list(self):
        self.assertEqual(parse_ports("80,443,8080"), [80, 443, 8080])

    def test_range(self):
        self.assertEqual(parse_ports("2000-2002"), [2000, 2001, 2002])

    def test_mixed(self):
        self.assertEqual(
            parse_ports("80, 443,9000-9002"), [80, 443, 9000, 9001, 9002]
        )

    def test_dedupes_and_sorts(self):
        self.assertEqual(parse_ports("443,80,443,80"), [80, 443])

    def test_reversed_range(self):
        self.assertEqual(parse_ports("2010-2008"), [2008, 2009, 2010])

    def test_rejects_garbage(self):
        for bad in ["abc", "0", "70000", "80-", "-443", ""]:
            with self.assertRaises(ValueError, msg=bad):
                parse_ports(bad)

    def test_rejects_out_of_range(self):
        with self.assertRaises(ValueError):
            parse_ports("99999")


class ResolveHostTests(unittest.TestCase):
    def test_passthrough_ipv4(self):
        self.assertEqual(resolve_host("127.0.0.1"), "127.0.0.1")

    def test_resolves_localhost(self):
        self.assertEqual(resolve_host("localhost"), "127.0.0.1")

    def test_rejects_unknown_host(self):
        with self.assertRaises(ValueError):
            resolve_host("definitely-not-a-real-host.invalid")


class TopPortsTests(unittest.TestCase):
    def test_exactly_100(self):
        self.assertEqual(len(TOP_PORTS), 100)

    def test_unique_and_bounded(self):
        self.assertEqual(len(set(TOP_PORTS)), 100)
        self.assertTrue(all(1 <= p <= 65535 for p in TOP_PORTS))

    def test_top_ports_clamp(self):
        self.assertEqual(top_ports(5), TOP_PORTS[:5])
        self.assertEqual(top_ports(0), [])
        self.assertEqual(top_ports(9999), TOP_PORTS)

    def test_known_services(self):
        self.assertEqual(service_name(22), "ssh")
        self.assertEqual(service_name(443), "https")
        self.assertEqual(service_name(6379), "redis")
        self.assertEqual(service_name(65534), "-")

    def test_web_first(self):
        self.assertEqual(TOP_PORTS[0], 80)
        self.assertIn(443, TOP_PORTS[:5])


class CleanBannerTests(unittest.TestCase):
    def test_collapses_whitespace(self):
        self.assertEqual(_clean_banner("SSH-2.0-OpenSSH\r\n\r\n"), "SSH-2.0-OpenSSH")

    def test_truncates_long(self):
        out = _clean_banner("A" * 100)
        self.assertEqual(len(out), 60)
        self.assertTrue(out.endswith("..."))


class CliTests(unittest.TestCase):
    def _free_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_bad_host_returns_2(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["definitely-not-a-real-host.invalid", "--top", "5"])
        self.assertEqual(code, 2)

    def test_bad_ports_returns_2(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(["127.0.0.1", "--ports", "notaport"])
        self.assertEqual(code, 2)

    def test_json_output_shape(self):
        closed = self._free_port()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                ["127.0.0.1", "--ports", str(closed), "--json", "--all"]
            )
        self.assertEqual(code, 0)
        payload = json.loads(buf.getvalue())
        self.assertEqual(payload["host"], "127.0.0.1")
        self.assertEqual(payload["resolved"], "127.0.0.1")
        self.assertEqual(payload["scanned"], 1)
        self.assertEqual(payload["summary"]["open"], 0)
        self.assertEqual(payload["ports"][0]["state"], "closed")
        self.assertIn("service", payload["ports"][0])

    def test_open_only_default(self):
        closed = self._free_port()
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(
                ["127.0.0.1", "--ports", str(closed)]
            )
        self.assertEqual(code, 0)
        # open-only default: nothing to show, but a valid table still prints
        self.assertIn("portprobe", buf.getvalue())

    def test_usage_row_rendering(self):
        closed = self._free_port()
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["127.0.0.1", "--ports", str(closed), "--all"])
        out = buf.getvalue()
        self.assertIn("PORT", out)
        self.assertIn("closed", out)


if __name__ == "__main__":
    unittest.main()
