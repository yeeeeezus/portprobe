"""Command-line interface for portprobe."""

import argparse
import asyncio
import json
import socket
import sys

from .scanner import scan
from .topports import SERVICE_NAMES, TOP_PORTS, top_ports
from . import __version__

BANNER_TRUNC = 60


def parse_ports(spec: str) -> list:
    """Parse a ports spec like ``80,443,2000-2010`` into a sorted unique list."""
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo_s, _, hi_s = part.partition("-")
            try:
                lo, hi = int(lo_s), int(hi_s)
            except ValueError:
                raise ValueError(f"invalid range: {part!r}")
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise ValueError(f"range out of bounds: {part!r}")
            if lo > hi:
                lo, hi = hi, lo
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(part)
            except ValueError:
                raise ValueError(f"invalid port: {part!r}")
            if not (1 <= p <= 65535):
                raise ValueError(f"port out of bounds: {part!r}")
            ports.add(p)
    if not ports:
        raise ValueError("empty ports spec")
    return sorted(ports)


def resolve_host(host: str) -> str:
    """Resolve a hostname to an address; pass through bare IPs."""
    try:
        socket.inet_aton(host)
        return host
    except OSError:
        pass
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        raise ValueError(f"cannot resolve host: {host}")


def _clean_banner(banner: str) -> str:
    collapsed = " ".join(banner.split())
    if len(collapsed) > BANNER_TRUNC:
        collapsed = collapsed[: BANNER_TRUNC - 3] + "..."
    return collapsed


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="portprobe",
        description=(
            "Zero-dependency async TCP port scanner. "
            "Grabs banners from open ports; classifies closed and filtered."
        ),
    )
    parser.add_argument("host", help="hostname or IP address to scan")
    parser.add_argument(
        "--ports",
        help="port spec, e.g. 80,443,2000-2010 (overrides --top)",
    )
    parser.add_argument(
        "--top",
        type=int,
        default=100,
        metavar="N",
        help="probe the first N ports of the built-in top-%d list (default: 100)"
        % len(TOP_PORTS),
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        metavar="SEC",
        help="connect timeout in seconds (default: 1.0)",
    )
    parser.add_argument(
        "--banner-timeout",
        type=float,
        default=0.75,
        metavar="SEC",
        help="max wait for a banner on open ports (default: 0.75)",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=400,
        metavar="N",
        help="parallel probes in flight (default: 400)",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit machine-readable JSON"
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="include closed and filtered ports in output (default: open only)",
    )
    parser.add_argument(
        "--version", action="version", version=f"portprobe {__version__}"
    )
    return parser


def render_table(host: str, results: list) -> str:
    lines = []
    lines.append(f"portprobe {__version__} — {host}")
    lines.append("")
    lines.append(f"{'PORT':<7}{'STATE':<10}{'SERVICE':<22}BANNER")
    for r in results:
        banner = _clean_banner(r.get("banner", ""))
        service = SERVICE_NAMES.get(r["port"], "-")
        lines.append(
            f"{r['port']:<7}{r['state']:<10}{service:<22}{banner}"
        )
    open_n = sum(1 for r in results if r["state"] == "open")
    lines.append("")
    lines.append(f"{open_n} open of {len(results)} shown")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    try:
        host = resolve_host(args.host)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if args.ports:
        try:
            ports = parse_ports(args.ports)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    else:
        ports = top_ports(args.top)

    results = asyncio.run(
        scan(
            host,
            ports,
            timeout=args.timeout,
            banner_timeout=args.banner_timeout,
            concurrency=args.concurrency,
        )
    )

    if not args.all:
        results = [r for r in results if r["state"] == "open"]

    if args.json:
        open_n = sum(1 for r in results if r["state"] == "open")
        payload = {
            "host": args.host,
            "resolved": host,
            "scanned": len(ports),
            "summary": {
                "open": open_n,
                "shown": len(results),
            },
            "ports": [
                {
                    "port": r["port"],
                    "state": r["state"],
                    "service": SERVICE_NAMES.get(r["port"], "-"),
                    "banner": r.get("banner", ""),
                }
                for r in results
            ],
        }
        print(json.dumps(payload, indent=2))
    else:
        print(render_table(host, results))
    return 0


if __name__ == "__main__":
    sys.exit(main())
