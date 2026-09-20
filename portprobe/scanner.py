"""Async TCP port scan engine.

A port is probed by opening a TCP connection with a bounded timeout and,
on success, attempting a short banner read. Results are classified:

- ``open``     — connection accepted (banner, if any, captured)
- ``closed``   — connection refused (RST received)
- ``filtered`` — no answer within the timeout

Only the standard library is used.
"""

import asyncio

CONNECT_ERRORS_CLOSED = (ConnectionRefusedError,)


def classify_connect_error(exc: BaseException) -> str:
    """Map a connect exception to a port state."""
    if isinstance(exc, ConnectionRefusedError):
        return "closed"
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return "filtered"
    # EHOSTUNREACH, ENETUNREACH, DNS failures, ECONNRESET mid-handshake...
    return "filtered"


async def probe(
    host: str,
    port: int,
    *,
    timeout: float = 1.0,
    banner_timeout: float = 0.75,
) -> dict:
    """Probe a single TCP port and return a result dict."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
    except (TimeoutError, asyncio.TimeoutError) as exc:
        return {"port": port, "state": classify_connect_error(exc)}
    except OSError as exc:
        return {"port": port, "state": classify_connect_error(exc)}

    banner = ""
    try:
        chunk = await asyncio.wait_for(reader.read(128), timeout=banner_timeout)
        banner = chunk.decode("utf-8", errors="replace").strip()
    except (TimeoutError, asyncio.TimeoutError, OSError):
        pass

    try:
        writer.close()
        await writer.wait_closed()
    except (OSError, asyncio.CancelledError):
        pass

    return {"port": port, "state": "open", "banner": banner}


async def scan(
    host: str,
    ports,
    *,
    timeout: float = 1.0,
    banner_timeout: float = 0.75,
    concurrency: int = 400,
) -> list:
    """Probe many ports concurrently; results sorted by port number."""
    sem = asyncio.Semaphore(max(1, concurrency))

    async def run(port: int) -> dict:
        async with sem:
            return await probe(
                host, port, timeout=timeout, banner_timeout=banner_timeout
            )

    results = await asyncio.gather(*(run(p) for p in ports))
    return sorted(results, key=lambda r: r["port"])
