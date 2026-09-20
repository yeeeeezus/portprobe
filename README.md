# portprobe

**Zero-dependency async TCP port scanner** — banner grabbing, closed/filtered classification, JSON output, built-in top-100 ports. Pure Python standard library, nothing to install beyond the tool itself.

[![CI](https://github.com/yeeeeezus/portprobe/actions/workflows/ci.yml/badge.svg)](https://github.com/yeeeeezus/portprobe/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-success)](pyproject.toml)

```console
$ portprobe scanme.nmap.org --top 25
PORT   STATE     SERVICE               BANNER
22     open      ssh                   SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
80     open      http

2 open of 2 shown
```

(That's a real run against [scanme.nmap.org](https://scanme.nmap.org), the Nmap project's sanctioned scanning target.)

## Why

Most of the time you don't need Nmap. You need to know which ports answer on a host, what's behind them, and you need it in a pipeline-friendly form. portprobe does exactly that in ~350 lines of standard-library Python: no compiled binaries, no packet crafting, no root, no dependencies — `pipx` it and scan.

## Install

```console
$ pipx install git+https://github.com/yeeeeezus/portprobe
```

or with `uv`:

```console
$ uvx --from git+https://github.com/yeeeeezus/portprobe portprobe <host>
```

or from a checkout:

```console
$ git clone https://github.com/yeeeeezus/portprobe
$ pip install ./portprobe
```

## Usage

```console
$ portprobe 127.0.0.1 --ports 22,80,3000-3010
```

Scanning a range and want everything, not just open ports?

```console
$ portprobe 10.0.0.5 --ports 1-1024 --all
```

Machine-readable output for scripts and CI:

```console
$ portprobe scanme.nmap.org --top 25 --json
{
  "host": "scanme.nmap.org",
  "resolved": "45.33.32.156",
  "scanned": 25,
  "summary": { "open": 2, "shown": 2 },
  "ports": [
    {
      "port": 22,
      "state": "open",
      "service": "ssh",
      "banner": "SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13"
    },
    {
      "port": 80,
      "state": "open",
      "service": "http",
      "banner": ""
    }
  ]
}
```

## How it works

Each port gets one TCP connection attempt with a bounded timeout, driven by `asyncio` with a semaphore capping parallel probes (default 400). The result of a probe is classified the way classic scanners classify it:

| state | meaning |
|-------|---------|
| `open` | connection accepted; up to 128 bytes of banner captured if the peer speaks first |
| `closed` | connection refused (RST) — the port is reachable but nothing listens |
| `filtered` | no answer within the timeout — firewalled or unreachable |

Banners are read opportunistically: SSH, FTP, SMTP and friends that greet on connect are captured; HTTP-style servers that wait for a request show an empty banner. Output is open-only by default; `--all` shows every state.

## Options

| option | default | description |
|--------|---------|-------------|
| `host` | — | hostname or IP to scan |
| `--ports SPEC` | — | e.g. `80,443,2000-2010`; overrides `--top` |
| `--top N` | `100` | first N ports of the built-in top-100 ranking |
| `--timeout SEC` | `1.0` | connect timeout |
| `--banner-timeout SEC` | `0.75` | max wait for a banner on open ports |
| `--concurrency N` | `400` | probes in flight |
| `--json` | off | machine-readable JSON |
| `--all` | off | include closed/filtered in output |

## Authorization

Only scan hosts you own or have explicit permission to scan. `scanme.nmap.org` is the Nmap project's public test target and the example target here for that reason.

## Development

```console
$ git clone https://github.com/yeeeeezus/portprobe && cd portprobe
$ python -m unittest discover -s tests -v
```

32 tests, no test dependencies — the suite spins up real local TCP servers and scans them.

## License

[MIT](LICENSE)
