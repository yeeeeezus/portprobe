"""portprobe — zero-dependency async TCP port scanner.

Package init. Keeps the public surface tiny: version + the scan engine.
"""

from .scanner import probe, scan

__version__ = "1.0.0"
__all__ = ["probe", "scan"]
