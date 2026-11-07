"""Turn a raw request into the keys the detectors work with."""
from __future__ import annotations

import bisect
import hashlib
import hmac
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

import phonenumbers

_DIGITS = re.compile(r"\D+")

# words in an AS description that usually mean servers, not people
_HOSTING_WORDS = ("hosting", "cloud", "data center", "datacenter", "server", "vps",
                  "amazon", "google", "microsoft", "digitalocean", "ovh", "hetzner",
                  "linode", "akamai", "alibaba", "tencent", "oracle", "contabo")


@dataclass(frozen=True)
class Phone:
    e164: str              # "+966512345678", or "" when the number can't be parsed
    region: str            # ISO country, e.g. "SA"; "ZZ" if unknown
    calling_code: int
    prefix: str            # calling code + first N national digits, e.g. "+966512"
    hash: str              # keyed hash of e164


@dataclass(frozen=True)
class Network:
    ip: str
    net: str               # /24 for IPv4, /48 for IPv6
    asn: int | None
    hosting: bool


def normalize_phone(raw: str, default_region: str = "SA") -> str:
    """Best-effort conversion of the formats seen in real logs to something
    phonenumbers can parse: '00966…', '966…', '+966…', '05…'."""
    s = raw.strip()
    if not s:
        return ""
    if s.startswith("+"):
        return "+" + _DIGITS.sub("", s)
    d = _DIGITS.sub("", s)
    if d.startswith("00"):
        return "+" + d[2:]
    cc = phonenumbers.country_code_for_region(default_region)
    if cc and d.startswith(str(cc)) and len(d) > len(str(cc)) + 7:
        return "+" + d
    return d  # national format, parsed with the default region


class PhoneParser:
    def __init__(self, secret: bytes, default_region: str = "SA", prefix_digits: int = 3):
        self.secret = secret
        self.default_region = default_region
        self.prefix_digits = prefix_digits
        self._cache: dict[str, Phone] = {}

    def parse(self, raw: str) -> Phone:
        hit = self._cache.get(raw)
        if hit is not None:
            return hit
        norm = normalize_phone(raw, self.default_region)
        region, cc, national, e164 = "ZZ", 0, "", ""
        if norm:
            try:
                num = phonenumbers.parse(norm, self.default_region)
                cc = num.country_code
                national = str(num.national_number)
                e164 = f"+{cc}{national}"
                region = phonenumbers.region_code_for_number(num) or "ZZ"
                if region == "ZZ":
                    # unallocated or new ranges: fall back to the main region of the code
                    region = phonenumbers.region_code_for_country_code(cc) or "ZZ"
            except phonenumbers.NumberParseException:
                pass
        key = e164 or ("raw:" + norm)
        h = hmac.new(self.secret, key.encode(), hashlib.sha256).hexdigest()[:24]
        prefix = f"+{cc}{national[: self.prefix_digits]}" if e164 else "unknown"
        phone = Phone(e164=e164, region=region, calling_code=cc, prefix=prefix, hash=h)
        if len(self._cache) > 200_000:
            self._cache.clear()
        self._cache[raw] = phone
        return phone


class AsnTable:
    """IP → ASN lookup from an iptoasn.com style TSV
    (range_start, range_end, asn, country, description). Optional."""

    def __init__(self) -> None:
        self._starts: list[int] = []
        self._rows: list[tuple[int, int, str]] = []

    @classmethod
    def load(cls, path: str | Path) -> "AsnTable":
        t = cls()
        rows = []
        with open(path, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                parts = line.rstrip("\n").split("\t")
                if len(parts) < 3:
                    continue
                try:
                    lo = int(ipaddress.ip_address(parts[0]))
                    hi = int(ipaddress.ip_address(parts[1]))
                    asn = int(parts[2])
                except ValueError:
                    continue
                if asn == 0:
                    continue
                rows.append((lo, hi, asn, parts[4] if len(parts) > 4 else ""))
        rows.sort()
        t._starts = [r[0] for r in rows]
        t._rows = [(r[1], r[2], r[3]) for r in rows]
        return t

    def lookup(self, ip: str) -> tuple[int | None, str]:
        if not self._starts:
            return None, ""
        n = int(ipaddress.ip_address(ip))
        i = bisect.bisect_right(self._starts, n) - 1
        if i >= 0 and n <= self._rows[i][0]:
            return self._rows[i][1], self._rows[i][2]
        return None, ""


class NetworkParser:
    def __init__(self, asn_table: AsnTable | None = None, hosting_asns: set[int] | None = None):
        self.asn_table = asn_table or AsnTable()
        self.hosting_asns = hosting_asns or set()

    def parse(self, ip: str | None) -> Network | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            return None
        plen = 24 if addr.version == 4 else 48
        net = str(ipaddress.ip_network(f"{addr}/{plen}", strict=False))
        asn, desc = self.asn_table.lookup(str(addr))
        desc_l = desc.lower()
        hosting = (asn in self.hosting_asns) or any(w in desc_l for w in _HOSTING_WORDS)
        return Network(ip=str(addr), net=net, asn=asn, hosting=hosting)
