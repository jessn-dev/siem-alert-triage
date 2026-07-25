"""Alert enrichment and risk scoring.

The GeoIP table here is a static stand-in for a real provider (MaxMind, IPinfo).
It is deliberately keyed on the documentation ranges the log generator uses so
the demo exercises every scoring branch. Swapping in a real lookup means
replacing `lookup_country` only — the scoring model does not change.
"""

import ipaddress

# Documentation / test ranges (RFC 5737, RFC 6598) mapped to demo geographies.
GEOIP_PREFIXES = {
    "203.0.113.": "RU",
    "198.51.100.": "CN",
    "192.0.2.": "BR",
    "100.20.30.": "RU",
}

HIGH_RISK_COUNTRIES = {"RU", "CN", "KP", "IR"}

CRITICAL_ACCOUNTS = {"admin", "root", "ceo", "svc_db", "administrator", "domain_admin"}

SEVERITY_BANDS = ((80, "CRITICAL"), (60, "HIGH"), (40, "MEDIUM"), (0, "LOW"))

# Enumerated explicitly rather than using ipaddress.is_private: that property
# also covers the RFC 5737 documentation ranges, which would classify our
# simulated external attackers as trusted internal hosts.
INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                 "127.0.0.0/8", "169.254.0.0/16", "fc00::/7")
)


def is_internal(ip: str) -> bool:
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in net for net in INTERNAL_NETWORKS if net.version == address.version)


def lookup_country(ip: str) -> str:
    if is_internal(ip):
        return "INTERNAL"
    for prefix, country in GEOIP_PREFIXES.items():
        if ip.startswith(prefix):
            return country
    return "UNKNOWN"


def enrich_context(ip: str, users: list) -> dict:
    """Attaches GeoIP and asset-criticality context to a detection."""
    country = lookup_country(ip)
    critical_targets = sorted({u for u in users if u in CRITICAL_ACCOUNTS})

    return {
        "geoip": {
            "ip": ip,
            "country": country,
            "is_internal": country == "INTERNAL",
        },
        "asset_context": {
            "critical_targets_hit": len(critical_targets),
            "critical_users": critical_targets,
        },
    }


def calculate_dynamic_risk(base_risk: int, enrichment: dict) -> tuple:
    """Derives final risk score and severity band from rule base + context.

    A brute force against a guest account from the office LAN and the same
    attack against root from a high-risk geography must not page identically.
    """
    score = base_risk
    country = enrichment["geoip"]["country"]

    if country in HIGH_RISK_COUNTRIES:
        score += 20
    elif not enrichment["geoip"]["is_internal"]:
        score += 10

    score += 10 * enrichment["asset_context"]["critical_targets_hit"]
    score = max(0, min(100, score))

    severity = next(name for floor, name in SEVERITY_BANDS if score >= floor)
    return score, severity
