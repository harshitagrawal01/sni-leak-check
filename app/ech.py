"""Work out whether a hostname leaks on the wire, and whether the site could
hide it with Encrypted ClientHello (ECH).

The SNI (the hostname) is sent in the clear in every ordinary TLS handshake,
so on its own that is not interesting: it is always true. What varies between
sites is whether they publish an ECH config in DNS, because that is what lets
a capable client encrypt the hostname. So the real signal is: does this domain
publish ECH, and if so, what cover name would a watcher see instead.
"""
import base64
import json
import urllib.parse
import urllib.request

DOH = "https://cloudflare-dns.com/dns-query"


def https_record(domain):
    """Fetch the DNS HTTPS (type 65) record via DoH JSON. Returns the raw
    record strings, or [] if there is none."""
    q = f"{DOH}?name={urllib.parse.quote(domain)}&type=HTTPS"
    req = urllib.request.Request(q, headers={"accept": "application/dns-json",
                                             "user-agent": "sni-leak-check"})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = json.load(r)
    return [a.get("data", "") for a in data.get("Answer", []) if a.get("type") == 65]


def parse_ech(b64):
    """Decode an ECHConfigList far enough to report the version, KEM and the
    public_name (the cover hostname). Returns None if it does not parse."""
    try:
        raw = base64.b64decode(b64 + "==")
        i = 2                                   # skip ECHConfigList length
        version = raw[i:i + 2].hex(); i += 2
        i += 2                                  # skip this config's length
        config_id = raw[i]; i += 1
        kem = int.from_bytes(raw[i:i + 2], "big"); i += 2
        pklen = int.from_bytes(raw[i:i + 2], "big"); i += 2
        i += pklen                              # skip public key
        cslen = int.from_bytes(raw[i:i + 2], "big"); i += 2 + cslen
        i += 1                                  # maximum_name_length
        pnlen = raw[i]; i += 1
        public_name = raw[i:i + pnlen].decode("ascii", "replace")
        kems = {0x0020: "X25519", 0x0010: "P-256", 0x0012: "P-384"}
        return {"version": "0x" + version, "config_id": config_id,
                "kem": kems.get(kem, f"0x{kem:04x}"), "public_name": public_name}
    except Exception:
        return None


def check(domain):
    domain = domain.strip().lower().rstrip(".")
    if not domain or "/" in domain or " " in domain:
        return {"error": "Enter a bare hostname, like example.com"}
    result = {"domain": domain, "sni_sent_in_clear": domain,
              "ech_published": False, "ech": None, "records": []}
    try:
        recs = https_record(domain)
    except Exception as e:
        result["error"] = f"DNS lookup failed: {type(e).__name__}"
        return result
    result["records"] = recs
    for rec in recs:
        for tok in rec.split():
            if tok.startswith("ech="):
                ech = parse_ech(tok[4:])
                if ech:
                    result["ech_published"] = True
                    result["ech"] = ech
    return result
