#!/usr/bin/env python3
"""Regenerate the sourced hosting CIDR snapshot from official provider feeds."""

import csv
import datetime
import io
import json
import pathlib
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "data" / "hosting_prefixes.csv"
AWS_URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"
GCP_URL = "https://www.gstatic.com/ipranges/cloud.json"
CLOUDFLARE_V4 = "https://www.cloudflare.com/ips-v4/"
CLOUDFLARE_V6 = "https://www.cloudflare.com/ips-v6/"


def fetch(url):
    request = urllib.request.Request(url, headers={"User-Agent": "nulltrace-data-updater/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.read()


def main():
    rows = []
    for url in (CLOUDFLARE_V4, CLOUDFLARE_V6):
        for cidr in fetch(url).decode().splitlines():
            if cidr.strip():
                rows.append(("Cloudflare", cidr.strip(), "https://www.cloudflare.com/ips/"))

    aws = json.loads(fetch(AWS_URL))
    for item in aws.get("prefixes", []):
        provider = f"AWS {item.get('service', 'unknown')} {item.get('region', 'GLOBAL')}"
        rows.append((provider, item["ip_prefix"], AWS_URL))
    for item in aws.get("ipv6_prefixes", []):
        provider = f"AWS {item.get('service', 'unknown')} {item.get('region', 'GLOBAL')}"
        rows.append((provider, item["ipv6_prefix"], AWS_URL))

    gcp = json.loads(fetch(GCP_URL))
    for item in gcp.get("prefixes", []):
        cidr = item.get("ipv4Prefix") or item.get("ipv6Prefix")
        if cidr:
            provider = f"Google Cloud {item.get('service', 'unknown')} {item.get('scope', 'GLOBAL')}"
            rows.append((provider, cidr, GCP_URL))

    rows = sorted(set(rows), key=lambda row: (row[0], row[1]))
    output = io.StringIO()
    output.write(
        f"# Generated {datetime.date.today().isoformat()} from official provider feeds; attribution is not a risk verdict.\n"
    )
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("provider", "cidr", "source"))
    writer.writerows(rows)
    OUTPUT.write_text(output.getvalue(), encoding="utf-8")
    print(f"wrote {len(rows)} sourced prefixes to {OUTPUT}")


if __name__ == "__main__":
    main()
