#!/usr/bin/env python3

import json
import re
import sys
import urllib.request
from os import path

# URL to download the JSON data from
url = "https://api.2fa.directory/v3/totp.json"

# Characters allowed in a DNS label (lowercase, since inputs are lowercased first)
LABEL_RE = re.compile(r"^[a-z0-9-]+\Z")
TLD_RE = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})\Z")


def is_valid_label(label: str) -> bool:
    # RFC 1035: 1-63 chars, alphanumeric at both ends, hyphens allowed inside
    return (
        1 <= len(label) <= 63
        and LABEL_RE.match(label) is not None
        and label[0] != '-'
        and label[-1] != '-'
    )


def is_valid_domain(value: str) -> bool:
    # Split-and-check instead of a single regex: linear time, no backtracking blowup
    if not 1 <= len(value) <= 253:
        return False
    labels = value.split('.')
    if len(labels) < 2:
        return False
    return all(is_valid_label(label) for label in labels[:-1]) and bool(TLD_RE.match(labels[-1]))

CUSTOM_DOMAINS_FILE = path.abspath(path.join(path.dirname(__file__), 'custom2faDomains.txt'))
EXCLUDE_DOMAINS_FILE = path.abspath(path.join(path.dirname(__file__), 'excluded2faDomains.txt'))
DEFAULT_DST = path.abspath(path.join(__file__, "../../proton-pass-common", "2faDomains.txt"))

# Send a GET request to the URL
req = urllib.request.Request(url, headers={'Accept': 'application/json', 'User-Agent': 'curl/7.81.0'})
response = urllib.request.urlopen(req)

with open(EXCLUDE_DOMAINS_FILE, 'r') as f:
    excluded_domains = {domain.strip().lower() for domain in f.readlines() if domain.strip()}

# Check if the request was successful
if response.status == 200:
    # Load JSON data from the response

    body = response.read()
    text = body.decode('utf-8')

    data = json.loads(text)

    # Extract domains
    domains = []
    skipped = []
    for item in data:
        if isinstance(item, list) and len(item) > 1 and 'domain' in item[1]:
            domain = item[1]['domain']
            if not isinstance(domain, str):
                continue
            domain = domain.strip().lower()
            if not is_valid_domain(domain):
                skipped.append(domain)
                continue
            if domain not in excluded_domains:
                domains.append(domain)

    # Open the custom domains file in read mode
    with open(CUSTOM_DOMAINS_FILE, 'r') as file:
        for line in file.readlines():
            custom_domain = line.strip().lower()
            if not custom_domain:
                continue
            if not is_valid_domain(custom_domain):
                skipped.append(custom_domain)
                continue
            if custom_domain not in excluded_domains:
                domains.append(custom_domain)

    if skipped:
        print(f"Skipped {len(skipped)} invalid domain(s):", file=sys.stderr)
        for domain in skipped:
            print(f"  {domain!r}", file=sys.stderr)

    clean_domains = sorted(list(set(domains)))

    # Save domains to a text file
    with open(DEFAULT_DST, 'w') as file:
        for domain in clean_domains:
            file.write(domain + '\n')

    print("Domains have been extracted and saved to domains.txt")
else:
    print(f"Failed to download the JSON data. Status code: {response.status_code}")
