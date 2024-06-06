#!/usr/bin/env python3

import json
import pathlib
import urllib.request

# URL to download the JSON data from  TODO: What json data?
url = "https://api.2fa.directory/v3/totp.json"

CUSTOM_DOMAINS_FILE = pathlib.Path(__file__).parent / "custom2faDomains.txt"
EXCLUDE_DOMAINS_FILE = pathlib.Path(__file__).parent / "excluded2faDomains.txt"
DEFAULT_DESTINATION = (
    pathlib.Path(__file__).parent.parent / "proton-pass-common" / "2faDomains.txt"
)

request = urllib.request.Request(
    url, headers={"Accept": "application/json", "User-Agent": "curl/7.81.0"}
)
response = urllib.request.urlopen(request)

excluded_domains = [
    domain_
    for domain in EXCLUDE_DOMAINS_FILE.read_text().split("\n")
    if (domain_ := domain.strip())
]

if response.status == 200:
    # Load JSON data from the response

    body = response.read()
    text = body.decode("utf-8")

    data = json.loads(text)

    # Extract domains
    domains = []
    for item in data:
        if isinstance(item, list) and len(item) > 1 and "domain" in item[1]:
            domain = item[1]["domain"]
            if domain not in excluded_domains:
                domains.append(domain)

    # Open the custom domains file in read mode
    with open(CUSTOM_DOMAINS_FILE) as file:
        for line in file.readlines():
            custom_domain = line.strip()
            if custom_domain not in excluded_domains:
                domains.append(custom_domain)

    clean_domains = sorted(list(set(domains)))

    # Save domains to a text file
    with open(DEFAULT_DESTINATION, "w") as file:
        for domain in clean_domains:
            file.write(domain + "\n")

    print("Domains have been extracted and saved to domains.txt")
else:
    print(f"Failed to download the JSON data. Status code: {response.status_code}")
