#!/usr/bin/env python3

import requests
from os import path

# URL to download the JSON data from
url = "https://api.2fa.directory/v3/all.json"

CUSTOM_DOMAINS_FILE = path.abspath(path.join(path.dirname(__file__), 'custom2faDomains.txt'))
DEFAULT_DST = path.abspath(path.join(__file__, "../../proton-pass-common", "2faDomains.txt"))

# Send a GET request to the URL
response = requests.get(url)

# Check if the request was successful
if response.status_code == 200:
    # Load JSON data from the response
    data = response.json()

    # Extract domains
    domains = []
    for item in data:  # Loop through the outer list
        if isinstance(item, list) and len(item) > 1 and 'domain' in item[1]:
            domains.append(item[1]['domain'])  # Access the 'domain' in the dictionary

    # Open the custom domains file in read mode
    with open(CUSTOM_DOMAINS_FILE, 'r') as file:
        # Iterate over each line in the file
        for line in file:
        # Strip newline characters and append the line to the existing array
            domains.append(line.strip())

    clean_domains = sorted(list(set(domains)))
    # Save domains to a text file
    with open(DEFAULT_DST, 'w') as file:
        for domain in clean_domains:
            file.write(domain + '\n')

    print("Domains have been extracted and saved to domains.txt")
else:
    print(f"Failed to download the JSON data. Status code: {response.status_code}")
