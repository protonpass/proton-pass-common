#!/usr/bin/env python3
import http.client
import json
import pathlib
import typing
import urllib.request

# https://2fa.directory/api/
URL = "https://api.2fa.directory/v3/totp.json"
CUSTOM_DOMAINS_FILE = pathlib.Path(__file__).parent / "custom2faDomains.txt"
EXCLUDE_DOMAINS_FILE = pathlib.Path(__file__).parent / "excluded2faDomains.txt"
DEFAULT_DESTINATION = (
    pathlib.Path(__file__).parent.parent / "proton-pass-common" / "2faDomains.txt"
)


class Metadata(typing.TypedDict):
    domain: str


def get_2fa_data() -> typing.List[typing.Tuple[str, Metadata]]:
    request = urllib.request.Request(
        URL, headers={"Accept": "application/json", "User-Agent": "curl/7.81.0"}
    )
    response: http.client.HTTPResponse = urllib.request.urlopen(request)
    if response.status != http.HTTPStatus.OK:
        print(f"Failed to download the JSON data. Status code: {response.status}")
        exit(1)
    body = response.read()
    text = body.decode("utf-8")
    data = json.loads(text)
    return data


def generate_domains(
    data: typing.List[typing.Tuple[str, Metadata]],
) -> typing.List[str]:
    domains = {metadata["domain"] for _, metadata in data}
    domains |= {
        domain.strip() for domain in CUSTOM_DOMAINS_FILE.read_text().split("\n")
    }
    excluded_domains = {
        domain.strip() for domain in EXCLUDE_DOMAINS_FILE.read_text().split("\n")
    }
    excluded_domains -= {""}  # Remove empty lines
    domains -= excluded_domains
    domains = sorted(domains)
    return domains


def generate_domains_file() -> None:
    data = get_2fa_data()
    domains = generate_domains(data)
    DEFAULT_DESTINATION.write_text("\n".join(domains))
    print("Domains have been extracted and saved to domains.txt")


if __name__ == "__main__":
    generate_domains_file()
