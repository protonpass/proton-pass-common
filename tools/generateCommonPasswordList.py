#!/usr/bin/env python3
import pathlib
import sys
import urllib.request
from typing import List

WORDLISTS_URLS = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-1000.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt",
]

DEFAULT_DESTINATION = str(
    pathlib.Path(__file__).parent.parent / "proton-pass-common" / "passwords.txt"
)


def download_wordlist(url: str) -> List[str]:
    response = urllib.request.urlopen(url)
    data = response.read()
    text = data.decode("utf-8")
    lines = [
        stripped.lower()
        for line in text.split("\n")
        if len(stripped := line.strip().replace("'", "")) > 3
    ]
    return lines


def main(password_destination_path: str) -> None:
    # Download all the wordlists
    wordlists = map(download_wordlist, WORDLISTS_URLS)

    # Combine all the words
    words = [word for wordlist in wordlists for word in wordlist]

    # Dedup
    deduped_words = sorted(list(set(words)))

    # Sort by length
    sorted_by_length = reversed(sorted(deduped_words, key=len))

    # Write
    with open(password_destination_path, "w") as f:
        f.write("\n".join(sorted_by_length))

    print(f"Wrote the passwords file to {password_destination_path}")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] in ["-h", "--help"]:
        print(f"{sys.argv[0]} DST_FILE")
        print(f"(defaults to {DEFAULT_DESTINATION})")
        sys.exit(0)

    if len(sys.argv) > 2:
        print(f"Bad usage:\n\t{sys.argv[0]} DST_FILE")
        sys.exit(1)

    main(sys.argv[1] if len(sys.argv) == 2 else DEFAULT_DESTINATION)
