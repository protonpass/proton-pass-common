#!/usr/bin/env python3
import itertools
import pathlib
import sys
import urllib.request
from typing import List

WORDS_URLS = [
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords-1000.txt",
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/darkweb2017-top10000.txt",
]

DEFAULT_DESTINATION = (
    pathlib.Path(__file__).parent.parent / "proton-pass-common" / "passwords.txt"
)


def get_words(url: str) -> List[str]:
    response = urllib.request.urlopen(url)
    body = response.read()
    text = body.decode("utf-8")
    lines = [
        word.lower()
        for line in text.split("\n")
        if len(word := line.strip().replace("'", "")) > 3
    ]
    return lines


def generate_password_file(destination_path: pathlib.Path) -> None:
    word_lists = map(get_words, WORDS_URLS)

    # Sort unique because of later sort by length.
    # Timsort being stable, and set being unordered,
    # this will keep the order of words equal in length over multiple runs.
    unique_words = sorted(set(itertools.chain(*word_lists)))

    sorted_by_length = sorted(unique_words, key=len, reverse=True)
    destination_path.write_text("\n".join(sorted_by_length))
    print(f"Wrote the passwords file to {destination_path}")


if __name__ == "__main__":
    if len(sys.argv) == 2 and sys.argv[1] in ["-h", "--help"]:
        print(f"{sys.argv[0]} DST_FILE")
        print(f"(defaults to {DEFAULT_DESTINATION})")
        sys.exit(0)

    if len(sys.argv) > 2:
        print(f"Bad usage:\n\t{sys.argv[0]} DST_FILE")
        sys.exit(1)

    generate_password_file(
        pathlib.Path(sys.argv[1]) if len(sys.argv) == 2 else DEFAULT_DESTINATION
    )
