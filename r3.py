#!/usr/bin/env python3

from core.core import R3Core
import argparse

def main():
    parser = argparse.ArgumentParser(description="RapidRansomResponder - CLI")
    parser.add_argument("--epicenter", help="IP ou nom machine infectée", required=True)
    args = parser.parse_args()

    r3 = R3Core()
    print(f"[R3] Démarrage réponse ransomware pour : {args.epicenter}")
    r3.handle_attack(args.epicenter)

if __name__ == "__main__":
    main()
