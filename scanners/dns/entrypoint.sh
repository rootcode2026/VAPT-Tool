#!/bin/sh
# dnsx -d is wordlist brute-force mode. Record lookup uses -l/stdin.

if [ "$1" = "-version" ] || [ "$1" = "-h" ] || [ "$1" = "-help" ]; then
    exec dnsx "$@"
fi

domain="$1"
shift

if [ -z "$domain" ]; then
    echo "DNS target cannot be empty." >&2
    exit 1
fi

printf '%s\n' "$domain" | exec dnsx -l - "$@"
