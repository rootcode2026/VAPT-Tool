#!/bin/sh
# Write JSON to a file so progress logs are not mixed into structured output.

if [ "$1" = "--version" ] || [ "$1" = "--help" ] || [ "$1" = "-h" ]; then
    exec testssl.sh "$@"
fi

outfile="/tmp/vapt-tls.json"
rm -f "$outfile"

testssl.sh \
    --jsonfile "$outfile" \
    --color 0 \
    --warnings off \
    --quiet \
    "$@"
status=$?

if [ -s "$outfile" ]; then
    cat "$outfile"
    exit 0
fi

exit "$status"
