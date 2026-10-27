#!/bin/sh
# Burrow's test suite, run inside a guest: sh run.sh [test...]
#
# Each test is a script here that prints one "ok"/"FAIL" line per check and
# exits non-zero if any check failed. The rootfs needs perl and python3.
cd "$(dirname "$0")" || exit 1
[ $# -gt 0 ] || set -- *.py *.pl
failed=
for t in "$@"; do
    case $t in
    *.py) run=python3 ;;
    *.pl) run=perl ;;
    *) continue ;;
    esac
    echo "== $t"
    timeout 120 $run "$t" || failed="$failed $t"
done
# Built by tools/burrow-test.sh when it finds Go.
if [ -f go/burrowtest ] && [ "$*" = "$(echo *.py *.pl)" ]; then
    echo "== go"
    chmod 755 go/burrowtest
    timeout 120 go/burrowtest || failed="$failed go"
fi
if [ -n "$failed" ]; then
    echo "FAILED:$failed"
    exit 1
fi
echo "all passed"
