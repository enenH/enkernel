#!/bin/sh
# Emit flags only for a complete, recognized read_swap_cache_async signature.
# Vendor kernels can carry the transitional (bool, swap_iocb **) ABI.
set -eu
test -f "$1" || exit 0
signature=$(awk '
    /^struct (page|folio) \*read_swap_cache_async[[:space:]]*\(/ { copying = 1 }
    copying {
        line = $0
        if (index(line, ")")) {
            printf "%s", substr(line, 1, index(line, ")"))
            exit
        }
        printf "%s", line
    }
' "$1" | tr -d '[:space:]')
name='[a-zA-Z_][a-zA-Z0-9_]*'
prefix="(structpage|structfolio)\*read_swap_cache_async\(swp_entry_t${name},gfp_t${name},structvm_area_struct\*${name},unsignedlong${name},"
poll="bool${name}"
plug="structswap_iocb\*\*${name}"
flags=
if printf '%s' "$signature" | grep -Eq "^${prefix}${poll},${plug}\)$"; then
    flags='-DDFM_SWAP_READ_POLL -DDFM_SWAP_READ_PLUG'
elif printf '%s' "$signature" | grep -Eq "^${prefix}${plug}\)$"; then
    flags='-DDFM_SWAP_READ_PLUG'
elif printf '%s' "$signature" | grep -Eq "^${prefix}${poll}\)$"; then
    flags='-DDFM_SWAP_READ_POLL'
else
    exit 0
fi
case "$signature" in
    structfolio*) flags="$flags -DDFM_SWAP_READ_FOLIO" ;;
esac
printf '%s\n' "-DDFM_SWAP_READER_KNOWN $flags"
