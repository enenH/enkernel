#!/bin/sh
# Source-tree detection also covers vendor backports and callback CFI types.
set -eu
header="$1/arch/arm64/include/asm/debug-monitors.h"
fault="$1/arch/arm64/mm/fault.c"
test -r "$header" && test -r "$fault" || exit 0
grep -q 'struct step_hook {' "$header" || exit 0
grep -q 'register_user_step_hook' "$header" || exit 0
step_type=$(sed -n '/struct step_hook {/,/^};/p' "$header" | tr '\n' ' ')
fault_type=$(sed -n '/struct fault_info {/,/^};/p' "$fault" | tr '\n' ' ')
case "$step_type" in
  *'unsigned int esr'*) step=' -DDFM_PTE_STEP_ESR32' ;;
  *'unsigned long esr'*) step='' ;;
  *) exit 0 ;;
esac
case "$fault_type" in
  *'unsigned int esr'*) fault=' -DDFM_PTE_FAULT_ESR32' ;;
  *'unsigned long esr'*) fault='' ;;
  *) exit 0 ;;
esac
printf '%s\n' "-DDFM_PTE_USER_STEP_HOOK$step$fault"
