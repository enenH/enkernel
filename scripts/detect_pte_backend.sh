#!/bin/sh
# Source-tree detection also covers vendor backports and callback CFI types.
set -eu
header="$1/arch/arm64/include/asm/debug-monitors.h"
fault="$1/arch/arm64/mm/fault.c"
monitor="$1/arch/arm64/kernel/debug-monitors.c"
test -r "$header" && test -r "$fault" || exit 0
fault_type=$(sed -n '/struct fault_info {/,/^};/p' "$fault" | tr '\n' ' ')
case "$fault_type" in
  *'unsigned int esr'*) fault=' -DDFM_PTE_FAULT_ESR32' ;;
  *'unsigned long esr'*) fault='' ;;
  *) exit 0 ;;
esac
if grep -q 'struct step_hook {' "$header"; then
  grep -q 'register_user_step_hook' "$header" || exit 0
  step_type=$(sed -n '/struct step_hook {/,/^};/p' "$header" | tr '\n' ' ')
  case "$step_type" in
    *'unsigned int esr'*) step=' -DDFM_PTE_STEP_ESR32' ;;
    *'unsigned long esr'*) step='' ;;
    *) exit 0 ;;
  esac
  printf '%s\n' "-DDFM_PTE_USER_STEP_HOOK$step$fault"
else
  # 6.18: only this recognized void AAPCS entry can be skipped safely.
  test -r "$monitor" || exit 0
  grep -q 'NOKPROBE_SYMBOL(do_el0_softstep)' "$monitor" && exit 0
  grep -Eq '^void do_el0_softstep\(unsigned long esr, struct pt_regs \*regs\)' "$monitor" || exit 0
  printf '%s\n' "-DDFM_PTE_SOFTSTEP_KPROBE$fault"
fi
