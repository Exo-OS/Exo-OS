set pagination off
set confirm off
set logging file /tmp/gdbfa.log
set logging overwrite on
set logging redirect on
target remote :1234
set language c
set logging on
# Fa = 0x5726000 = frame de pile VIVANTE d'init (page 0x7ffffffef000).
# physmap = 0xFFFF800000000000 + Fa.
#  - Fa+0x0   : début de frame → le buddy y écrit un FreeNode au FREE (init n'écrit
#               jamais si bas dans la page) → capte la LIBÉRATION erronée (cause #25).
#  - Fa+0xae0 : slot d'adresse de retour (rsp au SEGV) → capte le ZEROING (zero_pages).
watch *(long*)0xFFFF800005726000
commands
  silent
  printf "\n== FREE Fa+0 pc=0x%lx cr3=0x%lx val=0x%lx ==\n", $pc, $cr3, *(long*)0xFFFF800005726000
  bt 18
  continue
end
watch *(long*)0xFFFF800005726ae0
commands
  silent
  printf "\n== ZERO Fa+ae0 pc=0x%lx cr3=0x%lx val=0x%lx ==\n", $pc, $cr3, *(long*)0xFFFF800005726ae0
  bt 18
  continue
end
continue
