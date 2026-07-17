set pagination off
set confirm off
set logging file /tmp/gdbfa2.log
set logging overwrite on
set logging redirect on
target remote :1234
set language c
set logging on
# Skip boot churn : on n'arme le watchpoint sur Fa=0x5726000 (pile vivante d'init)
# qu'au PREMIER do_fork (init vforke ipc_router). On capte alors l'écriture tardive
# qui corrompt la pile d'init pendant la fenêtre concurrente.
hbreak do_fork
commands
  silent
  disable 1
  watch *(long*)0xFFFF800005726ae0
  commands
    silent
    printf "\n== ZERO Fa+ae0 pc=0x%lx cr3=0x%lx val=0x%lx ==\n", $pc, $cr3, *(long*)0xFFFF800005726ae0
    bt 16
    continue
  end
  watch *(long*)0xFFFF800005726000
  commands
    silent
    printf "\n== W Fa+0 pc=0x%lx cr3=0x%lx val=0x%lx ==\n", $pc, $cr3, *(long*)0xFFFF800005726000
    bt 16
    continue
  end
  continue
end
continue
