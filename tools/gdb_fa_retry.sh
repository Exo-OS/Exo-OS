#!/bin/bash
# #25 : retry QEMU+gdb (watchpoint sur Fa=0x5726000 armé au do_fork pour sauter le
# churn de boot) jusqu'à un boot qui atteint init (SEGV) AVEC des hits sur Fa.
# Dumpe alors l'écriture tardive qui corrompt la pile vivante d'init + sa chaîne.
cd /mnt/c/Users/xavie/Desktop/Exo-OS || exit 1
N="${1:-6}"
i=0
while [ "$i" -lt "$N" ]; do
  i=$((i + 1))
  pkill -9 qemu-system-x86 gdb 2>/dev/null
  sleep 1
  rm -f /tmp/e9fa.txt /tmp/gdbfa2.log /tmp/gdbout.txt
  nohup qemu-system-x86_64 -machine pc -m 256M -boot d -vga std -serial null \
    -no-reboot -no-shutdown -s -S -debugcon file:/tmp/e9fa.txt \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -hda target/qemu/exofs-root.img -cdrom exo-os.iso -display none >/tmp/qfa.log 2>&1 &
  sleep 3
  timeout 150 gdb -batch -x tools/gdb_fa2.gdb target/x86_64-unknown-none/debug/exo-os-kernel >/tmp/gdbout.txt 2>&1
  seg=$(tr -cd "\11\12\15\40-\176\n" < /tmp/e9fa.txt | grep -aoE "<SEGV pid=1" | head -1)
  hits=$(grep -acE "== (ZERO|W) Fa" /tmp/gdbfa2.log 2>/dev/null)
  bpe=$(grep -aiE "no symbol|not defined|cannot" /tmp/gdbout.txt | head -1)
  echo "run $i: seg='${seg:-none}' Fa_hits=${hits:-0} ${bpe:+BPERR='$bpe'}"
  if [ -n "$seg" ] && [ "${hits:-0}" -gt 0 ]; then
    echo "=== Fa LATE writes (post-do_fork) ==="
    grep -aE "== (ZERO|W) Fa|exo_os_kernel|compiler_builtins" /tmp/gdbfa2.log | head -55
    echo "GOOD at run $i"
    exit 0
  fi
done
echo "no good gdb run in $N tries"
