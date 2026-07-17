#!/bin/bash
# #25 : boucle QEMU pc (SANS gdb, robuste au flake boot) jusqu'à capter une
# corruption de Fa (pile vivante d'init) : <25ZEROFA> (zero_pages écrase Fa) ou
# <25FREEF> (Fa libéré). Dumpe la chaîne d'appel (addresses code) du coupable.
cd /mnt/c/Users/xavie/Desktop/Exo-OS || exit 1
N="${1:-10}"
i=0
while [ "$i" -lt "$N" ]; do
  i=$((i + 1))
  pkill -9 qemu-system-x86 2>/dev/null
  sleep 1
  rm -f /tmp/e9r.txt
  timeout 100 qemu-system-x86_64 -machine pc -m 256M -boot d -vga std -serial null \
    -no-reboot -no-shutdown -debugcon file:/tmp/e9r.txt \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -hda target/qemu/exofs-root.img -cdrom exo-os.iso -display none >/dev/null 2>&1
  clean=$(tr -cd "\11\12\15\40-\176\n" < /tmp/e9r.txt)
  seg=$(echo "$clean" | grep -aoE "<SEGV pid=1" | head -1)
  fa=$(echo "$clean" | grep -acE "<25ZEROINIT|<25FREEINIT|<25ZEROFA|<25FREEF")
  echo "run $i: seg='${seg:-none}' FA_corrupt=$fa"
  if [ "${fa:-0}" -gt 0 ]; then
    echo "=== ZEROINIT / FREEINIT (init frame corruption + chaîne) ==="
    echo "$clean" | grep -aoE "<25(ZEROINIT|FREEINIT|ZEROFA|FREEF)[^>]*>" | head -8
    echo "GOOD at run $i"
    exit 0
  fi
done
echo "no Fa corruption caught in $N tries (=> écriture VA-étrangère, pas physmap free/zero)"
