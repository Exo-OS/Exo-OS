#!/bin/bash
# Boucle #25 : lance QEMU pc N fois, rapporte SEGV / TDCF / progression.
# Sert à mesurer l'intermittence de #25 (timing-roulette) + corréler TDCF.
cd /mnt/c/Users/xavie/Desktop/Exo-OS || exit 1
N="${1:-4}"
i=0
while [ "$i" -lt "$N" ]; do
  i=$((i + 1))
  pkill -9 qemu-system-x86 2>/dev/null
  sleep 1
  rm -f /tmp/e9r.txt
  timeout 95 qemu-system-x86_64 -machine pc -m 256M -boot d -vga std -serial null \
    -no-reboot -no-shutdown -debugcon file:/tmp/e9r.txt \
    -device isa-debug-exit,iobase=0xf4,iosize=0x04 \
    -hda target/qemu/exofs-root.img -cdrom exo-os.iso -display none >/dev/null 2>&1
  clean=$(tr -cd "\11\12\15\40-\176\n" < /tmp/e9r.txt)
  spawned=$(echo "$clean" | grep -aoE "spawned [a-z_]+" | tr '\n' ',')
  shellm=$(echo "$clean" | grep -aoiE "shell|EXOSH|ready|login" | head -1)
  seg=$(echo "$clean" | grep -aoE "<SEGV pid=[0-9]+ cr2=[0-9a-f]+ rip=[0-9a-f]+" | head -1)
  echo "run $i: spawned=[${spawned}] reached='${shellm:-?}' | ${seg:-NO-SEGV}"
done
echo ALLDONE
