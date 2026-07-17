#!/bin/bash
# #25 : lance QEMU pc jusqu'à un run qui atteint init (SEGV pid=1), puis dumpe
# les <F25 ... cr3=> (cassures CoW pile user, avec cr3) + <25VF pcr3/ccr3> pour
# identifier le frame de pile d'init (le <F25> dont cr3 == pcr3) = cible watchpoint.
cd /mnt/c/Users/xavie/Desktop/Exo-OS || exit 1
N="${1:-8}"
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
  seg=$(echo "$clean" | grep -aoE "<SEGV pid=1 cr2=[0-9a-f]+ rip=[0-9a-f]+ rsp=[0-9a-f]+" | head -1)
  bytes=$(wc -c < /tmp/e9r.txt)
  echo "run $i: bytes=$bytes seg='${seg:-none}'"
  if [ -n "$seg" ]; then
    echo "  VF: $(echo "$clean" | grep -aoE 'pcr3=[0-9a-f]+>|ccr3=[0-9a-f]+>' | tr '\n' ' ')"
    echo "  FA (init stack frame Fa): $(echo "$clean" | grep -aoE '<25FA [0-9a-f]+>' | sort -u | tr '\n' ' ')"
    echo "  F25 (unique p/f/cr3):"
    echo "$clean" | grep -aoE "<F25 p=[0-9a-f]+ f=[0-9a-f]+ cr3=[0-9a-f]+>" | sort -u
    echo "GOOD RUN FOUND at iteration $i"
    exit 0
  fi
done
echo "no good run in $N tries"
