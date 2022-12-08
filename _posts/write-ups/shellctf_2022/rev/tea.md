# tea

## SHELL CTF 2022

## TEA

Challenge

![Challenge](https://raw.githubusercontent.com/ngovinhhuy/CTF\_bullshit\_stuffs/main/shellctf\_2022/rev/tea/image/Screenshot\_2022-08-15\_01-04-51.png)

Check binary

![Binary](https://github.com/ngovinhhuy/CTF\_bullshit\_stuffs/blob/main/shellctf\_2022/rev/tea/image/Screenshot\_2022-08-15\_01-05-55.png?raw=true)

Decompiling with IDA

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  boilWater(argc, argv, envp);
  if ( strlen(pwd) == 32 )
  {
    addSugar();
    addTea();
    addMilk();
    strainAndServe();
  }
  else
  {
    puts("wrong length");
  }
  return 0;
}
int strainAndServe()
{
  int result; // eax

  if ( !strcmp("R;crc75ihl`cNYe`]m%50gYhugow~34i", pwd) )
    result = puts("yep, that's right");
  else
    result = puts("nope, that's not it");
  return result;
}
```

The binary saves input in `pwn`, encrypts `pwn` with 3 functions and compares with ``"R;crc75ihl`cNYe`]m%50gYhugow~34i".``

Check addMilk() first

```c
unsigned __int64 addMilk()
{
  size_t v0; // rax
  size_t v1; // rax
  int i; // [rsp+4h] [rbp-ACh]
  char part1[8]; // [rsp+10h] [rbp-A0h] BYREF
  __int64 v5; // [rsp+18h] [rbp-98h]
  __int64 v6; // [rsp+20h] [rbp-90h]
  __int64 v7; // [rsp+28h] [rbp-88h]
  char v8; // [rsp+30h] [rbp-80h]
  char part2[8]; // [rsp+40h] [rbp-70h] BYREF
  __int64 v10; // [rsp+48h] [rbp-68h]
  __int64 v11; // [rsp+50h] [rbp-60h]
  __int64 v12; // [rsp+58h] [rbp-58h]
  char v13; // [rsp+60h] [rbp-50h]
  char part3[8]; // [rsp+70h] [rbp-40h] BYREF
  __int64 v15; // [rsp+78h] [rbp-38h]
  __int64 v16; // [rsp+80h] [rbp-30h]
  __int64 v17; // [rsp+88h] [rbp-28h]
  char v18; // [rsp+90h] [rbp-20h]
  unsigned __int64 v19; // [rsp+98h] [rbp-18h]

  v19 = __readfsqword(0x28u);
  i = 0;
  *(_QWORD *)part1 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0;
  *(_QWORD *)part2 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  v13 = 0;
  *(_QWORD *)part3 = 0LL;
  v15 = 0LL;
  v16 = 0LL;
  v17 = 0LL;
  v18 = 0;
  while ( pwd[i] != 53 && i < strlen(pwd) )     // part2 starts with '5'
    strncat(part1, &pwd[i++], 1uLL);
  while ( pwd[i] != 82 && i < strlen(pwd) )     // part3 starts with 'R'
    strncat(part2, &pwd[i++], 1uLL);
  while ( i < strlen(pwd) )
    strncat(part3, &pwd[i++], 1uLL);
  v0 = strlen(part1);
  strncat(part3, part1, v0);                    // part3+=part1
  v1 = strlen(part2);
  strncat(part3, part2, v1);                    // part3+=part2
  strcpy(pwd, part3);                           // pwd=part3
  return __readfsqword(0x28u) ^ v19;
}
```

Wtf! Calling strncat(part1, \&pwd\[i++], 1uLL) ?? 1st argument of strncat must be a pointer, but remember that, a x64 pointer has 8 bytes long so no problem with char\[8] part1 (It might be that IDA made a mistake by realizing part1 as char\[8] rather than a pointer.)

With pseudcode C, we can write a "reverse version" of this function.

```python
def milk_rev():
    possi_flags=[]
    part3_part1="R;crc75ihl`cNYe`]m%" #part3 starts with 'R'
    part2="50gYhugow~34i"#part2 starts with '5'
    for i in range(1,len(part3_part1)):
        part1=part3_part1[i:]
        part3=part3_part1[:i]
        possi_flags+=[part1+part2+part3]
    return possi_flags
```

Because we don't know how long part1 and part3 are, there are many of their cases.

Check addTea function.

```c
unsigned __int64 addTea()
{
  ....
  for ( i = 0; ; ++i )
  {
    v0 = i;
    if ( v0 >= strlen(pwd) >> 1 )               // x >> 1 == x / 2
      break;
    encrypted_char = pwd[i] + 3 * (i / -2);
    strncat(s1, &encrypted_char, 1uLL);         // s1+=encryted_char
  }
  for ( j = strlen(pwd) >> 1; ; ++j )
  {
    v1 = j;
    if ( v1 >= strlen(pwd) )
      break;
    encrypted_char = pwd[j] + j / 6;
    strncat(s1, &encrypted_char, 1uLL);
  }
  strcpy(pwd, s1);                              // pwd=s1
}
```

Just a simple alogrithm, we can easly write a "reverse version".

```python
def tea_rev(possi_flags):
    new_possi_flags=[]
    for i in range(len(possi_flags)):
        flag=possi_flags[i]
        flag=list(flag)
        for x in range(16):
            decryted_char=ord(flag[x])+3*(x//2)
            flag[x]=chr(decryted_char)
        for y in range(16,32):
            decryted_char=ord(flag[y]) - y // 6;
            flag[y]=chr(decryted_char)
        new_possi_flags+=[''.join(flag)]
    return new_possi_flags
```

Checkk addSugar function.

```c
unsigned __int64 addSugar()
{
  ...
  for ( i = 0; i < strlen(pwd); ++i )
  {
    if ( (i & 1) != 0 )                         // i & 1 = i%2
      strncat(odd, &pwd[i], 1uLL);
    else
      strncat(even, &pwd[i], 1uLL);
  }
  strncat(odd, even, 0x11uLL);                  // odd+=even
  strcpy(pwd, odd);                             // pwn=odd
  return __readfsqword(0x28u) ^ v8;
}
```

This function puts chars that have odd indexes into a string and the others into another string.

Write a "reverse version"

```python
def sugar_rev(possi_flags):
    new_possi_flags=[]
    for i in range(len(possi_flags)):
        new_flag=""
        even=possi_flags[i][16:]
        odd=possi_flags[i][:16]
        x=0
        y=0
        for i in range(32):
            if i%2:
                new_flag+=odd[y]
                y+=1
            else:
                new_flag+=even[x]
                x+=1
        new_possi_flags+=[new_flag]
    return new_possi_flags
```

Final script

```python
def debug_flags(possi_flags):
    for flag in possi_flags:
        print(flag)
def milk_rev():
    possi_flags=[]
    part3_part1="R;crc75ihl`cNYe`]m%" #part3 starts with 'R'
    part2="50gYhugow~34i"#part2 starts with '5'
    for i in range(1,len(part3_part1)):
        part1=part3_part1[i:]
        part3=part3_part1[:i]
        possi_flags+=[part1+part2+part3]
    return possi_flags
def tea_rev(possi_flags):
    new_possi_flags=[]
    for i in range(len(possi_flags)):
        flag=possi_flags[i]
        flag=list(flag)
        for x in range(16):
            decryted_char=ord(flag[x])+3*(x//2)
            flag[x]=chr(decryted_char)
        for y in range(16,32):
            decryted_char=ord(flag[y]) - y // 6;
            flag[y]=chr(decryted_char)
        new_possi_flags+=[''.join(flag)]
    return new_possi_flags
def sugar_rev(possi_flags):
    new_possi_flags=[]
    for i in range(len(possi_flags)):
        new_flag=""
        even=possi_flags[i][16:]
        odd=possi_flags[i][:16]
        x=0
        y=0
        for i in range(32):
            if i%2:
                new_flag+=odd[y]
                y+=1
            else:
                new_flag+=even[x]
                x+=1
        new_possi_flags+=[new_flag]
    return new_possi_flags
for flag in sugar_rev(tea_rev(milk_rev())):
    print(flag)
```

![run](https://github.com/ngovinhhuy/CTF\_bullshit\_stuffs/blob/main/shellctf\_2022/rev/tea/image/Screenshot\_2022-08-15\_01-50-24.png?raw=true)

`Flag: shellctf{T0_1nfiNi7y_4nD_B3y0nd}`
