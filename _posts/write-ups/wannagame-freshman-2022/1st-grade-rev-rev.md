# 1st grade rev (Rev)

Decomplie bằng IDA

{% code lineNumbers="true" %}
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [rsp+24h] [rbp-2Ch]
  char v5[5]; // [rsp+2Bh] [rbp-25h] BYREF
  char s1[3]; // [rsp+30h] [rbp-20h] BYREF
  char v7; // [rsp+33h] [rbp-1Dh]
  char v8; // [rsp+34h] [rbp-1Ch]
  char v9; // [rsp+35h] [rbp-1Bh]
  char v10; // [rsp+36h] [rbp-1Ah]
  char v11; // [rsp+37h] [rbp-19h]
  char v12; // [rsp+38h] [rbp-18h]
  char v13; // [rsp+39h] [rbp-17h]
  char v14; // [rsp+3Ah] [rbp-16h]
  unsigned __int64 v15; // [rsp+48h] [rbp-8h]

  v15 = __readfsqword(0x28u);
  printf("What is flag? ");
  __isoc99_scanf("%s", s1);
  if ( strncmp(s1, "W1{", 3uLL) || s1[strlen(s1) - 1] != 125 )
  {
    puts("Wrong format, try again!");
    exit(0);
  }
  for ( i = 0; s1[i]; ++i )
    ;
  if ( i != 17 )
  {
    puts("Flag length must be 17.");
    exit(0);
  }
  substr(s1, 0xBLL, 5LL, v5);
  if ( v7 == 'E'
    && v8 == '4'
    && v9 == '$'
    && v10 == 'y'
    && v7 + v11 == 151
    && v12 - v8 == -1
    && v9 * v13 == 4248
    && v14 != (v10 == 28)
    && !strncmp(v5, "R51n9", 5uLL) )
  {
    puts("Nice flag!");
  }
  else
  {
    puts("Wrong flag!");
  }
  return 1;
}
```
{% endcode %}

Bài này đơn giản chỉ cần tính toán một chút ở line 36 đến line 38, chú ý là v14 chỉ cần khác 0 là đúng điều kiện nên ta phải đoán v14 bằng bao nhiêu

```python
flag="W1{"
v7 = 'E'
v8 = '4'
v9 = '$'
v10 = 'y'
v11 = chr(151-ord(v7))
v12 = chr(ord(v8)-1)
v13 = chr(4248//ord(v9))
v14="?"
v5="R51n9"
flag+=v7+v8+v9+v10+v11+v12+v13+v14+v5+'}'
print(flag)
```

Khi chạy mình ra flag là `W1{E4$yR3v?R51n9}` ( vì mình đang để v14='?' ), có thể dễ đoán v14='3'

`R3v?R51n9` -> REvErSing :))

Flag: `W1{E4$yR3v3R51n9}`

