# Password Checker (Rev)

Bài này đưa source code Java để rev. ( Đọc code java mà muốn thở oxi :(( ).

![](<../../.gitbook/assets/image (1).png>)

{% file src="../../.gitbook/assets/PasswordChecker.java" %}

Kiểm tra hàm checkPassword

{% code lineNumbers="true" %}
```java
    public static boolean checkPassword(String password){
        int []arr = {0xeb05,0x923c,0x1bbed,0x20f7d,0xbc04,0x10522,0x11f3f,0x1db43,0x15379,0x15379,0xa1e7,0xa72,0x0,0x18cec,0x781f,0x539,0x1d60a,0x0,0x214b6,0x272b8,0x172cf,0xd0e8,0x1395c,0x1c65f,0x1d60a,0xffe9,0xc676,0x17d41,0x1685d,0xdb5a,0x12478,0x1b6b4,0x172cf,0xe093,0x23e7e,0x1685d,0x187b3};
        int c = password.charAt(0);
        int counter = 1;
        c = password.charAt(0);     
        counter = 1;   
        while (counter<password.length()){
            int tmp = (c^password.charAt(counter)) *1337;
            if (tmp!=arr[counter-1]) 
                return false;
            c = password.charAt(counter);
            counter++;
        }
        return true;
    }
```
{% endcode %}

Có thể tóm gọn là nó duyệt từng kí tự trong password và kiểm tra xem \`(`password[i] ^ password[i+1]) == arr[i]`&#x20;

Vì kí tự đầu tiên sẽ ảnh hưởng đến kết quả kiểm tra của các kí tự sau nên mình sẽ dò tất cả các trường hợp khả dĩ

```python
arr = [0xeb05,0x923c,0x1bbed,0x20f7d,0xbc04,0x10522,0x11f3f,0x1db43,0x15379,0x15379,0xa1e7,0xa72,0x0,0x18cec,0x781f,0x539,0x1d60a,0x0,0x214b6,0x272b8,0x172cf,0xd0e8,0x1395c,0x1c65f,0x1d60a,0xffe9,0xc676,0x17d41,0x1685d,0xdb5a,0x12478,0x1b6b4,0x172cf,0xe093,0x23e7e,0x1685d,0x187b3]
def solve(c,index):
    for out in range(ord(' '),ord('}')):
        if (c^out)*1337==arr[index]:
            return out
for c in range(ord('A'),ord('z')+1):
    print(chr(c),end='')
    for index in range(len(arr)):
        if c:
            tmp=solve(c,index)
        if tmp:
            print(chr(tmp),end='')
        c=tmp
    print()
```

<figure><img src="../../.gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

Mình thấy password\[0]='H' là hợp lý nhất, password giải ra đủ 37 kí tự và có nghĩa.

Flag: `W1{Hey,Im_h3r3,..but..H0w_c4n_y0u_g3t_1t?}`
