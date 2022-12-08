# Junior Hacking Talents Writeup

## Quay ngược thời gian

![alt](https://github.com/ngovinhhuy/CTF\_writeup/raw/main/Junior%20Hacking%20TalentsJ/Forensics/Quaynguocthoigian/Screenshot\_2021-09-06%20Junior%20Hacking%20Talents%20B%E1%BA%A3ng%20THPT.png)

Memory dump: [mem.mem](https://drive.google.com/file/d/1G2Ndl58ypp\_Uz8Zq1nBXVkh3qyDEcHIo/view?usp=sharing)

Mục tiêu: Xác định user, host, key\_rsa/passowrd để truy cập ssh.

Lần này mình sẽ không sử dụng volatility, thay vào đó mình sẽ dùng ... strings và grep :3

Dump hết string về 1 file cho dễ thao tác:

**$ strings mem.mem > strings.out**

Tìm từ những dòng liên quan đến ssh:

**$ cat strings.out | grep ssh**

![alt](https://github.com/ngovinhhuy/CTF\_writeup/raw/main/Junior%20Hacking%20TalentsJ/Forensics/Quaynguocthoigian/Screenshot\_2021-09-05\_18\_51\_11.png)

Ta thấy có 2 dòng quan trọng sau:

**\[00m$ cat \~/.ssh/id\_rsa**: lệnh cat file key ssh, chứng tỏ nội dung key ssh có thể được lưu trong file mem.mem này

**ssh trung149@188.166.233.168 -p 18888**: ta có được cả user, host, và port để truy cập

Vậy vấn đề còn lại ta chỉ cần xác định nội dung của file id\_rsa.

Các key của shh có 1 format chung,

Dòng đầu luôn là: **-----BEGIN OPENSSH PRIVATE KEY-----**

và dòng cuối là: **-----END OPENSSH PRIVATE KEY-----**

Ta xác định nội dung của key ssh bắt đầu ở dòng nào trong file strings.out:

**$ cat strings.out | grep -n "BEGIN OPENSSH PRIVATE KEY"** ( -n để grep hiển thị vị trí dòng)

![alt](https://github.com/ngovinhhuy/CTF\_writeup/raw/main/Junior%20Hacking%20TalentsJ/Forensics/Quaynguocthoigian/Screenshot\_2021-09-05\_19-03-22.png)

Thử view dòng 63722

![alt](https://github.com/ngovinhhuy/CTF\_writeup/raw/main/Junior%20Hacking%20TalentsJ/Forensics/Quaynguocthoigian/Screenshot\_2021-09-05\_19-34-40.png)

Như ta mong đợi :v dưới lệnh cat là nội dung key

Ghi nội dung key vào một file và chmod 600 nó, cuối cùng ta đã có flag:

![alt](https://github.com/ngovinhhuy/CTF\_writeup/raw/main/Junior%20Hacking%20TalentsJ/Forensics/Quaynguocthoigian/Screenshot\_2021-09-05\_20-32-33.png)

Nice :))))
