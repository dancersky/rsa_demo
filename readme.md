**how to use ?**

```
cd rsa_demo
mkdir build
cd build
cmake ..
make
./mainpro
```



**API使用注意事项**

```c
#include <openssl/rsa.h>

int RSA_public_encrypt(int flen, unsigned char *from,
   unsigned char *to, RSA *rsa, int padding);

int RSA_private_decrypt(int flen, unsigned char *from,
    unsigned char *to, RSA *rsa, int padding);


/*
	一般我们的填充方式padding都是选RSA_PKCS1_PADDING.这是比较广泛的使用。以下说明都是基于此方式。
	在encrypt(加密)时：
		flen ： 要加密的明文长度，不能大于RSA_SIZE(rsa)-11.
		from :	明文内容
		to 　：　存储密文，内存长度不能小于RSA_SIZE(rsa).
	在decrypt(解密)时：
		flen ： rsa的长度，RSA_SIZE(rsa).
		from :	密文
		to 　：　存储解密明文，长度不大于RSA_SIZE(rsa)大小。
*/
```



**base64和二进制转换问题**

```c
/*
由于二进制数据打印出来也不容易阅读，现在我们把加密的二进制密文转为base64的编码格式，base64是六个bit组成一个单元表示一个字符，那么就是说三个字节的二进制数据24个bit就相当于4个单元的base64，即四个字节。base64编码就是为了数据传输易读。所以一般加密后密文转为base64格式，但解密时要将base64转换为原来的二进制类型密文。
*/
```



**ubuntu14.04如何生成公钥私钥问题**

```c
首先安装openssl
 	sudo apt-get install openssl
 生成私钥---存储到private.pem文件中
 	openssl genrsa -out private.pem 1024
 生成公钥---存储到public.pem文件中
 	openssl rsa -in private.pem -pubout -out public.pem
```