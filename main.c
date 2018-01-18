#include <stdio.h>
#include <stdlib.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h> 
#include <openssl/pem.h>
#include "lib64/base64.h"

#define TYPE_PUB    0
#define TYPE_PRI    1

typedef unsigned char uchar;

/*RSA Create*/
RSA *create_rsa(uchar *key, int type)
{
	RSA *rsa = NULL;
    BIO *bio = BIO_new_mem_buf(key, -1);
    if (NULL == bio) {
		fprintf(stderr, "create bio key failed\n");
		goto err1;
    }
    switch (type) {
		case TYPE_PUB: {
			rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
			break;
		}
		case TYPE_PRI: {
			rsa = PEM_read_bio_RSAPrivateKey(bio, NULL,NULL, NULL);
			break;
		}
		default:
			break;
    }
    if (NULL == rsa) {
		fprintf(stderr, "create rsa failed\n");
		goto err2;
    }
    BIO_free_all(bio);
    return rsa;
err2:
	BIO_free_all(bio);
err1:
	return NULL;
}

/*malloc func*/
void *mem_calloc(size_t nmemb, size_t size)
{
	return calloc(nmemb, size);
}

/*encrypt for public key*/
uchar *rsa_pub_encrypt(uchar *pubkey, uchar *text, int padding)
{
	uchar enctxt[512] = {0};
	RSA *rsa = create_rsa(pubkey, TYPE_PUB);
	if (NULL == rsa) {
		fprintf(stderr, "create pub rsa failed\n");
		goto err1;
	}
	if (NULL == text) {
		goto err1;
	}
	/*加密数据明文不能大于RSA_size(rsa)-11*/
	int len = RSA_size(rsa);
	if (len - 11 < strlen(text)) {
		fprintf(stderr, "text is too long\n");
		goto err2;
	}
	int size = RSA_public_encrypt(strlen(text), text, enctxt, rsa, padding);
	if (size < 0) {
		fprintf(stderr, "public key encrypt failed\n");
		goto err2;
	}
	int enc_64_len = (size/3*4) + 8;
	uchar *enctxt_64 = mem_calloc(1, enc_64_len);
	if (NULL == enctxt_64) {
		goto err2;
	}
	memset(enctxt_64, 0, enc_64_len);
	/*binary convert to base64 */
	base64x_encode_binary(enctxt_64, enctxt, size);
	RSA_free(rsa);
	return enctxt_64;
err2:
	RSA_free(rsa);
err1:
	return NULL;
}

/*decrypt for public key*/
uchar *rsa_pub_decrypt(uchar *pubkey, uchar *text, int padding)
{
	uchar enc_bin[512] = {0};
	RSA *rsa = create_rsa(pubkey, TYPE_PUB);
	if (NULL == rsa) {
		fprintf(stderr, "create pub rsa failed\n");
		goto err1;
	}
	if (NULL == text) {
		goto err1;
	}
	int size = RSA_size(rsa);
	int len = base64x_decode_binary(enc_bin, text);
	uchar *dectxt = mem_calloc(1, size);
	if (NULL == dectxt) {
		goto err2;
	}
	int ret = RSA_public_decrypt(size, enc_bin, dectxt, rsa, padding);
	if (ret < 0) {
		printf("decrypt failed\n");
		goto err3;
	}
	RSA_free(rsa);
	return dectxt;
err3:
	free(dectxt);
err2:
	RSA_free(rsa);
err1:
	return NULL;
}


/*encrypt for private key*/
uchar *rsa_pri_encrypt(uchar *prikey, uchar *text, int padding)
{
	uchar enctxt[512] = {0};
	RSA *rsa = create_rsa(prikey, TYPE_PRI);
	if (NULL == rsa) {
		fprintf(stderr, "create pri rsa failed\n");
		goto err1;
	}
	if (NULL == text) {
		goto err1;
	}
	/*加密数据明文不能大于RSA_size(rsa)-11*/
	int len = RSA_size(rsa);
	if (len - 11 < strlen(text)) {
		fprintf(stderr, "text is too long\n");
		goto err2;
	}
	int size = RSA_private_encrypt(strlen(text), text, enctxt, rsa, padding);
	if (size < 0) {
		fprintf(stderr, "public key encrypt failed\n");
		goto err2;
	}
	int enc_64_len = (size/3*4) + 8;
	uchar *enctxt_64 = mem_calloc(1, enc_64_len);
	if (NULL == enctxt_64) {
		goto err2;
	}
	memset(enctxt_64, 0, enc_64_len);
	/*binary convert to base64 */
	base64x_encode_binary(enctxt_64, enctxt, size);
	RSA_free(rsa);
	return enctxt_64;
err2:
	RSA_free(rsa);
err1:
	return NULL;
}

/*decrypt for private key*/
uchar *rsa_pri_decrypt(uchar *prikey, uchar *text, int padding)
{
	uchar enc_bin[512] = {0};
	RSA *rsa = create_rsa(prikey, TYPE_PRI);
	if (NULL == rsa) {
		fprintf(stderr, "create pri rsa failed\n");
		goto err1;
	}
	if (NULL == text) {
		goto err1;
	}
	int size = RSA_size(rsa);
	int len = base64x_decode_binary(enc_bin, text);
	uchar *dectxt = mem_calloc(1, size);
	if (NULL == dectxt) {
		goto err2;
	}
	int ret = RSA_private_decrypt(size, enc_bin, dectxt, rsa, padding);
	if (ret < 0) {
		printf("decrypt failed\n");
		goto err3;
	}
	RSA_free(rsa);
	return dectxt;
err3:
	free(dectxt);
err2:
	RSA_free(rsa);
err1:
	return NULL;
}


uchar *pubkey = "-----BEGIN PUBLIC KEY-----\n"\
				"MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRj8aVvsFRyoCyIRp4Wep0YF9\n"\
				"dZBJZJgQZ/HcF7qbuuggPqKOXhgtHsPrVKcPD24Tn7McASOwwARji0kn+zjdiT4\n"\
				"FCkjuPmWCOmTSs66GEMwDqHr7A4ceKBW7NzTIlQ164VhI5NefnuNTBFGmzcGI4+\n"\
				"RcDEhIrTAxT4j9T3tsznQIDAQAB\n"\
				"-----END PUBLIC KEY-----\n";


uchar *prikey = "-----BEGIN RSA PRIVATE KEY-----\n"\
				"MIICXQIBAAKBgQDRj8aVvsFRyoCyIRp4Wep0YF9dZBJZJgQZ/HcF7qbuuggPqKOX\n"\
				"hgtHsPrVKcPD24Tn7McASOwwARji0kn+zjdiT4FCkjuPmWCOmTSs66GEMwDqHr7A\n"\
				"4ceKBW7NzTIlQ164VhI5NefnuNTBFGmzcGI4+RcDEhIrTAxT4j9T3tsznQIDAQAB\n"\
				"AoGAXXtol9YvQMA35r5To4pgxydSg0On17LYs4rmwXOzbdz4yZtt1qMKFyIA0uQ9\n"\
				"mvoq8Ja0MxFUoxlqM4yhS5RMKbUgjnGIyA8BYdQy0hQ1tBp1IWQD9XY0xMYJTHrv\n"\
				"CKwS9zps9Z5FToO2BN57nh6G7OEX4XPMidQOrSD6Htx6I5UCQQDs6i452kv4KsHQ\n"\
				"CPoDJ4SsNgDNZi9Az/Ge2q7LNbLS9pL/BGCD/B+ML8hgC9IYbfI9OfNOJ+uDOZqv\n"\
				"bWoU5jHXAkEA4nF/8iTzvHK64ddYBdbk+9ljLrXgE/UJ3uuYZhrafj7WlFuLK6pC\n"\
				"CkvXao2HToFiw34eEVLeK0u2TZh2YUw/qwJBAN4Pkkx/pH1z9j38a/rQ67ZO1+mu\n"\
				"QdRKFHuFFhk6t+atX5LQk3aitx87GmGMMtzbERb6Xmd/W2ygbbDIqYn1SfkCQFna\n"\
				"Oa/G0+RiDh/RSD9A7ym0L/P3/UtN/zWyfI1/eFWB77l8vbN84qmdQIQqVpdjJeJ2\n"\
				"p82t+TRq3ZLavZaMH/MCQQC8+1YVVtjyUcWpIN4U3WeosWFYP2mGkCakNXj8v1lG\n"\
				"EgBG/E5PSgZKRt++/Gg4lozofkZ0IFXtw0ju9G4wMQ0P\n"\
				"-----END RSA PRIVATE KEY-----\n";


/*test for public key encrypt then use private key decrypt*/
void test_pubenc_pridec()
{
	uchar *text = "Keep real by Sky";
	fprintf(stdout, "will encrypt plaintxt: %s\n", text);
	int padding = RSA_PKCS1_PADDING;
	uchar *enc_pub = rsa_pub_encrypt(pubkey, text, padding);
	if (NULL == enc_pub) {
		fprintf(stderr, "rsa public encrypt failed\n");
		goto err1;
	}
	fprintf(stdout, "enc: %s\n", enc_pub);
	uchar *dec_pri = rsa_pri_decrypt(prikey ,enc_pub, padding);
	if (NULL == dec_pri) {
		fprintf(stderr, "rsa public encrypt failed\n");
		goto err1;
	}
	fprintf(stdout, "dec: %s\n\n", dec_pri);
	free(enc_pub);
	free(dec_pri);
	return;
err2:
	free(enc_pub);
err1:
	return;
}

/*test for private key encrypt then use public key decrypt*/
void test_prienc_pubdec()
{
	uchar *text = "Be yourself by Sky";
	fprintf(stdout, "will encrypt plaintxt: %s\n", text);
	int padding = RSA_PKCS1_PADDING;
	uchar *enc_pri = rsa_pri_encrypt(prikey, text, padding);
	if (NULL == enc_pri) {
		fprintf(stderr, "rsa public encrypt failed\n");
		goto err1;
	}
	fprintf(stdout, "enc: %s\n", enc_pri);
	uchar *dec_pub = rsa_pub_decrypt(pubkey ,enc_pri, padding);
	if (NULL == dec_pub) {
		fprintf(stderr, "rsa public encrypt failed\n");
		goto err1;
	}
	fprintf(stdout, "dec: %s\n\n", dec_pub);
	free(enc_pri);
	free(dec_pub);
	return;
err2:
	free(enc_pri);
err1:
	return;
}

int main()
{
	test_pubenc_pridec();
	test_prienc_pubdec();
	return 0;
}
