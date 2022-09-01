#ifndef __CPPOPENSSL_AES_HPP__
#define __CPPOPENSSL_AES_HPP__

#include "global.hpp"

typedef struct aes_key_st AES_KEY;

namespace CppOpenSSL
{
class CppAES
{
public:
	enum AES_METHOD
	{
		AES_ECB,	// AES_ecb_encrypt
		AES_CBC,	// AES_cbc_encrypt
		AES_CFB128,	// AES_cfb128_encrypt
		AES_CFB1,	// AES_cfb1_encrypt
		AES_CFB8,	// AES_cfb8_encrypt
		AES_OFB128	// AES_ofb128_encrypt
	};

public:
	CppAES();

	~CppAES();

public:
	static bool GenerateKey(char* key, int klen);

	int Init(int method, const char* from, int flen, const char* key, int klen, const char ivec[16], bool enc);

	void Do(char* to);

	void Final(int& plen = CppLValue<int>::object);

private:
	int _method;
	const unsigned char* _from;
	int _flen;
	CppPtr<AES_KEY> _key;
	unsigned char _ivec[16];
	int _num;
	int _enc;
	int _blo;
	unsigned char* _to;
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_AES_HPP__
