#ifndef __CPPOPENSSL_HMAC_HPP__
#define __CPPOPENSSL_HMAC_HPP__

#include "global.hpp"

typedef struct evp_md_st EVP_MD;
typedef struct hmac_ctx_st HMAC_CTX;

namespace CppOpenSSL
{
class CppHMAC
{
public:
	enum HMAC_MD
	{
		HMAC_MD2,			// EVP_md2
		HMAC_MD4,			// EVP_md4
		HMAC_MD5,			// EVP_md5
		HMAC_MD5_SHA1,		// EVP_md5_sha1
		HMAC_BLAKE2B512,	// EVP_blake2b512
		HMAC_BLAKE2S256,	// EVP_blake2s256
		HMAC_SHA1,			// EVP_sha1
		HMAC_SHA224,		// EVP_sha224
		HMAC_SHA256,		// EVP_sha256
		HMAC_SHA384,		// EVP_sha384
		HMAC_SHA512,		// EVP_sha512
		HMAC_SHA512_224,	// EVP_sha512_224
		HMAC_SHA512_256,	// EVP_sha512_256
		HMAC_SHA3_224,		// EVP_sha3_224
		HMAC_SHA3_256,		// EVP_sha3_256
		HMAC_SHA3_384,		// EVP_sha3_384
		HMAC_SHA3_512,		// EVP_sha3_512
		HMAC_SHAKE128,		// EVP_shake128
		HMAC_SHAKE256,		// EVP_shake256
		HMAC_MDC2,			// EVP_mdc2
		HMAC_RIPEMD160,		// EVP_ripemd160
		HMAC_WHIRLPOOL,		// EVP_whirlpool
		HMAC_SM3,			// EVP_sm3

		HMAC_GUARD
	};

public:
	CppHMAC();

	~CppHMAC();

public:
	int Init(int md, const char* key, int klen);

	bool Update(const char* from, int flen);

	bool Final(char* to);

private:
	typedef const EVP_MD* (*_OPENSSL_HMAC_FP)();

private:
	static _OPENSSL_HMAC_FP _fp[HMAC_GUARD];
	CppPtr<HMAC_CTX> _ctx;
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_HMAC_HPP__
