#include "hmac.hpp"

#include <openssl/hmac.h>

namespace CppOpenSSL
{
CppHMAC::_OPENSSL_HMAC_FP CppHMAC::_fp[HMAC_GUARD] =
{
#ifndef OPENSSL_NO_MD2
	EVP_md2,
#else
	nullptr,
#endif
#ifndef OPENSSL_NO_MD4
	EVP_md4,
#else
	nullptr,
#endif
#ifndef OPENSSL_NO_MD5
	EVP_md5,
	EVP_md5_sha1,
#else
	nullptr,
	nullptr,
#endif
#ifndef OPENSSL_NO_BLAKE2
	EVP_blake2b512,
	EVP_blake2s256,
#else
	nullptr,
	nullptr,
#endif
	EVP_sha1,
	EVP_sha224,
	EVP_sha256,
	EVP_sha384,
	EVP_sha512,
	EVP_sha512_224,
	EVP_sha512_256,
	EVP_sha3_224,
	EVP_sha3_256,
	EVP_sha3_384,
	EVP_sha3_512,
	EVP_shake128,
	EVP_shake256,
#ifndef OPENSSL_NO_MDC2
	EVP_mdc2,
#else
	nullptr,
#endif
#ifndef OPENSSL_NO_RMD160
	EVP_ripemd160,
#else
	nullptr,
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
	EVP_whirlpool,
#else
	nullptr,
#endif
#ifndef OPENSSL_NO_SM3
	EVP_sm3
#else
	nullptr
#endif
};

CppHMAC::CppHMAC() :
_ctx(HMAC_CTX_free)
{
}

CppHMAC::~CppHMAC()
{
}

int CppHMAC::Init(int md, const char* key, int klen)
{
	_ctx.Reset(HMAC_CTX_new());
	if (_ctx == nullptr)
	{
		return 0;
	}

	if (HMAC_Init_ex(_ctx, key, klen, _fp[md](), nullptr) != 1)
	{
		return 0;
	}

	return static_cast<int>(HMAC_size(_ctx));
}

bool CppHMAC::Update(const char* from, int flen)
{
	return HMAC_Update(_ctx, CppUCast(from), flen) == 1;
}

bool CppHMAC::Final(char* to)
{
	unsigned int tlen = 0;

	return HMAC_Final(_ctx, CppUCast(to), &tlen) == 1;
}
}	// CppOpenSSL
