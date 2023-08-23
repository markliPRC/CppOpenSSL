#include "sha.hpp"

#include <openssl/sha.h>

namespace CppOpenSSL
{
CppSHA::CppSHA() :
_ctx(nullptr)
{
}

CppSHA::~CppSHA()
{
}

bool CppSHA::Init(int method)
{
	switch (method)
	{
	case SHA1:
		_ctx = CppPtr<SHA_CTX>(CppFree<SHA_CTX>, CppAlloc<SHA_CTX>());
		_SHA_InitFunc = std::bind(SHA1_Init, _ctx.Cast<SHA_CTX>());
		_SHA_UpdateFunc = std::bind(SHA1_Update, _ctx.Cast<SHA_CTX>(), std::placeholders::_1, std::placeholders::_2);
		_SHA_FinalFunc = std::bind(SHA1_Final, std::placeholders::_1, _ctx.Cast<SHA_CTX>());
		break;
	case SHA224:
		_ctx = CppPtr<SHA_CTX>(CppFree<SHA256_CTX, SHA_CTX>, CppAlloc<SHA256_CTX, SHA_CTX>());
		_SHA_InitFunc = std::bind(SHA224_Init, _ctx.Cast<SHA256_CTX>());
		_SHA_UpdateFunc = std::bind(SHA224_Update, _ctx.Cast<SHA256_CTX>(), std::placeholders::_1, std::placeholders::_2);
		_SHA_FinalFunc = std::bind(SHA224_Final, std::placeholders::_1, _ctx.Cast<SHA256_CTX>());
		break;
	case SHA256:
		_ctx = CppPtr<SHA_CTX>(CppFree<SHA256_CTX, SHA_CTX>, CppAlloc<SHA256_CTX, SHA_CTX>());
		_SHA_InitFunc = std::bind(SHA256_Init, _ctx.Cast<SHA256_CTX>());
		_SHA_UpdateFunc = std::bind(SHA256_Update, _ctx.Cast<SHA256_CTX>(), std::placeholders::_1, std::placeholders::_2);
		_SHA_FinalFunc = std::bind(SHA256_Final, std::placeholders::_1, _ctx.Cast<SHA256_CTX>());
		break;
	case SHA384:
		_ctx = CppPtr<SHA_CTX>(CppFree<SHA512_CTX, SHA_CTX>, CppAlloc<SHA512_CTX, SHA_CTX>());
		_SHA_InitFunc = std::bind(SHA384_Init, _ctx.Cast<SHA512_CTX>());
		_SHA_UpdateFunc = std::bind(SHA384_Update, _ctx.Cast<SHA512_CTX>(), std::placeholders::_1, std::placeholders::_2);
		_SHA_FinalFunc = std::bind(SHA384_Final, std::placeholders::_1, _ctx.Cast<SHA512_CTX>());
		break;
	case SHA512:
		_ctx = CppPtr<SHA_CTX>(CppFree<SHA512_CTX, SHA_CTX>, CppAlloc<SHA512_CTX, SHA_CTX>());
		_SHA_InitFunc = std::bind(SHA512_Init, _ctx.Cast<SHA512_CTX>());
		_SHA_UpdateFunc = std::bind(SHA512_Update, _ctx.Cast<SHA512_CTX>(), std::placeholders::_1, std::placeholders::_2);
		_SHA_FinalFunc = std::bind(SHA512_Final, std::placeholders::_1, _ctx.Cast<SHA512_CTX>());
		break;
	}

	return _SHA_InitFunc() == 1;
}

bool CppSHA::Update(const char* from, int flen)
{
	return _SHA_UpdateFunc(from, flen) == 1;
}

bool CppSHA::Final(char* to)
{
	return _SHA_FinalFunc(CppUCast(to)) == 1;
}
}	// CppOpenSSL
