#include "md5.hpp"

#include <openssl/md5.h>

namespace CppOpenSSL
{
CppMD5::CppMD5() :
_ctx(CppFree<MD5_CTX>)
{
}

CppMD5::~CppMD5()
{
}

bool CppMD5::Init()
{
	_ctx.Reset(CppAlloc<MD5_CTX>());

	return MD5_Init(_ctx) == 1;
}

bool CppMD5::Update(const char* from, int flen)
{
	return MD5_Update(_ctx, from, flen) == 1;
}

bool CppMD5::Final(char to[16])
{
	return MD5_Final(CppUCast(to), _ctx) == 1;
}
}	// CppOpenSSL
