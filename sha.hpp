#ifndef __CPPOPENSSL_SHA_HPP__
#define __CPPOPENSSL_SHA_HPP__

#include "global.hpp"

typedef struct SHAstate_st SHA_CTX;

namespace CppOpenSSL
{
class CppSHA
{
public:
	enum SHA_METHOD
	{
		SHA1,
		SHA224,
		SHA256,
		SHA384,
		SHA512
	};

public:
	CppSHA();

	~CppSHA();

public:
	bool Init(int method);

	bool Update(const char* from, int flen);

	bool Final(char* to);

private:
	CppPtr<SHA_CTX> _ctx;
	std::function<bool()> _SHA_InitFunc;
	std::function<bool(const void*, size_t)> _SHA_UpdateFunc;
	std::function<bool(unsigned char*)> _SHA_FinalFunc;
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_SHA_HPP__
