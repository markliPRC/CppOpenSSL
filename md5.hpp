#ifndef __CPPOPENSSL_MD5_HPP__
#define __CPPOPENSSL_MD5_HPP__

#include "global.hpp"

typedef struct MD5state_st MD5_CTX;

namespace CppOpenSSL
{
class CppMD5
{
public:
	CppMD5();

	~CppMD5();

public:
	bool Init();

	bool Update(const char* from, int flen);

	bool Final(char to[16]);

private:
	CppPtr<MD5_CTX> _ctx;
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_MD5_HPP__
