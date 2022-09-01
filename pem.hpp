#ifndef __CPPOPENSSL_PEM_HPP__
#define __CPPOPENSSL_PEM_HPP__

#include "global.hpp"

typedef struct rsa_st RSA;

namespace CppOpenSSL
{
class CppPEM
{
public:
	static CppPtr<RSA> ReadRSAPubKey(const char* from, int flen);

	static CppPtr<RSA> ReadRSAPrivKey(const char* from, int flen);

	static CppPtr<char> WriteRSAPubKey(const RSA* key);

	static CppPtr<char> WriteRSAPrivKey(const RSA* key);
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_PEM_HPP__
