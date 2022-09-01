#ifndef __CPPOPENSSL_BASE64_HPP__
#define __CPPOPENSSL_BASE64_HPP__

#include "global.hpp"

namespace CppOpenSSL
{
class CppBASE64
{
public:
	static CppPtr<char> Encode(const char* from, int flen, bool nl);

	static CppPtr<char> Decode(const char* from, int flen, bool nl);

private:
	static int _LengthOfDecode(int flen, bool nl);

private:
	static const char _padding = '=';
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_BASE64_HPP__
