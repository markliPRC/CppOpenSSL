#include "aes.hpp"

#include <cstring>

#include <openssl/aes.h>
#include <openssl/rand.h>

namespace CppOpenSSL
{
CppAES::CppAES() :
_method(0),
_from(nullptr),
_flen(0),
_key(CppFree<AES_KEY>),
_num(0),
_enc(0),
_blo(0),
_to(nullptr)
{
	memset(_ivec, 0, 16);
}

CppAES::~CppAES()
{
}

bool CppAES::GenerateKey(char* key, int klen)
{
	return RAND_bytes(CppUCast(key), klen) == 1;
}

int CppAES::Init(int method, const char* from, int flen, const char* key, int klen, const char ivec[16], bool enc)
{
	_method = method;
	_from = CppUCast(from);
	_flen = flen;
	_key.Reset(CppAlloc<AES_KEY>());
	if (ivec != nullptr) memcpy(_ivec, ivec, 16);
	_num = 0;
	_enc = enc ? AES_ENCRYPT : AES_DECRYPT;

	int (*fp)(const unsigned char*, const int, AES_KEY*) = nullptr;

	if (_method == AES_ECB || _method == AES_CBC)
	{
		if (_enc == AES_ENCRYPT)
		{
			fp = AES_set_encrypt_key;
		}
		else
		{
			fp = AES_set_decrypt_key;
		}
	}
	else
	{
		fp = AES_set_encrypt_key;
	}

	if (fp(CppUCast(key), 8 * klen, _key) != 0)
	{
		return 0;
	}

	int tlen = 0;

	if (_method == AES_ECB || _method == AES_CBC)
	{
		if (_enc == AES_ENCRYPT)
		{
			_blo = _flen / 16 + 1;
		}
		else
		{
			_blo = _flen / 16;
		}

		tlen = 16 * _blo;
	}
	else
	{
		tlen = _flen;
	}

	return tlen;
}

void CppAES::Do(char* to)
{
	_to = CppUCast(to);

	if (_method == AES_ECB)
	{
		int blo = _enc == AES_ENCRYPT ? _blo - 1 : _blo;

		for (int i = 0; i < blo; ++i)
		{
			AES_ecb_encrypt(_from + 16 * i, _to + 16 * i, _key, _enc);
		}
	}
	else if (_method == AES_CBC)
	{
		int blo = _enc == AES_ENCRYPT ? _blo - 1 : _blo;

		if (blo > 0)
		{
			AES_cbc_encrypt(_from, _to, 16 * blo, _key, _ivec, _enc);
		}
	}
	else if (_method == AES_CFB128)
	{
		AES_cfb128_encrypt(_from, _to, _flen, _key, _ivec, &_num, _enc);
	}
	else if (_method == AES_CFB1)
	{
		AES_cfb1_encrypt(_from, _to, 8 * _flen, _key, _ivec, &_num, _enc);
	}
	else if (_method == AES_CFB8)
	{
		AES_cfb8_encrypt(_from, _to, _flen, _key, _ivec, &_num, _enc);
	}
	else if (_method == AES_OFB128)
	{
		AES_ofb128_encrypt(_from, _to, _flen, _key, _ivec, &_num);
	}
}

void CppAES::Final(int& plen)
{
	if (_method == AES_ECB || _method == AES_CBC)
	{
		if (_enc == AES_ENCRYPT)
		{
			unsigned char buff[16] = {};
			int len = _flen - 16 * (_blo - 1);

			memcpy(buff, _from + 16 * (_blo - 1), len);
			memset(buff + len, 16 - len, 16 - len);

			if (_method == AES_ECB)
			{
				AES_ecb_encrypt(buff, _to + 16 * (_blo - 1), _key, _enc);
			}
			else
			{
				AES_cbc_encrypt(buff, _to + 16 * (_blo - 1), 16, _key, _ivec, _enc);
			}
		}
		else
		{
			plen = _to[16 * _blo - 1];
		}
	}
}
}	// CppOpenSSL
