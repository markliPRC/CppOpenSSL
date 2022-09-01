#include "rsa.hpp"

#include <cstring>

#include <utility>

#include <openssl/bn.h>
#include <openssl/rsa.h>

namespace CppOpenSSL
{
CppRSA::_OPENSSL_RSA_FP CppRSA::_fp[4] =
{
	RSA_public_encrypt,
	RSA_public_decrypt,
	RSA_private_encrypt,
	RSA_private_decrypt
};

CppRSA::CppRSA() :
_method(0),
_from(nullptr),
_flen(0),
_key(nullptr),
_padding(0),
_mlen(0),
_blen(0),
_blo(0),
_to(nullptr)
{
}

CppRSA::~CppRSA()
{
}

CppPtr<RSA> CppRSA::GenerateKey(int bits, int e)
{
	CppPtr<RSA> key(RSA_free, RSA_new());
	if (key == nullptr)
	{
		return nullptr;
	}

	CppPtr<BIGNUM> bn_e(BN_free, BN_new());
	if (bn_e == nullptr)
	{
		return nullptr;
	}

	if (BN_set_word(bn_e, e) != 1)
	{
		return nullptr;
	}

	if (RSA_generate_key_ex(key, bits, bn_e, nullptr) != 1)
	{
		return nullptr;
	}

	return key;
}

bool CppRSA::GetKey(const RSA* key, CppPtr<char>& n, int& e, CppPtr<char>& d)
{
	const BIGNUM* bn_n = nullptr;
	const BIGNUM* bn_e = nullptr;
	const BIGNUM* bn_d = nullptr;
	RSA_get0_key(key, &bn_n, &bn_e, &bn_d);

	auto OPENSSL_freeFunc = [](void* ptr) { OPENSSL_free(ptr); };

	CppPtr<char> the_n(OPENSSL_freeFunc, BN_bn2hex(bn_n));
	int the_e = static_cast<int>(BN_get_word(bn_e));
	if (the_n == nullptr || the_e == -1)
	{
		return false;
	}

	n = std::move(the_n);
	e = the_e;

	if (bn_d != nullptr)
	{
		CppPtr<char> the_d(OPENSSL_freeFunc, BN_bn2hex(bn_d));
		if (the_d == nullptr)
		{
			return false;
		}

		d = std::move(the_d);
	}

	return true;
}

CppPtr<RSA> CppRSA::SetKey(const char* n, int e, const char* d)
{
	CppPtr<RSA> key(RSA_free, RSA_new());
	if (key == nullptr)
	{
		return nullptr;
	}

	CppPtr<BIGNUM> bn_n(BN_free, BN_new());
	CppPtr<BIGNUM> bn_e(BN_free, BN_new());
	if (bn_n == nullptr || bn_e == nullptr)
	{
		return nullptr;
	}

	if (BN_hex2bn(&bn_n, n) == 0 || BN_set_word(bn_e, e) != 1)
	{
		return nullptr;
	}

	if (RSA_set0_key(key, bn_n.Release(), bn_e.Release(), nullptr) != 1)
	{
		return nullptr;
	}

	if (d != nullptr)
	{
		CppPtr<BIGNUM> bn_d(BN_free, BN_new());
		if (bn_d == nullptr)
		{
			return nullptr;
		}

		if (BN_hex2bn(&bn_d, d) == 0)
		{
			return nullptr;
		}

		if (RSA_set0_key(key, nullptr, nullptr, bn_d.Release()) != 1)
		{
			return nullptr;
		}
	}

	return key;
}

int CppRSA::Init(int method, const char* from, int flen, RSA* key, int padding)
{
	_method = method;
	_from = CppUCast(from);
	_flen = flen;
	_key = key;
	_padding = padding;

	_mlen = RSA_size(_key);

	switch (_padding)
	{
	case RSA_PKCS1:
		_blen = _mlen - 12;
		break;
	case RSA_NO:
		_blen = _mlen;
		break;
	case RSA_PKCS1_OAEP:
		_blen = _mlen - 42;
		break;
	default:
		return 0;
	}

	int tlen = 0;

	if (_method == RSA_PUB_ENC || _method == RSA_PRIV_ENC)
	{
		if (_padding == RSA_NO)
		{
			_blo = _flen / _blen + 1;
		}
		else
		{
			_blo = _flen % _blen == 0 ? _flen / _blen : _flen / _blen + 1;
		}

		tlen = _mlen * _blo;
	}
	else
	{
		_blo = _flen / _mlen;
		tlen = _blen * _blo;
	}

	return tlen;
}

bool CppRSA::Do(char* to)
{
	_to = CppUCast(to);

	if (_method == RSA_PUB_ENC || _method == RSA_PRIV_ENC)
	{
		for (int i = 0; i < _blo - 1; ++i)
		{
			if (_fp[_method](_blen, _from + _blen * i, _to + _mlen * i, _key, _padding) == -1)
			{
				return false;
			}
		}
	}
	else
	{
		for (int i = 0; i < _blo - 1; ++i)
		{
			if (_fp[_method](_mlen, _from + _mlen * i, _to + _blen * i, _key, _padding) == -1)
			{
				return false;
			}
		}
	}

	return true;
}

bool CppRSA::Final(int& plen)
{
	if (_method == RSA_PUB_ENC || _method == RSA_PRIV_ENC)
	{
		int len = _flen - _blen * (_blo - 1);

		if (_padding == RSA_NO)
		{
			CppPtr<unsigned char> buff(CppFree<unsigned char>, CppAlloc<unsigned char>(_blen));

			memcpy(buff, _from + _blen * (_blo - 1), len);
			memset(buff + len, _blen - len, _blen - len);

			if (_fp[_method](_blen, buff, _to + _mlen * (_blo - 1), _key, _padding) == -1)
			{
				return false;
			}
		}
		else
		{
			if (_fp[_method](len, _from + _blen * (_blo - 1), _to + _mlen * (_blo - 1), _key, _padding) == -1)
			{
				return false;
			}
		}
	}
	else
	{
		int len = _fp[_method](_mlen, _from + _mlen * (_blo - 1), _to + _blen * (_blo - 1), _key, _padding);
		if (len == -1)
		{
			return false;
		}

		if (_padding == RSA_NO)
		{
			plen = _to[_blen * _blo - 1];
		}
		else
		{
			plen = _blen - len;
		}
	}

	return true;
}
}	// CppOpenSSL
