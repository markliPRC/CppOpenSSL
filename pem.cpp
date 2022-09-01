#include "pem.hpp"

#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace CppOpenSSL
{
CppPtr<RSA> CppPEM::ReadRSAPubKey(const char* from, int flen)
{
	CppPtr<BIO> bio(BIO_free, BIO_new_mem_buf(from, flen));
	if (bio == nullptr)
	{
		return nullptr;
	}

	CppPtr<RSA> key(RSA_free, PEM_read_bio_RSAPublicKey(bio, nullptr, nullptr, nullptr));
	if (key == nullptr)
	{
		return nullptr;
	}

	return key;
}

CppPtr<RSA> CppPEM::ReadRSAPrivKey(const char* from, int flen)
{
	CppPtr<BIO> bio(BIO_free, BIO_new_mem_buf(from, flen));
	if (bio == nullptr)
	{
		return nullptr;
	}

	CppPtr<RSA> key(RSA_free, PEM_read_bio_RSAPrivateKey(bio, nullptr, nullptr, nullptr));
	if (key == nullptr)
	{
		return nullptr;
	}

	return key;
}

CppPtr<char> CppPEM::WriteRSAPubKey(const RSA* key)
{
	CppPtr<BIO> bio(BIO_free, BIO_new(BIO_s_mem()));
	if (bio == nullptr)
	{
		return nullptr;
	}

	if (PEM_write_bio_RSAPublicKey(bio, key) != 1)
	{
		return nullptr;
	}

	BUF_MEM* buf_mem = nullptr;

	BIO_get_mem_ptr(bio, &buf_mem);
	BIO_set_close(bio, BIO_NOCLOSE);

	return CppPtr<char>([=](void*) { BUF_MEM_free(buf_mem); }, buf_mem->data, buf_mem->length);
}

CppPtr<char> CppPEM::WriteRSAPrivKey(const RSA* key)
{
	CppPtr<BIO> bio(BIO_free, BIO_new(BIO_s_mem()));
	if (bio == nullptr)
	{
		return nullptr;
	}

	if (PEM_write_bio_RSAPrivateKey(bio, const_cast<RSA*>(key), nullptr, nullptr, 0, nullptr, nullptr) != 1)
	{
		return nullptr;
	}

	BUF_MEM* buf_mem = nullptr;

	BIO_get_mem_ptr(bio, &buf_mem);
	BIO_set_close(bio, BIO_NOCLOSE);

	return CppPtr<char>([=](void*) { BUF_MEM_free(buf_mem); }, buf_mem->data, buf_mem->length);
}
}	// CppOpenSSL
