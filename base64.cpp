#include "base64.hpp"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

namespace CppOpenSSL
{
CppPtr<char> CppBASE64::Encode(const char* from, int flen, bool nl)
{
	CppPtr<BIO> bio_base64(BIO_free_all, BIO_new(BIO_f_base64()));
	if (bio_base64 == nullptr)
	{
		return nullptr;
	}

	if (!nl)
	{
		BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);
	}

	BIO* bio_mem = BIO_new(BIO_s_mem());
	if (bio_mem == nullptr)
	{
		return nullptr;
	}

	BIO_push(bio_base64, bio_mem);

	if (BIO_write(bio_base64, from, flen) < flen)
	{
		return nullptr;
	}

	if (BIO_flush(bio_base64) != 1)
	{
		return nullptr;
	}

	BUF_MEM* buf_mem = nullptr;

	BIO_get_mem_ptr(bio_mem, &buf_mem);
	BIO_set_close(bio_mem, BIO_NOCLOSE);

	return CppPtr<char>([=](void*) { BUF_MEM_free(buf_mem); }, buf_mem->data, buf_mem->length);
}

CppPtr<char> CppBASE64::Decode(const char* from, int flen, bool nl)
{
	CppPtr<BIO> bio_base64(BIO_free_all, BIO_new(BIO_f_base64()));
	if (bio_base64 == nullptr)
	{
		return nullptr;
	}

	if (!nl)
	{
		BIO_set_flags(bio_base64, BIO_FLAGS_BASE64_NO_NL);
	}

	BIO* bio_mem = BIO_new_mem_buf(from, flen);
	if (bio_mem == nullptr)
	{
		return nullptr;
	}

	BIO_push(bio_base64, bio_mem);

	int tlen = _LengthOfDecode(flen, nl);

	if (*reinterpret_cast<const short*>(from + flen - 2) == (static_cast<short>(_padding) << 8 | _padding))
	{
		tlen -= 2;
	}
	else if (from[flen - 1] == _padding)
	{
		tlen -= 1;
	}

	CppPtr<char> to(CppFree<char>, CppAlloc<char>(tlen), tlen);

	if (BIO_read(bio_base64, to, tlen) < tlen)
	{
		return nullptr;
	}

	return to;
}

int CppBASE64::_LengthOfDecode(int flen, bool nl)
{
	if (nl)
	{
		flen -= (flen - 1) / 65 + 1;
	}

	int tlen = flen / 4 * 3;

	return tlen;
}
}	// CppOpenSSL
