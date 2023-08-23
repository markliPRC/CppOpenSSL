#ifndef __CPPOPENSSL_GLOBAL_HPP__
#define __CPPOPENSSL_GLOBAL_HPP__

#include <cstddef>

#include <functional>
#include <type_traits>

namespace CppOpenSSL
{
template <typename T, typename U = T>
inline U* CppAlloc(int n = 1)
{
	T* ptr = new T[n]();
	return reinterpret_cast<U*>(ptr);
}

template <typename T, typename U = T>
inline void CppFree(U* ptr)
{
	delete[] reinterpret_cast<T*>(ptr);
}

template <typename T>
inline auto CppUCast(T* ptr)
{
	return reinterpret_cast<typename std::make_unsigned<T>::type*>(ptr);
}

template <typename T>
struct CppLValue
{
	inline static T object;
};

template <typename T>
class CppPtr
{
public:
	CppPtr(std::nullptr_t) :
	_ptr(nullptr),
	_n(-1)
	{
	}

	template <typename U>
	explicit CppPtr(U deleter, T* ptr = nullptr, int n = -1) :
	_deleter(std::bind(deleter, std::placeholders::_1)),
	_ptr(ptr),
	_n(n)
	{
	}

	~CppPtr()
	{
		Reset();
	}

	CppPtr(CppPtr<T>&& other) :
	_deleter(other._deleter),
	_ptr(other._ptr),
	_n(other._n)
	{
		other.Release();
	}

	CppPtr<T>& operator =(CppPtr<T>&& other)
	{
		Reset();
		_deleter = other._deleter;
		_ptr = other._ptr;
		_n = other._n;
		other.Release();
		return *this;
	}

	bool operator ==(const T* ptr) const
	{
		return _ptr == ptr;
	}

	bool operator !=(const T* ptr) const
	{
		return !operator ==(ptr);
	}

	operator T*()
	{
		return _ptr;
	}

	T* operator ->()
	{
		return _ptr;
	}

	T** operator &()
	{
		return &_ptr;
	}

	T& operator *()
	{
		return *_ptr;
	}

public:
	template <typename U>
	U* Cast()
	{
		return reinterpret_cast<U*>(_ptr);
	}

	T* Release()
	{
		T* ptr = _ptr;
		_ptr = nullptr;
		_n = -1;
		return ptr;
	}

	void Reset(T* ptr = nullptr, int n = -1)
	{
		if (_ptr != nullptr)
		{
			_deleter(_ptr);
		}

		_ptr = ptr;
		_n = n;
	}

	int Size()
	{
		return _n;
	}

private:
	std::function<void(T*)> _deleter;
	T* _ptr;
	int _n;
};

class CppUtil
{
public:
	static void Bytes2String(const char* from, int flen, char* to)
	{
		static const char hex[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};

		for (int i = 0; i < flen; ++i)
		{
			unsigned char c = from[i];

			to[2 * i] = hex[c >> 4];
			to[2 * i + 1] = hex[c & 0xF];
		}
	}
};
}	// CppOpenSSL

#endif	// __CPPOPENSSL_GLOBAL_HPP__
