#include <vector>
#include <string>
#include <cstring>
#include <cassert>

#include <iostream>


namespace circ {

//==================================================================================================
template<typename T>
struct basic_string_ref
{
	using value_type = T;

	constexpr basic_string_ref() :
		b{nullptr},
		e{nullptr} {}

	constexpr basic_string_ref(value_type *b, value_type *e) :
		b{b},
		e{e} {}

	constexpr basic_string_ref(value_type *s) :
		b{s},
		e{s + std::strlen(s)} {}

	template<typename U>
	constexpr basic_string_ref(basic_string_ref<U> const &rhs) :
		b{rhs.b},
		e{rhs.e} {}

	bool empty() const { return b == e; }
	size_t size() const { return e - b; }

	value_type *b, *e;
};

using string_ref = basic_string_ref<char>;
using cstring_ref = basic_string_ref<char const>;


template<typename T>
bool operator == (basic_string_ref<T> const &a, basic_string_ref<T> const &b)
{
	if(a.size() != b.size())
		return false;

	auto cur_a = a.b;
	auto cur_b = b.b;
	while(cur_a != a.e)
	{
		if(*cur_a++ != *cur_b++)
			return false;
	}

	return true;
}

template<typename T>
std::ostream& operator << (std::ostream &os, basic_string_ref<T> a)
{
	while(a.b != a.e)
		os << a.b++;

	return os;
}

template<typename T, typename Str>
bool operator == (basic_string_ref<T> const &a, Str const *str)
{
	return a == basic_string_ref<Str const>{str};
}

template<typename T>
std::basic_string<typename std::remove_const<T>::type> to_str(basic_string_ref<T> const &ref)
{
	return {ref.b, ref.e};
}

template<typename T>
bool starts_with(basic_string_ref<T> const &ref, typename std::remove_const<T>::type const *str)
{
	auto cur = ref.b;
	while(cur != ref.e && *str)
	{
		if(*cur++ != *str++)
			return false;
	}

	return *str == 0;
}

template<typename T>
bool starts_with(basic_string_ref<T> a, basic_string_ref<T> b)
{
	if(a.size() < b.size())
		return false;

	while(a.b != a.e && b.b != b.e)
	{
		if(*a.b++ != *b.b++)
			return false;
	}

	return true;
}

template<typename OutIt, typename T>
OutIt iota_n(OutIt it, size_t n, T value)
{
	while(n--)
	{
		*it++ = value;
		++value;
	}

	return it;
}


//==================================================================================================
// All bits in `val` above `width` must be zero.
template<typename T>
T sign_extend(T val, int width)
{
	// See http://graphics.stanford.edu/~seander/bithacks.html
	T m = T{1} << (width - 1);
	return (val ^ m) - m;
}

template<typename T>
bool is_power_of_two(T t)
{
	return t != 0 && !(t & (t - 1));
}

template<typename T>
T set_leading_ones(int count)
{
	if(count == sizeof(T) * 8)
		return -1;
	else
		return (T{1} << count) - 1;
}

template<typename T>
T extract_bits(T val, int start, int count)
{
	assert(start >= 0 && start + count <= (int)sizeof(T) * 8);

	return (val >> start) & set_leading_ones<T>(count);
}

inline uint64_t extract_bits(std::vector<uint8_t> const &data, int start, int count)
{
	assert(count <= 64);

	auto byte_idx = start / 8;
	auto num_bits_read = 0;

	uint64_t val = 0;
	int num_bits_in_first_byte = std::min(count, 8 - start % 8);
	val |= extract_bits(data[byte_idx++], start % 8, num_bits_in_first_byte);
	num_bits_read += num_bits_in_first_byte;

	while(count - num_bits_read >= 8)
	{
		val |= (uint64_t)data[byte_idx++] << num_bits_read;
		num_bits_read += 8;
	}

	auto remaining_bits = count - num_bits_read;
	if(remaining_bits)
		val |= uint64_t(data[byte_idx] & set_leading_ones<uint8_t>(remaining_bits)) << num_bits_read;

	assert(num_bits_read + remaining_bits == count);

	return val;
}


//==================================================================================================
struct nullopt_t {};
constexpr nullopt_t nullopt;

template<typename T>
class optional
{
public:
	using value_type = T;

	optional() :
		m_init{false} {}

	optional(nullopt_t) :
		m_init{false} {}

	optional(T const &v)
	{
		new (&m_value) T(v);
		m_init = true;
	}

	~optional() { clear(); }

	optional& operator = (T const &v)
	{
		if(m_init)
			value_unchecked() = v;
		else
		{
			new (&m_value) T(v);
			m_init = true;
		}

		return *this;
	}

	void clear()
	{
		if(m_init)
			reinterpret_cast<T*>(&m_value)->~T();
	}

	T& operator * () { return value(); }
	T const& operator * () const { return value(); }

	T* operator -> () { return &value(); }
	T const* operator -> () const { return &value(); }

	explicit operator bool () const { return m_init; }

	T& value()
	{
		if(!m_init)
			throw std::runtime_error{"optional is not initialized"};

		return value_unchecked();
	}

	T const& value() const
	{
		if(!m_init)
			throw std::runtime_error{"optional is not initialized"};

		return value_unchecked();
	}

	T& value_unchecked()
	{
		return *reinterpret_cast<T*>(&m_value);
	}

	T const& value_unchecked() const
	{
		return *reinterpret_cast<T const*>(&m_value);
	}

private:
	bool m_init;
	typename std::aligned_storage<sizeof(T), alignof(T)>::type m_value;
};

}
