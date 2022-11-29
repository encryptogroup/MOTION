#pragma once

#include <cassert>
#include <algorithm>
#include <stdexcept>
#include <string>
#include <cstring>
#include <cstddef>
#include <iostream>
#include <sstream>
#include <map>

#include "sorted_vector.h"


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

  template<typename U>
    constexpr basic_string_ref(std::basic_string<U> const &rhs) :
      b{rhs.data()},
    e{rhs.data() + rhs.size()} {}

  char const& operator [] (ptrdiff_t i) const
  {
    assert(i < (ptrdiff_t)size());
    return b[i];
  }

  bool empty() const { return b == e; }
  size_t size() const { return e - b; }

  value_type& back() { assert(size()); return e[-1]; }
  value_type const& back() const { assert(size()); return e[-1]; }

  value_type *b, *e;
};

using string_ref = basic_string_ref<char>;
using cstring_ref = basic_string_ref<char const>;


template<typename T>
T* begin(basic_string_ref<T> const &s)
{
  return s.b;
}

template<typename T>
T* end(basic_string_ref<T> const &s)
{
  return s.e;
}


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
bool operator == (basic_string_ref<T> const &a, std::basic_string<typename std::remove_const<T>::type> const &b)
{
  return a == basic_string_ref<T>{b};
}

template<typename T>
bool operator < (basic_string_ref<T> const &a, basic_string_ref<T> const &b)
{
  auto cur_a = a.b;
  auto cur_b = b.b;
  while(cur_a != a.e && cur_b != b.e)
  {
    if(*cur_a < *cur_b)
      return true;

    if(*cur_a > *cur_b)
      return false;

    ++cur_a;
    ++cur_b;
  }

  return cur_b != b.e;
}

template<typename T>
std::ostream& operator << (std::ostream &os, basic_string_ref<T> a)
{
  return os.write(a.b, a.size());
}

template<typename T, typename Str>
bool operator == (basic_string_ref<T> const &a, Str const *str)
{
  return a == basic_string_ref<Str const>{str};
}

template<typename T>
std::basic_string<typename std::remove_const<T>::type> str(basic_string_ref<T> const &ref)
{
  return {ref.b, ref.e};
}

inline std::string operator + (std::string str,cstring_ref ref)
{
  str.reserve(str.size() + ref.size());
  str.append(ref.b, ref.e);
  return str;
}

template<typename T>
basic_string_ref<T> substr_ref(std::basic_string<T> const &str, size_t start, size_t length)
{
  assert(start + length < str.size());
  return {&str[start], &str[start + length]};
}

template<typename T>
bool starts_with(basic_string_ref<T const> const &subject, T const *suffix)
{
  auto cur = subject.b;
  while(cur != subject.e && *suffix)
  {
    if(*cur++ != *suffix++)
      return false;
  }

  return *suffix == 0;
}

template<typename T>
bool starts_with(std::basic_string<T> const &str, T const *prefix)
{
  return starts_with(basic_string_ref<T const>{str}, prefix);
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

template<typename S, typename T>
bool ends_with(basic_string_ref<S> const &subject, basic_string_ref<T> const &suffix)
{
  if(suffix.size() > subject.size())
    return false;

  return std::equal(subject.e - suffix.size(), subject.e, suffix.b);
}

template<typename T>
bool ends_with(basic_string_ref<T const> const &str, T const *suffix)
{
  return ends_with(str, basic_string_ref<T const>{suffix});
}

template<typename T>
bool ends_with(std::basic_string<T> const &str, T const *suffix)
{
  return ends_with(basic_string_ref<T const>{str}, basic_string_ref<T const>{suffix});
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


struct Identity
{
	template<typename T>
	T&& operator () (T &&v) const { return std::forward<T>(v); }
};


template<typename Range, typename Projection = Identity>
void join(std::ostream &os, Range const &range, char const *sep, Projection &&proj = Identity{})
{
  using std::begin;
  using std::end;

  auto first = begin(range);
  auto last = end(range);

  if(first == last)
    return;

  os << proj(*first);
  while(++first != last)
    os << sep << proj(*first);
}

template<typename Range, typename Projection = Identity>
std::string join(Range const &range, char const *sep, Projection &&proj = Identity{})
{
  std::stringstream ss;
  join(ss, range, sep, proj);
  return ss.str();
}


template<typename Func>
void for_each_piece(cstring_ref str, char sep, Func &&func)
{
  cstring_ref piece{str.b, std::find(str.b, str.e, sep)};
  func(str);

  while(piece.e != str.e)
  {
    piece = {piece.e+1, std::find(piece.e+1, str.e, sep)};
    func(piece);
  }
}

template<typename T>
basic_string_ref<T> trim(basic_string_ref<T> str)
{
  while(str.size() && std::isspace(*str.b))
    ++str.b;

  while(str.size() && std::isspace(str.back()))
    --str.e;

  return str;
}

template<typename T>
bool isalpha(basic_string_ref<T> str)
{
  for(char c: str)
  {
    if(!std::isalpha(c))
      return false;
  }

  return true;
}


// Quick and dirty implementation of optional<> so we don't depend on C++14
//==================================================================================================
struct emptyopt_t {};
constexpr emptyopt_t emptyopt;

template<typename T>
class optional
{
public:
  using value_type = T;

  optional() :
    m_init{false} {}

  optional(emptyopt_t) :
    m_init{false} {}

  optional(T const &v)
  {
    new (&m_value) T(v);
    m_init = true;
  }

  optional(T &&v)
  {
    new (&m_value) T(std::move(v));
    m_init = true;
  }

  optional(optional const &rhs)
  {
    m_init = rhs.m_init;
    if(m_init)
      new (&m_value) T(rhs.value_unchecked());
  }

  ~optional() { clear(); }

  optional& operator = (optional const &rhs)
  {
    if(rhs.m_init)
      *this = rhs.value_unchecked();
    else
      clear();

    return *this;
  }

  // TODO Implement
  optional& operator = (optional &&rhs) = delete;

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

  optional& operator = (T &&v)
  {
    if(m_init)
      value_unchecked() = std::move(v);
    else
    {
      new (&m_value) T(std::move(v));
      m_init = true;
    }

    return *this;
  }

  optional& operator = (emptyopt_t)
  {
	  clear();
  }

  void clear()
  {
    if(m_init)
    {
      value_unchecked().~T();
      m_init = false;
    }
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


//==================================================================================================
template<typename T>
struct IteratorRange
{
  using iterator = T;
  using value_type = typename std::iterator_traits<T>::value_type;
  using reference = typename std::iterator_traits<T>::reference;

  IteratorRange() :
    b{},
    e{} {}

  IteratorRange(iterator begin, iterator end) :
    b{begin},
    e{end} {}

  bool empty() const { return b == e; }
  size_t size() const { return e - b; }

  reference front() { assert(!empty()); return *b; }
  reference back() { assert(!empty()); return *std::prev(e); }
  reference operator [] (ptrdiff_t idx) const { return b[idx]; }

  iterator b, e;
};

template<typename T>
T begin(IteratorRange<T> const &r)
{
  return r.b;
}

template<typename T>
T end(IteratorRange<T> const &r)
{
  return r.e;
}


template<typename It>
class PairFirstIterator
{
public:
  using traits = std::iterator_traits<It>;
  using PairType = typename traits::value_type;

  // Try to guess if the pair is const
  static constexpr bool is_const = std::is_const<typename std::remove_pointer<typename traits::pointer>::type>::value;

  using difference_type = typename traits::difference_type;
  using value_type = typename PairType::first_type;
  using pointer = typename std::conditional<is_const, value_type const*, value_type*>::type;
  using reference = typename std::conditional<is_const, value_type const&, value_type&>::type;
  using iterator_category = typename traits::iterator_category;

  PairFirstIterator(It it) :
    m_it{it} {}


  reference operator * () const { return m_it->first; }
  pointer operator -> () const { return &m_it->first; }

  PairFirstIterator& operator ++ () { ++m_it; return *this; }
  PairFirstIterator operator ++ (int)
  {
    auto tmp = *this;
    ++m_it;
    return tmp;
  }

  PairFirstIterator& operator -- () { --m_it; return *this; }
  PairFirstIterator operator -- (int)
  {
    auto tmp = *this;
    --m_it;
    return tmp;
  }

  friend bool operator == (PairFirstIterator a, PairFirstIterator b) { return a.m_it == b.m_it; }
  friend bool operator != (PairFirstIterator a, PairFirstIterator b) { return a.m_it != b.m_it; }

private:
  It m_it;
};


template<typename It>
class PairSecondIterator
{
public:
  using traits = std::iterator_traits<It>;
  using PairType = typename traits::value_type;

  // Try to guess if the pair is const
  static constexpr bool is_const = std::is_const<typename std::remove_pointer<typename traits::pointer>::type>::value;

  using difference_type = typename traits::difference_type;
  using value_type = typename PairType::second_type;
  using pointer = typename std::conditional<is_const, value_type const*, value_type*>::type;
  using reference = typename std::conditional<is_const, value_type const&, value_type&>::type;
  using iterator_category = typename traits::iterator_category;

  PairSecondIterator(It it) :
    m_it{it} {}

  reference operator * () const { return m_it->second; }
  pointer operator -> () const { return &m_it->second; }

  PairSecondIterator& operator ++ () { ++m_it; return *this; }
  PairSecondIterator operator ++ (int)
  {
    auto tmp = *this;
    ++m_it;
    return tmp;
  }

  PairSecondIterator& operator -- () { --m_it; return *this; }
  PairSecondIterator operator -- (int)
  {
    auto tmp = *this;
    --m_it;
    return tmp;
  }

  friend bool operator == (PairSecondIterator a, PairSecondIterator b) { return a.m_it == b.m_it; }
  friend bool operator != (PairSecondIterator a, PairSecondIterator b) { return a.m_it != b.m_it; }

private:
  It m_it;
};

template<typename K, typename V, typename A>
IteratorRange<PairSecondIterator<typename std::map<K, V, A>::const_iterator>>
values(std::map<K, V, A> const &m)
{
	return {{m.begin()}, {m.end()}};
}

//==================================================================================================
template<typename T, typename Tag>
struct TaggedValue
{
	using value_type = T;

	TaggedValue() = default;
	explicit TaggedValue(T value) :
		value{value} {}

	// To make a TaggedValue usable with std::iota()
	TaggedValue& operator ++ ()
	{
		++value;
		return *this;
	}

	value_type value;
};

template<typename T, typename Tag>
inline bool operator < (TaggedValue<T, Tag> const &a, TaggedValue<T, Tag> const &b)
{
	return a.value < b.value;
}

template<typename T, typename Tag>
inline bool operator <= (TaggedValue<T, Tag> const &a, TaggedValue<T, Tag> const &b)
{
	return a.value <= b.value;
}



namespace std {

template<typename T, typename Tag>
struct hash<::TaggedValue<T, Tag>>
{
	using argument_type = ::TaggedValue<T, Tag>;
	using result_type = size_t;

	result_type operator () (argument_type const &v) const
	{
		return hash<T>{}(v.value);
	}
};

}


//==================================================================================================
template<typename Range, typename Func>
typename Range::iterator combine_pairs(Range &range, Func &&func)
{
  using std::begin;
  using std::end;

  auto first = begin(range);
  auto last = end(range);
  if(first == last)
    return last;

  auto insert_pos = first;
  auto second = std::next(first);
  while(second != last)
  {
    *insert_pos = func(*first, *second);
    ++insert_pos;

    if(++second != last)
      ++second;

    std::advance(first, 2);
  }

  if(first != last)
  {
    *insert_pos = *first;
    ++insert_pos;
  }

  return insert_pos;
}


template<typename Range, typename Func>
typename Range::value_type& build_tree(Range &range, Func &&func)
{
  using ValueType = typename Range::value_type;
  using ItRange = IteratorRange<typename Range::iterator>;

  using std::begin;
  using std::end;

  if(range.empty())
    throw std::runtime_error{"build_tree(): range is empty"};

  ItRange sub_range{begin(range), end(range)};
  auto second = std::next(begin(range));
  int level = 0;
  while(second != sub_range.e)
  {
    sub_range.e = combine_pairs(sub_range, [&](ValueType const &a, ValueType const &b)
    {
      return func(a, b, level);
    });

    level++;
  }

  return *sub_range.b;
}


template<typename Range, typename Pred>
ptrdiff_t count_if(Range const &range, Pred pred)
{
  using std::begin;
  using std::end;

  return std::count_if(begin(range), end(range), pred);
}

template<typename Range, typename Pred>
typename Range::const_iterator find_if(Range const &range, Pred pred)
{
  using std::begin;
  using std::end;

  return std::find_if(begin(range), end(range), pred);
}


//==================================================================================================
inline int log2_ceil(int n)
{
  int res = 1;
  while((1 << res) < n)
    res++;

  return res;
}

inline uint32_t previous_power_of_two(uint32_t x)
{
  x = x | (x >> 1);
  x = x | (x >> 2);
  x = x | (x >> 4);
  x = x | (x >> 8);
  x = x | (x >> 16);
  return x - (x >> 1);
}

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


template<typename T, typename S>
void set_bits(T &val, S new_val, int start, int count)
{
	assert(start >= 0 && start + count <= (int)sizeof(T) * 8);

	int total_bits = sizeof(T)*8;
	val |= (new_val << (total_bits - count)) >> (total_bits - count - start);
}

inline void set_bits_aligned(std::vector<uint8_t> &data, uint64_t new_value, int byte_offset, int bit_count)
{
	size_t num_bytes = (bit_count + 7) / 8;
	if(data.size() < byte_offset + num_bytes)
		data.resize(data.size() + byte_offset + num_bytes);

	int num_complete_bytes = bit_count / 8;
	for(int i = 0; i < num_complete_bytes; ++i)
		data[byte_offset + i] |= (new_value >> (i * 8)) & 0xff;

	if(bit_count % 8)
	{
		uint8_t mask = (1 << (bit_count % 8)) - 1;
		data[byte_offset + num_complete_bytes] |= (new_value >> (num_complete_bytes * 8)) & mask;
	}
}

inline void set_bits(std::vector<uint8_t> &data, uint64_t new_value, int start, int count)
{
	auto byte_idx = start / 8;
	size_t num_bytes = (count + 7) / 8;
	if(data.size() < byte_idx + num_bytes)
		data.resize(data.size() + byte_idx + num_bytes);

	if(start % 8)
	{
		int num_bits_in_first_byte = std::min(count, 8 - start % 8);
		int bit_offset = start % 8;
		set_bits(data[byte_idx], new_value, bit_offset, num_bits_in_first_byte);
		byte_idx++;
		new_value >>= num_bits_in_first_byte;
		count -= num_bits_in_first_byte;
	}

	set_bits_aligned(data, new_value, byte_idx, count);
}


//==================================================================================================
template<typename T>
struct Raw
{
  explicit Raw(T t) :
    value{t} {}

  T value;
};

using RawUInt8 = Raw<uint8_t>;
using RawUInt32 = Raw<uint32_t>;
using RawInt32 = Raw<int32_t>;
using RawString = Raw<std::string const*>;
using RawCString = Raw<char const*>;

template<typename T>
std::ostream& operator << (std::ostream &os, Raw<T> raw)
{
  return os.write((char const*)&raw.value, sizeof(T));
}

inline std::ostream& operator << (std::ostream &os, RawString raw)
{
  return os.write(raw.value->c_str(), raw.value->length() + 1);
}

inline std::ostream& operator << (std::ostream &os, RawCString raw)
{
  return os.write(raw.value, strlen(raw.value) + 1);
}


//==================================================================================================
template<typename T>
void read_binary(std::istream &is, T &v)
{
	is.read((char*)&v, sizeof(v));
}

inline void read_binary(std::istream &is, std::string &v)
{
	std::getline(is, v, '\0');
}

struct RawReader
{
	std::istream &is;

	template<typename T>
	T read()
	{
		T v;
		read_binary(is, v);
		return v;
	}

	explicit operator bool () { return (bool)is; }
};

inline RawReader& operator >> (RawReader &rr, uint8_t &v)
{
	rr.is.read((char*)&v, sizeof(v));
	return rr;
}

inline RawReader& operator >> (RawReader &rr, uint32_t &v)
{
	rr.is.read((char*)&v, sizeof(v));
	return rr;
}

inline RawReader& operator >> (RawReader &rr, std::string &v)
{
	std::getline(rr.is, v, '\0');
	return rr;
}


//==================================================================================================
// Taken from Boost
template <class T>
inline void hash_combine(std::size_t& seed, const T& v)
{
  std::hash<T> hasher;
  seed ^= hasher(v) + 0x9e3779b9 + (seed<<6) + (seed>>2);
}


struct PairHash
{
  template<typename A, typename B>
  size_t operator () (std::pair<A, B> const &p) const
  {
    size_t hash = std::hash<A>{}(p.first);
    hash_combine(hash, p.second);

    return hash;
  }
};


struct SortedVectorHash
{
  template<typename T, bool NoDups, typename Pr, typename Alloc>
  size_t operator () (sorted_vector<T, NoDups, Pr, Alloc> const &p) const
  {
    size_t hash = std::hash<size_t>{}(p.size());
    for(auto const &v: p)
      hash_combine(hash, v);

    return hash;
  }
};

struct VectorHash
{
  template<typename T, typename Alloc>
  size_t operator () (std::vector<T, Alloc> const &p) const
  {
    size_t hash = std::hash<size_t>{}(p.size());
    for(auto const &v: p)
      hash_combine(hash, v);

    return hash;
  }
};


//==================================================================================================
constexpr size_t NPOS = -1;


inline size_t count_trailing_zeros(uint32_t val)
{
  if(val == 0)
    return 32;

  return __builtin_ctz(val);
}

inline size_t count_trailing_zeros(uint64_t val)
{
  if(val == 0)
    return 64;

  return __builtin_ctzll(val);
}

template<typename T>
size_t find_bit(T val, size_t start_idx = 0)
{
  // Set bits before `start_idx` to zero
  val &= ~T(0) << start_idx;

  if(val == 0)
    return NPOS;

  return count_trailing_zeros(val);
}


class bitset
{
public:
  using word_type = uintptr_t;
  static constexpr size_t num_word_bits = sizeof(word_type) * 8;

  static_assert(!(num_word_bits & (num_word_bits - 1)), "num_word_bits must be power of two");


  bitset() :
    m_data_or_ptr{1} {}

  bitset(bitset const &rhs)
  {
    if(rhs.is_small())
      m_data_or_ptr = rhs.m_data_or_ptr;
    else
      set_ptr(assign_dynamic_container(nullptr, rhs.get_ptr()));
  }

  bitset(bitset &&rhs) :
    m_data_or_ptr{rhs.m_data_or_ptr}
  {
    rhs.m_data_or_ptr = 1;
  }

  ~bitset() { clear(); }


  bitset& operator = (bitset const &rhs)
  {
    if(this == &rhs)
      return *this;

    if(rhs.is_small())
    {
      clear();
      m_data_or_ptr = rhs.m_data_or_ptr;
    }
    else
    {
      if(is_small())
        set_ptr(assign_dynamic_container(nullptr, rhs.get_ptr()));
      else
        set_ptr(assign_dynamic_container(get_ptr(), rhs.get_ptr()));
    }

    return *this;
  }

  bitset& operator = (bitset &&rhs)
  {
    m_data_or_ptr = rhs.m_data_or_ptr;
    rhs.m_data_or_ptr = 1;

    return *this;
  }


  bool is_small() const { return m_data_or_ptr & 1; }

  void clear()
  {
    if(!is_small())
      std::free(get_ptr());

    m_data_or_ptr = 1;
  }

  void set(size_t idx)
  {
    if(is_small() && idx < num_word_bits - 1)
      m_data_or_ptr |= word_type{1} << (idx + 1);
    else
    {
      ensure_dynamic_size(idx / num_word_bits + 1);
      get_ptr()->words[idx / num_word_bits] |= word_type{1} << (idx % num_word_bits);
    }
  }

  bool test(size_t idx) const
  {
    if(is_small())
    {
      if(idx < num_word_bits - 1)
        return (m_data_or_ptr >> (idx + 1)) & 1;

      return false;
    }
    else
    {
      auto *arr = get_ptr();
      size_t word_idx = idx / num_word_bits;
      if(word_idx < arr->num)
        return (arr->words[word_idx] >> (idx % num_word_bits)) & 1;

      return false;
    }
  }

  size_t find(size_t start_idx = 0) const
  {
    if(is_small())
    {
      if(start_idx < num_word_bits - 1)
        return find_bit(m_data_or_ptr >> 1, start_idx);

      return NPOS;
    }
    else
    {
      auto *arr = get_ptr();
      size_t word_idx = start_idx / num_word_bits;
      if(word_idx < arr->num)
      {
        size_t pos = find_bit(arr->words[word_idx], start_idx % num_word_bits);
        if(pos != NPOS)
          return word_idx * num_word_bits + pos;

        while(++word_idx < arr->num)
        {
          size_t pos = find_bit(arr->words[word_idx]);
          if(pos != NPOS)
            return word_idx * num_word_bits + pos;
        }
      }

      return NPOS;
    }
  }


  bitset& operator |= (bitset const &rhs)
  {
    if(rhs.is_small())
    {
      if(is_small())
        m_data_or_ptr |= rhs.m_data_or_ptr;
      else
        get_ptr()->words[0] |= rhs.m_data_or_ptr;
    }
    else
    {
      size_t max_word = rhs.max_used_word();
      if(max_word != NPOS)
      {
        ensure_dynamic_size(max_word + 1);
        auto *arr = get_ptr();
        for(size_t i = 0; i <= max_word; ++i)
          arr->words[i] |= rhs.get_ptr()->words[i];
      }
    }

    return *this;
  }


private:
  struct dynamic_container
  {
    size_t num;
    word_type words[1];
  };

  static constexpr size_t dynamic_container_base_size = sizeof(dynamic_container) - sizeof(word_type);

  word_type m_data_or_ptr;

private:
  dynamic_container* get_ptr()
  {
    assert(!is_small());
    return reinterpret_cast<dynamic_container*>(m_data_or_ptr);
  }

  dynamic_container const* get_ptr() const
  {
    assert(!is_small());
    return reinterpret_cast<dynamic_container*>(m_data_or_ptr);
  }

  void set_ptr(dynamic_container *arr)
  {
    m_data_or_ptr = reinterpret_cast<word_type>(arr);
  }

  void ensure_dynamic_size(size_t num_words)
  {
    assert(num_words > 0);

    if(is_small())
    {
      auto *arr = create_dynamic_container(num_words, true);
      arr->words[0] = m_data_or_ptr >> 1;
      set_ptr(arr);
    }
    else
      set_ptr(grow_dynamic_container(get_ptr(), num_words));
  }

  size_t max_used_word() const
  {
    assert(!is_small());

    auto *arr = get_ptr();

    // Find maximum word that has at least one bit set
    size_t max_word = arr->num;
    while(--max_word != NPOS)
    {
      if(arr->words[max_word])
        break;
    }

    return max_word;
  }

private:
  dynamic_container* grow_dynamic_container(dynamic_container *arr, size_t num_words)
  {
    assert(num_words > 0);

    if(arr->num < num_words)
    {
      auto *new_arr = create_dynamic_container(num_words, false);
      assign_dynamic_container(new_arr, arr);

      std::free(arr);
      arr = new_arr;
    }

    return arr;
  }

  dynamic_container* assign_dynamic_container(dynamic_container *dest, dynamic_container const *src)
  {
    if(!dest || dest->num < src->num)
    {
      std::free(dest);
      dest = create_dynamic_container(src->num, false);
    }

    // Copy data and set the rest to zero
    std::memcpy(dest->words, src->words, src->num * sizeof(word_type));
    std::memset(dest->words + src->num * sizeof(word_type), 0, (dest->num - src->num) * sizeof(word_type));

    return dest;
  }

  dynamic_container* create_dynamic_container(size_t num_words, bool set_to_zero)
  {
    size_t bytes_to_allocate = dynamic_container_base_size + num_words * sizeof(word_type);
    dynamic_container *arr;
    if(set_to_zero)
      arr = (dynamic_container*)std::calloc(1, bytes_to_allocate);
    else
      arr = (dynamic_container*)std::malloc(bytes_to_allocate);

    arr->num = num_words;
    return arr;
  }
};


template<typename Func>
void for_each_bit(bitset const &a, Func &&func)
{
  size_t idx = a.find();
  while(idx != NPOS)
  {
    func(idx);
    idx = a.find(idx + 1);
  }
}

template<typename Func>
void for_each_common_bit(bitset const &a, bitset const &b, Func &&func)
{
  size_t idx_a = a.find();
  size_t idx_b = b.find();
  while(idx_a != NPOS && idx_b != NPOS)
  {
    if(idx_a < idx_b)
      idx_a = a.find(idx_a + 1);
    else if(idx_b < idx_a)
      idx_b = b.find(idx_b + 1);
    else
    {
      func(idx_a);
      idx_a = a.find(idx_a + 1);
      idx_b = b.find(idx_b + 1);
    }
  }
}

template<typename Func>
void for_each_bit_not_in_b(bitset const &a, bitset const &b, Func &&func)
{
  size_t idx_a = a.find();
  while(idx_a != NPOS)
  {
    if(!b.test(idx_a))
      func(idx_a);

    idx_a = a.find(idx_a + 1);
  }
}
