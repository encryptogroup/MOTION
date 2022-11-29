#pragma once

#include <algorithm>
#include <stdexcept>


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

template<typename T>
struct IteratorRange
{
  using iterator = T;

  IteratorRange() = default;
  IteratorRange(iterator begin, iterator end) :
    b{begin},
    e{end} {}

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
