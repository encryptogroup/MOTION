// MIT License
//
// Copyright (c) 2019 Lennart Braun
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#pragma once

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <set>
#include <type_traits>
#include <vector>
#include "sp_provider.h"
#include "utility/helpers.h"

namespace encrypto::motion {

namespace detail {

// smallest square root of a mod 2^k
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
T sqrt(size_t k, T a) {
  assert(k >= 3);
  assert(a % 8 == 1);

  if (a == 1) return 1;

  std::array<T, 8> roots = {1, 3, 5, 7, 0, 0, 0, 0};
  std::array<T, 8> new_roots = {0};
  for (std::size_t j = 4; j < k + 1; ++j) {
    for (std::size_t l = 0; l < 4; ++l) {
      T r = roots[l];
      T i = ((r * r - a) >> (j - 1)) & 1;
      T nr = (r + (i << (j - 2))) & ((T(1) << j) - 1);
      new_roots[l] = nr;
      new_roots[l + 4] = (T(1) << j) - nr;
    }

    for (std::size_t l = 0; l < 8; ++l) {
      T nr = new_roots[l];
      for (size_t m = 0; m < 8; ++m) {
        if (roots[m] == 0) {
          roots[m] = nr;
          break;
        } else if (roots[m] == nr) {
          break;
        }
      }
    }
    std::swap(roots, new_roots);
  }
  T minimum = roots[0];
  for (std::size_t l = 1; l < 4; ++l) {
    if (roots[l] < minimum) minimum = roots[l];
  }
  return minimum;
}

// inversion of a mod 2^k
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
T invert(std::size_t k, T a) {
  assert((a & 1) == 1);
  const T mask = (T(1) << k) - 1;
  a &= mask;
  T b = 1;
  T X;
  T result = 0;
  for (std::size_t i = 0; i < k; ++i) {
    X = b & 1;
    b = (b - a * X) >> 1;
    result |= X << i;
  }
  return result;
}

template <typename T>
struct get_expanded_type {};
template <>
struct get_expanded_type<std::uint8_t> {
  using type = std::uint16_t;
};
template <>
struct get_expanded_type<std::uint16_t> {
  using type = std::uint32_t;
};
template <>
struct get_expanded_type<std::uint32_t> {
  using type = std::uint64_t;
};
template <>
struct get_expanded_type<std::uint64_t> {
  using type = __uint128_t;
};
template <typename T>
using get_expanded_type_t = typename get_expanded_type<T>::type;

template <typename T>
constexpr std::size_t GetBitSize() {
  return sizeof(T) * 8;
}

template <typename T, typename U = get_expanded_type_t<T>,
          typename = std::enable_if_t<std::is_same_v<U, get_expanded_type_t<T>>>>
constexpr U GetModMask() {
  return (U(1) << (GetBitSize<T>() + 2)) - 1;
}

template <typename T, typename U = get_expanded_type_t<T>,
          typename = std::enable_if_t<std::is_same_v<U, get_expanded_type_t<T>>>>
static std::pair<std::vector<U>, std::vector<U>> compute_sbs_phase_1(std::size_t number_of_sbs,
                                                                     std::size_t my_id,
                                                                     SpVector<U>& sps) {
  constexpr U mod_mask = GetModMask<T>();

  // generate random u_i mod 2^k+2
  auto wb1 = RandomVector<U>(number_of_sbs);

  // compute a_i = 2 * u_i + 1  mod2^k+2  (for party 0)
  //         a_i = 2 * u_i      mod2^k+2  (for all other parties)
  if (my_id == 0) {
    std::transform(wb1.cbegin(), wb1.cend(), wb1.begin(),
                   [mod_mask](auto u_i) { return (2 * u_i + 1) & mod_mask; });
  } else {
    std::transform(wb1.cbegin(), wb1.cend(), wb1.begin(),
                   [mod_mask](auto u_i) { return (2 * u_i) & mod_mask; });
  }

  // start squaring:

  // mask a with the first part of the SP
  std::vector<U> wb2;  // XXX: maybe reuse SP buffer here?
  wb2.reserve(number_of_sbs);
  std::transform(wb1.cbegin(), wb1.cend(), sps.a.cbegin(), std::back_inserter(wb2),
                 [mod_mask](auto a_i, auto sp_a_i) { return (a_i - sp_a_i) & mod_mask; });

  // wb1 contains our shares of a
  // wb2 contains our shares of d (which is the masked a)
  return {wb1, wb2};
}

template <typename T, typename U = get_expanded_type_t<T>,
          typename = std::enable_if_t<std::is_same_v<U, get_expanded_type_t<T>>>>
static void compute_sbs_phase_2(std::vector<U>& wb1, std::vector<U>& wb2, std::size_t my_id,
                                SpVector<U>& sps) {
  // wb1 contains our shares of a
  // wb2 contains the reconstructed d (which is the masked a)

  constexpr U mod_mask = GetModMask<T>();

  // continue with squaring:
  // compute shares of a^2
  if (my_id == 0) {
    std::transform(wb1.cbegin(), wb1.cend(), wb2.cbegin(), wb2.begin(),
                   [](auto a, auto d) { return 2 * d * a - d * d; });
  } else {
    std::transform(wb1.cbegin(), wb1.cend(), wb2.cbegin(), wb2.begin(),
                   [](auto a, auto d) { return 2 * d * a; });
  }
  std::transform(wb2.cbegin(), wb2.cend(), sps.c.cbegin(), wb2.begin(),
                 [mod_mask](auto t, auto c) { return (c + t) & mod_mask; });
  // wb2 contains now shares of a^2
}

template <typename T, typename U = get_expanded_type_t<T>,
          typename = std::enable_if_t<std::is_same_v<U, get_expanded_type_t<T>>>>
static void compute_sbs_phase_3(std::vector<U>& wb1, std::vector<U>& wb2, std::vector<T>& sbs,
                                std::size_t my_id) {
  // sbs is the output buffer
  // wb1 contains our share of a
  // wb2 contains the reconstructed a^2

  constexpr U mod_mask = GetModMask<T>();
  constexpr U mod_mask_1 = mod_mask >> 1;
  auto number_of_sbs = wb1.size();

  // compute c as smallest square root of a^2 mod 2^k+2
  std::transform(wb2.cbegin(), wb2.cend(), wb2.begin(),
                 [mod_mask](auto asq) { return sqrt(GetBitSize<T>() + 2, U(asq & mod_mask)); });

  // compute d_i = c^-1 * a + 1 mod 2^k+1  (for party 0)
  //         d_i = c^-1 * a     mod 2^k+1  (for all other parties)
  if (my_id == 0) {
    std::transform(wb1.cbegin(), wb1.cend(), wb2.cbegin(), wb1.begin(), [](U a_i, U c) {
      return (invert<U>(GetBitSize<T>() + 1, U(c & mod_mask_1)) * a_i + 1) & mod_mask_1;
    });
  } else {
    std::transform(wb1.cbegin(), wb1.cend(), wb2.cbegin(), wb1.begin(), [](auto a_i, auto c) {
      return (invert<U>(GetBitSize<T>() + 1, U(c & mod_mask_1)) * a_i) & mod_mask_1;
    });
  }

  // compute b_i = d_i / 2 as element of Z
  sbs.clear();
  sbs.reserve(number_of_sbs);
  std::transform(wb1.cbegin(), wb1.cend(), std::back_inserter(sbs),
                 [](auto& d_i) { return static_cast<T>(d_i >> 1); });
}

}  // namespace detail

}  // namespace encrypto::motion
