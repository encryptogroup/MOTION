// MIT License
//
// Copyright (c) 2022 Liang Zhao
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

// https://code-examples.net/en/q/32ce05

#include <inttypes.h>
#include <stdio.h>
#include <iostream>

/*
** Using documented GCC type unsigned __int128 instead of undocumented
** obsolescent typedef name __uint128_t.  Works with GCC 4.7.1 but not
** GCC 4.1.2 (but __uint128_t works with GCC 4.1.2) on Mac OS X 10.7.4.
*/
typedef unsigned __int128 uint128_t;

/*      UINT64_MAX 18446744073709551615ULL */
#define P10_UINT64 10000000000000000000ULL /* 19 zeroes */
#define E10_UINT64 19

#define STRINGIZER(x) #x
#define TO_STRING(x) STRINGIZER(x)

// print __uint128_t numbers
static void print_u128_u(uint128_t u128) {
  int rc;
  if (u128 > UINT64_MAX) {
    uint128_t leading = u128 / P10_UINT64;
    uint64_t trailing = u128 % P10_UINT64;
    // rc = print_u128_u(leading);
    // rc += printf("%." TO_STRING(E10_UINT64) PRIu64, trailing);
    print_u128_u(leading);
    printf("%." TO_STRING(E10_UINT64) PRIu64, trailing);
    std::cout << std::endl;
  } else {
    uint64_t u64 = u128;
    rc = printf("%" PRIu64, u64);
    std::cout << std::endl;
  }
  // return rc;
}

static void print_u128_u(const std::string& input, uint128_t u128) {
  std::cout << input;
  // std::cout << "u128" << std::endl;
  print_u128_u(u128);
}

// print __int128_t
static void print_u128_neg(const std::string& input, uint128_t u128) {
  if (__int128_t(u128) >= 0) {
    print_u128_u(input, u128);
  } else {
    print_u128_u(input + " -", -u128);
  }
}

// static void print_u128_u_neg(const std::string& input, std::uint64_t u64) {
//   std::cout << input << std::int64_t(u64) << std::endl;
// }

// int main(void)
// {
//     uint128_t u128a = ((uint128_t)UINT64_MAX + 1) * 0x1234567890ABCDEFULL +
//                       0xFEDCBA9876543210ULL;
//     uint128_t u128b = ((uint128_t)UINT64_MAX + 1) * 0xF234567890ABCDEFULL +
//                       0x1EDCBA987654320FULL;
//     int ndigits = print_u128_u(u128a);
//     printf("\n%d digits\n", ndigits);
//     ndigits = print_u128_u(u128b);
//     printf("\n%d digits\n", ndigits);
//     return(0);
// }