// MIT License
//
// Copyright (c) 2019 Lennart Braun
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

#include "gtest/gtest.h"

#include "test_constants.h"

#include "crypto/random/aes128_ctr_rng.h"

// Test vectors from NIST FIPS 197, Appendix A

TEST(AES128_CTR_RNG, no_trivial_output) {
  std::array<std::byte, 10 * AES128_CTR_RNG::block_size> output_0;
  std::array<std::byte, 10 * AES128_CTR_RNG::block_size> output_1;
  AES128_CTR_RNG rng;
  AES128_CTR_RNG rng2;
  auto& rngt = AES128_CTR_RNG::get_thread_instance();

  rng.random_blocks_aligned(output_0.data(), 10);
  rng.random_blocks_aligned(output_1.data(), 10);
  // two subsequent queries do not return the same bytes
  EXPECT_NE(output_0, output_1);

  rng.sample_key();
  rng.random_blocks_aligned(output_1.data(), 10);
  // a new key results in different bytes
  EXPECT_NE(output_0, output_1);

  rng2.random_blocks_aligned(output_1.data(), 10);
  // a different RNG instance results in different bytes
  EXPECT_NE(output_0, output_1);

  // the thread RNG instance results in different bytes
  rngt.random_blocks_aligned(output_1.data(), 10);
  EXPECT_NE(output_0, output_1);
}
