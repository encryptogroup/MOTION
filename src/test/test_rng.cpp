// MIT License
//
// Copyright (c) 2019-2021 Lennart Braun, Arianne Roselina Prananto
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
#include "primitives/random/aes128_ctr_rng.h"
#include "primitives/random/openssl_rng.h"
#include "test_constants.h"

// Test vectors from NIST FIPS 197, Appendix A

#ifndef __MINGW32__
TEST(Aes128CtrRng, NoTrivialOutput) {
  alignas(16) std::array<std::byte, 10 * encrypto::motion::Aes128CtrRng::kBlockSize> output_0;
  alignas(16) std::array<std::byte, 10 * encrypto::motion::Aes128CtrRng::kBlockSize> output_1;
  encrypto::motion::Aes128CtrRng rng1;
  encrypto::motion::Aes128CtrRng rng2;
  auto& rngt = encrypto::motion::Aes128CtrRng::GetThreadInstance();

  rng1.RandomBlocksAligned(output_0.data(), 10);
  rng1.RandomBlocksAligned(output_1.data(), 10);
  // two subsequent queries do not return the same bytes
  EXPECT_NE(output_0, output_1);

  rng1.SampleKey();
  rng1.RandomBlocksAligned(output_1.data(), 10);
  // a new key results in different bytes
  EXPECT_NE(output_0, output_1);

  rng2.RandomBlocksAligned(output_1.data(), 10);
  // a different RNG instance results in different bytes
  EXPECT_NE(output_0, output_1);

  // the thread RNG instance results in different bytes
  rngt.RandomBlocksAligned(output_1.data(), 10);
  EXPECT_NE(output_0, output_1);
}
#endif

TEST(OpenSslRng, NoTrivialOutput) {
  alignas(16) std::array<std::byte, 10 * encrypto::motion::OpenSslRng::kBlockSize> output_0;
  alignas(16) std::array<std::byte, 10 * encrypto::motion::OpenSslRng::kBlockSize> output_1;
  encrypto::motion::OpenSslRng rng1;
  encrypto::motion::OpenSslRng rng2;
  auto& rngt = encrypto::motion::OpenSslRng::GetThreadInstance();

  rng1.RandomBlocksAligned(output_0.data(), 10);
  rng1.RandomBlocksAligned(output_1.data(), 10);
  // two subsequent queries do not return the same bytes
  EXPECT_NE(output_0, output_1);

  rng1.SampleKey();
  rng1.RandomBlocksAligned(output_1.data(), 10);
  // a new key results in different bytes
  EXPECT_NE(output_0, output_1);

  rng2.RandomBlocksAligned(output_1.data(), 10);
  // a different RNG instance results in different bytes
  EXPECT_NE(output_0, output_1);

  // the thread RNG instance results in different bytes
  rngt.RandomBlocksAligned(output_1.data(), 10);
  EXPECT_NE(output_0, output_1);
}
