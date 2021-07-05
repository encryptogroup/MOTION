// MIT License
//
// Copyright (c) 2021 Arianne Roselina Prananto
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

#include <cstddef>
#include <memory>
#include "rng.h"

namespace encrypto::motion {

// TODO: This class is needed because MinGW has some problems with thread_local in Aes128CtrRng.
//  Aes128CtrRng should be used, once this problem is fixed.

// OpenSSL's RAND_bytes() function
// This class is thread-safe, since RAND_bytes() is thread-safe:
// https://mta.openssl.org/pipermail/openssl-users/2020-November/013146.html RNG implemented using
class OpenSslRng : public Rng {
 public:
  OpenSslRng();
  virtual ~OpenSslRng();

  // delete copy/move constructors/assignment operators
  OpenSslRng(const OpenSslRng&) = delete;
  OpenSslRng(OpenSslRng&&) = delete;
  OpenSslRng& operator=(const OpenSslRng&) = delete;
  OpenSslRng& operator=(OpenSslRng&&) = delete;

  // empty function
  virtual void SampleKey() override;

  // fill the output buffer with number_of_bytes random bytes
  virtual void RandomBytes(std::byte* output, std::size_t number_of_bytes) override;

  // fill the output buffer with number_of_blocks random blocks of size kBlockSize
  virtual void RandomBlocks(std::byte* output, std::size_t number_of_blocks) override;

  // fill the output buffer with number_of_blocks random blocks of size kBlockSize
  // where the buffer needs to be aligned at a multiple of kBlockSize
  virtual void RandomBlocksAligned(std::byte* output, std::size_t number_of_blocks) override;

  static constexpr std::size_t kBlockSize = 16;

  static Rng& GetThreadInstance() { return instance_; }

 private:
  static OpenSslRng instance_;
};

}  //  namespace encrypto::motion
