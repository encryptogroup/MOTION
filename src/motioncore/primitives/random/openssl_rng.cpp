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

#include "openssl_rng.h"
#include <fstream>
#include <openssl/rand.h>

namespace encrypto::motion {

OpenSslRng OpenSslRng::instance_;

OpenSslRng::OpenSslRng() = default;

OpenSslRng::~OpenSslRng() = default;

void OpenSslRng::SampleKey() {}

void OpenSslRng::RandomBlocksAligned(std::byte* output, std::size_t number_of_blocks) {
  std::byte* aligned_output = reinterpret_cast<std::byte*>(__builtin_assume_aligned(output, 16));
  int random =
      RAND_bytes(reinterpret_cast<unsigned char*>(aligned_output), number_of_blocks * kBlockSize);
  if (random != 1) {
    throw std::runtime_error("RAND_bytes in OpenSslRng::RandomBlocksAligned failed");
  }
}

void OpenSslRng::RandomBlocks(std::byte* output, std::size_t number_of_blocks) {
  int random = RAND_bytes(reinterpret_cast<unsigned char*>(output), number_of_blocks * kBlockSize);
  if (random != 1) {
    throw std::runtime_error("RAND_bytes in OpenSslRng::RandomBlocks failed");
  }
}

void OpenSslRng::RandomBytes(std::byte* output, std::size_t number_of_bytes) {
  int random = RAND_bytes(reinterpret_cast<unsigned char*>(output), number_of_bytes);
  if (random != 1) {
    throw std::runtime_error("RAND_bytes in OpenSslRng::RandomBytes failed");
  }
}

}  //  namespace encrypto::motion
