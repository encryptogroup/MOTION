// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#include <functional>
#include <memory>
#include <cstdint>

#include <openssl/evp.h>

namespace encrypto::motion {

using Blake2bCtx = std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>>;

Blake2bCtx NewBlakeCtx();

void Blake2b(std::uint8_t* message, std::uint8_t digest[EVP_MAX_MD_SIZE], std::size_t length,
             EVP_MD_CTX* context = nullptr);

void Blake2b(std::uint8_t* message, std::uint8_t digest[EVP_MAX_MD_SIZE], std::size_t length,
             Blake2bCtx& b);

}  // namespace encrypto::motion
