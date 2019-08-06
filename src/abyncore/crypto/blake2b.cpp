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

#include "blake2b.h"

namespace ABYN {
Blake2bCtx NewBlakeCtx() {
  return Blake2bCtx(EVP_MD_CTX_new(), [](EVP_MD_CTX *ctx) { EVP_MD_CTX_free(ctx); });
}

void Blake2b(std::uint8_t *msg, std::uint8_t digest[EVP_MAX_MD_SIZE], std::size_t len,
             EVP_MD_CTX *ctx) {
  const bool new_ctx = ctx == nullptr;

  unsigned int md_len;

  EVP_MD_CTX *mdctx;
  if (new_ctx) {
    mdctx = EVP_MD_CTX_new();
  } else {
    mdctx = ctx;
  }

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL)
  EVP_DigestInit_ex(mdctx, EVP_sha512(), nullptr);
#else
  EVP_DigestInit_ex(mdctx, EVP_blake2b512(), nullptr);
#endif

  EVP_DigestUpdate(mdctx, msg, len);
  EVP_DigestFinal_ex(mdctx, digest, &md_len);

  if (new_ctx) {
    EVP_MD_CTX_free(mdctx);
  } else {
    EVP_MD_CTX_reset(mdctx);
  }
}

void Blake2b(std::uint8_t *msg, std::uint8_t digest[EVP_MAX_MD_SIZE], std::size_t len,
             Blake2bCtx &b) {
  Blake2b(msg, digest, len, b.get());
}
}