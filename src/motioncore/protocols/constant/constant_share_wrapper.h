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

#include "protocols/share_wrapper.h"
#include "utility/meta.hpp"

namespace encrypto::motion {

/// \brief class to wrap constant share input functions
class ConstantShareWrapper {
 public:
  ConstantShareWrapper() : share_(nullptr){};

  ConstantShareWrapper(const SharePointer& share) : share_(share) {}

  ConstantShareWrapper(const ShareWrapper& sw) : share_(sw.Get()) {}

  ConstantShareWrapper(const ConstantShareWrapper& sw) : share_(sw.share_) {}

 public:
  /// \brief inputs constant unsigned integer as arithmetic GMW share
  template <typename T,
            typename = std::enable_if_t<std::is_unsigned_v<T> || std::is_same_v<T, __uint128_t>>>
  ShareWrapper CreateConstantArithmeticGmwInput(T constant_value,
                                                std::size_t num_of_simd = 1) const;

  /// \brief inputs constant unsigned integer vector as arithmetic GMW share
  template <typename T,
            typename = std::enable_if_t<std::is_unsigned_v<T> || std::is_same_v<T, __uint128_t>>,
            typename A>
  ShareWrapper CreateConstantArithmeticGmwInput(std::vector<T, A> constant_value_vector) const;

  /// \brief inputs constant unsigned integer vector as Boolean GMW share
  template <typename T,
            typename = std::enable_if_t<std::is_unsigned_v<T> || std::is_same_v<T, __uint128_t>>>
  ShareWrapper CreateConstantBooleanGmwInput(T constant_value, std::size_t num_of_simd) const;
  template <typename T,
            typename = std::enable_if_t<std::is_unsigned_v<T> || std::is_same_v<T, __uint128_t>>>
  ShareWrapper CreateConstantBooleanGmwInput(T constant_value) const;

  /// \brief inputs constant bool value as Boolean GMW share
  ShareWrapper CreateConstantBooleanGmwInput(bool constant_value) const;
  ShareWrapper CreateConstantBooleanGmwInput(bool constant_value, std::size_t num_of_simd) const;

  /// \brief inputs constant float/double value as Boolean GMW share
  ShareWrapper CreateConstantBooleanGmwInput(float constant_value, std::size_t num_of_simd) const;
  ShareWrapper CreateConstantBooleanGmwInput(float constant_value) const;
  ShareWrapper CreateConstantBooleanGmwInput(double constant_value, std::size_t num_of_simd) const;
  ShareWrapper CreateConstantBooleanGmwInput(double constant_value) const;

  /// \brief inputs constant float/double value as BMR share
  template <typename T,
            typename = std::enable_if_t<std::is_unsigned_v<T> || std::is_same_v<T, __uint128_t>>>
  ShareWrapper CreateConstantBmrInput(T constant_value, std::size_t num_of_simd) const;
  template <typename T,
            typename = std::enable_if_t<std::is_unsigned_v<T> || std::is_same_v<T, __uint128_t>>>
  ShareWrapper CreateConstantBmrInput(T constant_value) const;

  /// \brief inputs constant bool value as BMR share
  ShareWrapper CreateConstantBmrInput(bool constant_value) const;
  ShareWrapper CreateConstantBmrInput(bool constant_value, std::size_t num_of_simd) const;

  /// \brief inputs constant double value as BMR share
  ShareWrapper CreateConstantBmrInput(float constant_value, std::size_t num_of_simd) const;
  ShareWrapper CreateConstantBmrInput(float constant_value) const;
  ShareWrapper CreateConstantBmrInput(double constant_value, std::size_t num_of_simd) const;
  ShareWrapper CreateConstantBmrInput(double constant_value) const;

  /// \brief creates constant Boolean GMW or BMR shares based on the type of this.share_
  template <typename T,
            typename = std::enable_if_t<std::is_unsigned_v<T> || std::is_same_v<T, __uint128_t>>>
  ShareWrapper CreateConstantBooleanGmwOrBmrInput(T constant_value, std::size_t num_of_simd) const;
  template <typename T,
            typename = std::enable_if_t<std::is_unsigned_v<T> || std::is_same_v<T, __uint128_t>>>
  ShareWrapper CreateConstantBooleanGmwOrBmrInput(T constant_value) const;
  ShareWrapper CreateConstantBooleanGmwOrBmrInput(bool constant_value) const;
  ShareWrapper CreateConstantBooleanGmwOrBmrInput(bool constant_value,
                                                  std::size_t num_of_simd) const;
  ShareWrapper CreateConstantBooleanGmwOrBmrInput(float constant_value,
                                                  std::size_t num_of_simd) const;
  ShareWrapper CreateConstantBooleanGmwOrBmrInput(float constant_value) const;
  ShareWrapper CreateConstantBooleanGmwOrBmrInput(double constant_value,
                                                  std::size_t num_of_simd) const;
  ShareWrapper CreateConstantBooleanGmwOrBmrInput(double constant_value) const;


 private:
  SharePointer share_;
};

}  // namespace encrypto::motion
