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

#include "constant_share_wrapper.h"
#include "base/backend.h"

namespace encrypto::motion {

template <typename T, typename>
ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput(T constant_value,
                                                                 std::size_t num_of_simd) const {
  std::vector<T> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantBooleanGmwInput(ToInput<T>(constant_value_vector));
  return constant_boolean_gmw_share;
}

template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput<std::uint8_t>(
    std::uint8_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput<std::uint16_t>(
    std::uint16_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput<std::uint32_t>(
    std::uint32_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput<std::uint64_t>(
    std::uint64_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput<__uint128_t>(
    __uint128_t constant_value, std::size_t num_of_simd) const;

template <typename T, typename>
ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput(T constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<T> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantBooleanGmwInput(ToInput<T>(constant_value_vector));
  return constant_boolean_gmw_share;
}

template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput<std::uint8_t>(
    std::uint8_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput<std::uint16_t>(
    std::uint16_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput<std::uint32_t>(
    std::uint32_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput<std::uint64_t>(
    std::uint64_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput<__uint128_t>(
    __uint128_t constant_value) const;

ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput(bool constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<bool> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantBooleanGmwInput(BitVector<>(constant_value_vector));
  return constant_boolean_gmw_share;
}
ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput(bool constant_value,
                                                                 std::size_t num_of_simd) const {
  std::vector<bool> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantBooleanGmwInput(BitVector<>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput(float constant_value,
                                                                 std::size_t num_of_simd) const {
  std::vector<float> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantBooleanGmwInput(
      ToInput<float, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput(float constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<float> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantBooleanGmwInput(
      ToInput<float, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput(double constant_value,
                                                                 std::size_t num_of_simd) const {
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantBooleanGmwInput(
      ToInput<double, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwInput(double constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantBooleanGmwInput(
      ToInput<double, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

template <typename T, typename>
ShareWrapper ConstantShareWrapper::CreateConstantBmrInput(T constant_value,
                                                          std::size_t num_of_simd) const {
  std::vector<T> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantAsBmrInput(ToInput<T>(constant_value_vector));
  return constant_boolean_gmw_share;
}

template ShareWrapper ConstantShareWrapper::CreateConstantBmrInput<std::uint8_t>(
    std::uint8_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBmrInput<std::uint16_t>(
    std::uint16_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBmrInput<std::uint32_t>(
    std::uint32_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBmrInput<std::uint64_t>(
    std::uint64_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBmrInput<__uint128_t>(
    __uint128_t constant_value, std::size_t num_of_simd) const;

template <typename T, typename>
ShareWrapper ConstantShareWrapper::CreateConstantBmrInput(T constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<T> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantAsBmrInput(ToInput<T>(constant_value_vector));
  return constant_boolean_gmw_share;
}

template ShareWrapper ConstantShareWrapper::CreateConstantBmrInput<std::uint8_t>(
    std::uint8_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBmrInput<std::uint16_t>(
    std::uint16_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBmrInput<std::uint32_t>(
    std::uint32_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBmrInput<std::uint64_t>(
    std::uint64_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBmrInput<__uint128_t>(
    __uint128_t constant_value) const;

ShareWrapper ConstantShareWrapper::CreateConstantBmrInput(bool constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<bool> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantAsBmrInput(BitVector<>(constant_value_vector));
  return constant_boolean_gmw_share;
}
ShareWrapper ConstantShareWrapper::CreateConstantBmrInput(bool constant_value,
                                                          std::size_t num_of_simd) const {
  std::vector<bool> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share =
      share_->GetBackend().ConstantAsBmrInput(BitVector<>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ConstantShareWrapper::CreateConstantBmrInput(float constant_value,
                                                          std::size_t num_of_simd) const {
  std::vector<float> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantAsBmrInput(
      ToInput<float, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ConstantShareWrapper::CreateConstantBmrInput(float constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<float> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantAsBmrInput(
      ToInput<float, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}
ShareWrapper ConstantShareWrapper::CreateConstantBmrInput(double constant_value,
                                                          std::size_t num_of_simd) const {
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantAsBmrInput(
      ToInput<double, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

ShareWrapper ConstantShareWrapper::CreateConstantBmrInput(double constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_share = share_->GetBackend().ConstantAsBmrInput(
      ToInput<double, std::true_type>(constant_value_vector));
  return constant_boolean_gmw_share;
}

template <typename T, typename>
ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput(
    T constant_value, std::size_t num_of_simd) const {
  std::vector<T> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_or_bmr_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_or_bmr_share =
        share_->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(constant_value_vector));
  } else {
    constant_boolean_gmw_or_bmr_share =
        share_->GetBackend().ConstantAsBmrInput(ToInput<T>(constant_value_vector));
  }
  return constant_boolean_gmw_or_bmr_share;
}

template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput<std::uint8_t>(
    std::uint8_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput<std::uint16_t>(
    std::uint16_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput<std::uint32_t>(
    std::uint32_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput<std::uint64_t>(
    std::uint64_t constant_value, std::size_t num_of_simd) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput<__uint128_t>(
    __uint128_t constant_value, std::size_t num_of_simd) const;

template <typename T, typename>
ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput(T constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<T> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_or_bmr_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_or_bmr_share =
        share_->GetBackend().ConstantAsBooleanGmwInput(ToInput<T>(constant_value_vector));
  } else {
    constant_boolean_gmw_or_bmr_share =
        share_->GetBackend().ConstantAsBmrInput(ToInput<T>(constant_value_vector));
  }
  return constant_boolean_gmw_or_bmr_share;
}

template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput<std::uint8_t>(
    std::uint8_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput<std::uint16_t>(
    std::uint16_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput<std::uint32_t>(
    std::uint32_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput<std::uint64_t>(
    std::uint64_t constant_value) const;
template ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput<__uint128_t>(
    __uint128_t constant_value) const;

ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput(bool constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<bool> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_or_bmr_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_or_bmr_share =
        share_->GetBackend().ConstantAsBooleanGmwInput(BitVector<>(constant_value_vector));
  } else {
    constant_boolean_gmw_or_bmr_share =
        share_->GetBackend().ConstantAsBmrInput(BitVector<>(constant_value_vector));
  }
  return constant_boolean_gmw_or_bmr_share;
}
ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput(
    bool constant_value, std::size_t num_of_simd) const {
  std::vector<bool> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_or_bmr_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_or_bmr_share =
        share_->GetBackend().ConstantAsBooleanGmwInput(BitVector<>(constant_value_vector));
  } else {
    constant_boolean_gmw_or_bmr_share =
        share_->GetBackend().ConstantAsBmrInput(BitVector<>(constant_value_vector));
  }
  return constant_boolean_gmw_or_bmr_share;
}

ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput(
    float constant_value, std::size_t num_of_simd) const {
  std::vector<float> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_or_bmr_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_or_bmr_share = share_->GetBackend().ConstantAsBooleanGmwInput(
        ToInput<float, std::true_type>(constant_value_vector));
  } else {
    constant_boolean_gmw_or_bmr_share = share_->GetBackend().ConstantAsBmrInput(
        ToInput<float, std::true_type>(constant_value_vector));
  }
  return constant_boolean_gmw_or_bmr_share;
}

ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput(float constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<float> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_or_bmr_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_or_bmr_share = share_->GetBackend().ConstantAsBooleanGmwInput(
        ToInput<float, std::true_type>(constant_value_vector));
  } else {
    constant_boolean_gmw_or_bmr_share = share_->GetBackend().ConstantAsBmrInput(
        ToInput<float, std::true_type>(constant_value_vector));
  }
  return constant_boolean_gmw_or_bmr_share;
}
ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput(
    double constant_value, std::size_t num_of_simd) const {
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_or_bmr_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_or_bmr_share = share_->GetBackend().ConstantAsBooleanGmwInput(
        ToInput<double, std::true_type>(constant_value_vector));
  } else {
    constant_boolean_gmw_or_bmr_share = share_->GetBackend().ConstantAsBmrInput(
        ToInput<double, std::true_type>(constant_value_vector));
  }
  return constant_boolean_gmw_or_bmr_share;
}

ShareWrapper ConstantShareWrapper::CreateConstantBooleanGmwOrBmrInput(double constant_value) const {
  std::size_t num_of_simd = share_->GetNumberOfSimdValues();
  std::vector<double> constant_value_vector(num_of_simd, constant_value);
  ShareWrapper constant_boolean_gmw_or_bmr_share;
  if (share_->GetProtocol() == MpcProtocol::kBooleanGmw) {
    constant_boolean_gmw_or_bmr_share = share_->GetBackend().ConstantAsBooleanGmwInput(
        ToInput<double, std::true_type>(constant_value_vector));
  } else {
    constant_boolean_gmw_or_bmr_share = share_->GetBackend().ConstantAsBmrInput(
        ToInput<double, std::true_type>(constant_value_vector));
  }
  return constant_boolean_gmw_or_bmr_share;
}

}  // namespace encrypto::motion
