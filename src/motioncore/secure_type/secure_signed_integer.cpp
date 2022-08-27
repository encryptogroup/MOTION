// MIT License
//
// Copyright (c) 2022 Oleksandr Tkachenko
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

#include "secure_signed_integer.h"

#include "protocols/share.h"
#include "utility/bit_vector.h"

namespace encrypto::motion {

SecureSignedInteger SecureSignedInteger::Simdify(std::span<SecureSignedInteger> input) {
  std::vector<SharePointer> input_as_shares;
  input_as_shares.reserve(input.size());
  std::transform(input.begin(), input.end(), std::back_inserter(input_as_shares),
                 [&](SecureSignedInteger& i) -> SharePointer { return i.Get().Get(); });
  return SecureSignedInteger(ShareWrapper::Simdify(input_as_shares));
}

SecureSignedInteger SecureSignedInteger::Simdify(std::vector<SecureSignedInteger>&& input) {
  return Simdify(input);
}

SecureSignedInteger SecureSignedInteger::Subset(std::span<const size_t> positions) {
  ShareWrapper unwrap{this->Get()};
  return SecureUnsignedInteger(unwrap.Subset(positions));
}

SecureSignedInteger SecureSignedInteger::Subset(std::vector<size_t>&& positions) {
  return Subset(std::span<const std::size_t>(positions));
}

std::vector<SecureSignedInteger> SecureSignedInteger::Unsimdify() const {
  auto unsigned_ints{share_.Unsimdify()};
  std::vector<SecureSignedInteger> result(unsigned_ints.begin(), unsigned_ints.end());
  return result;
}

SecureSignedInteger SecureSignedInteger::Out(std::size_t output_owner) const {
  return SecureSignedInteger(share_.Out(output_owner));
}

template <typename T>
T SecureSignedInteger::As() const {
  if (share_.Get()->GetProtocol() == MpcProtocol::kArithmeticGmw) {
    if constexpr (std::is_signed_v<T>) {
      using U = typename std::make_unsigned<T>::type;
      return FromTwosComplement<U>(share_.Get().As<U>());
    } else {
      using value_type = typename T::value_type;
      using unsigned_value_type = typename std::make_unsigned<value_type>::type;
      using U = typename std::vector<unsigned_value_type>;
      return FromTwosComplement<unsigned_value_type>(share_.Get().As<U>());
    }
  } else if (share_.Get()->GetProtocol() == MpcProtocol::kBooleanGmw ||
             share_.Get()->GetProtocol() == MpcProtocol::kBmr) {
    auto share_out = share_.Get().As<std::vector<encrypto::motion::BitVector<>>>();
    if constexpr (std::is_signed<T>()) {
      using U = typename std::make_unsigned<T>::type;
      U unsigned_output{encrypto::motion::ToOutput<U>(share_out)};
      return FromTwosComplement(unsigned_output);
    } else {
      using value_type = typename T::value_type;
      using unsigned_value_type = typename std::make_unsigned<value_type>::type;
      using U = typename std::vector<unsigned_value_type>;
      U unsigned_output{encrypto::motion::ToVectorOutput<unsigned_value_type>(share_out)};
      return FromTwosComplement(unsigned_output);
    }
  } else {
    throw std::invalid_argument("Unsupported protocol for SecureSignedInteger::As()");
  }
}

template std::int8_t SecureSignedInteger::As() const;
template std::int16_t SecureSignedInteger::As() const;
template std::int32_t SecureSignedInteger::As() const;
template std::int64_t SecureSignedInteger::As() const;

template std::vector<std::int8_t> SecureSignedInteger::As() const;
template std::vector<std::int16_t> SecureSignedInteger::As() const;
template std::vector<std::int32_t> SecureSignedInteger::As() const;
template std::vector<std::int64_t> SecureSignedInteger::As() const;

}  // namespace encrypto::motion