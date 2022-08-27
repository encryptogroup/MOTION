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

#include <limits>
#include <memory>
#include <span>
#include <vector>

#include "utility/typedefs.h"

namespace encrypto::motion {

struct AlgorithmDescription;

class Share;
using SharePointer = std::shared_ptr<Share>;

class ShareWrapper {
 public:
  ShareWrapper() : share_(nullptr){};

  ShareWrapper(const SharePointer& share) : share_(share) {}
  ShareWrapper(const ShareWrapper& sw) : share_(sw.share_) {}

  void operator=(SharePointer share) { share_ = share; }
  void operator=(const ShareWrapper& sw) { share_ = sw.share_; }

  ShareWrapper operator~() const;

  ShareWrapper operator^(const ShareWrapper& other) const;

  ShareWrapper& operator^=(const ShareWrapper& other) {
    *this = *this ^ other;
    return *this;
  }

  ShareWrapper operator&(const ShareWrapper& other) const;

  ShareWrapper& operator&=(const ShareWrapper& other) {
    *this = *this & other;
    return *this;
  }

  ShareWrapper operator|(const ShareWrapper& other) const;

  ShareWrapper& operator|=(const ShareWrapper& other) {
    *this = *this | other;
    return *this;
  }

  ShareWrapper operator+(const ShareWrapper& other) const;

  ShareWrapper& operator+=(const ShareWrapper& other) {
    *this = *this + other;
    return *this;
  }

  ShareWrapper operator-(const ShareWrapper& other) const;

  ShareWrapper& operator-=(const ShareWrapper& other) {
    *this = *this - other;
    return *this;
  }

  ShareWrapper operator*(const ShareWrapper& other) const;

  ShareWrapper& operator*=(const ShareWrapper& other) {
    *this = *this * other;
    return *this;
  }
  
  friend ShareWrapper DotProduct(std::span<ShareWrapper> a, std::span<ShareWrapper> b);


  ShareWrapper operator==(const ShareWrapper& other) const;

  ShareWrapper operator>(const ShareWrapper& other) const;

  // use this as the selection bit
  // returns this ? a : b
  ShareWrapper Mux(const ShareWrapper& a, const ShareWrapper& b) const;

  template <MpcProtocol P>
  ShareWrapper Convert() const;

  SharePointer& Get() { return share_; }

  const SharePointer& Get() const { return share_; }

  const SharePointer& operator*() const { return share_; }

  const SharePointer& operator->() const { return share_; }

  /// \brief constructs an output gate, which reconstructs the cleartext result. The default
  /// parameter for the output owner corresponds to all parties being the output owners.
  ShareWrapper Out(std::size_t output_owner = std::numeric_limits<std::int64_t>::max()) const;

  /// \brief splits the share into single wires.
  std::vector<ShareWrapper> Split() const;

  /// \brief yields wire #i from share_ as ShareWrapper.
  /// \throws if i is out of range.
  ShareWrapper GetWire(std::size_t i) const;

  /// \brief concatenates wires in multiple shares in one share.
  /// \throws if wires have different numbers of SIMD values.
  static ShareWrapper Concatenate(std::vector<ShareWrapper>&& input) { return Concatenate(input); }

  /// \brief concatenates wires in multiple shares in one share.
  /// \throws if wires have different numbers of SIMD values.
  static ShareWrapper Concatenate(const std::vector<ShareWrapper>::const_iterator vector_begin,
                                  const std::vector<ShareWrapper>::const_iterator vector_end) {
    const auto v{std::vector<ShareWrapper>(vector_begin, vector_end)};
    return Concatenate(v);
  }

  /// \brief concatenates wires in multiple shares in one share. Throws if wires have different
  /// numbers of SIMD values.
  static ShareWrapper Concatenate(std::span<const ShareWrapper> input);

  /// \brief evaluates AlgorithmDescription also on this->share_ as input.
  /// \returns the output share of the evaluated circuit as ShareWrapper.
  ShareWrapper Evaluate(const std::shared_ptr<const AlgorithmDescription>& algo) const {
    return Evaluate(*algo);
  }

  /// \brief constructs a circuit from AlgorithmDescription algo and sets this->share_ as input.
  /// \returns a share over the output wires of the constructed circuit.
  ShareWrapper Evaluate(const AlgorithmDescription& algo) const;

  /// \brief constructs a SubsetGate that returns values stored at positions in this->share_.
  /// Internally calls ShareWrapper Subset(std::span<std::size_t> positions).
  ShareWrapper Subset(std::vector<std::size_t>&& positions);

  /// \brief constructs a SubsetGate that returns values stored at positions in this->share_, e.g.,
  /// Subset on values {0,1,2} on a share containing l wires with 4 SIMD values each would return
  /// all but the last SIMD value on the share while maintaining the number of wires and their
  /// order. Repetitions of the positions as well as the number of output SIMD values being greater
  /// the the number of the input SIMD values is allowed, e.g., subset of {0,0} of a share with only
  /// 1 SIMD value would yield an output share that stores the same value as SIMD twice.
  /// \throws out_of_range if at least one of the indices in positions is out of range.
  ShareWrapper Subset(std::span<const std::size_t> positions);

  /// \brief constructs an Unsimdify gate with this->share_ as input.
  /// UnsimdifyGate decomposes this->share_ into shares with exactly 1 SIMD value, e.g., if
  /// this->share_ contained s_0, s_1, and s_2 and SIMD values in this->share_, it will return an
  /// std::vector {s_0, s_1, s_2} as separate shares with exactly one SIMD value in each share.
  /// \throws invalid_argument if any of the shares internally has an inconsistent number of SIMD
  /// values across the wires.
  /// \throws invalid_argument if this->share_ is "empty", i.e., contains 0 SIMD values.
  std::vector<ShareWrapper> Unsimdify();

  /// \brief constructs a SimdifyGate that composes the shares in input into a "larger" share with
  /// all the input shares as SIMD values in one share.
  /// \throws invalid_argument the shares in input are "empty", i.e., contain 0 SIMD values.
  /// \throws invalid_argument if any of the shares have inconsistent number of wires.
  /// \throws invalid_argument if any of the shares internally has an inconsistent number of SIMD
  /// values across the wires.
  static ShareWrapper Simdify(std::span<SharePointer> input);

  /// \brief internally extracts shares from each entry in input and calls
  /// Simdify(std::span<SharePointer> input) on the result.
  static ShareWrapper Simdify(std::span<const ShareWrapper> input);

  /// \brief internally extracts shares from each entry in input and calls
  /// Simdify(std::span<SharePointer> input) on the result.
  static ShareWrapper Simdify(std::vector<ShareWrapper>&& input);

  /// \brief converts the information on the wires to T.
  /// Boolean and arithmetic GMW returns the secret-shared values on the wires.
  /// BMR returns "public values", which is also the place where the plaintext results from the
  /// output gates is stored. Only conversions to the same format are allowed, e.g., Boolean GMW and
  /// BMR to bool, BitVector, or std::vector<BitVector>. Arithmetic GMW shares can only be converted
  /// to the same unsigned integer type T that they hold or to std::vector<T>. Converting a Boolean
  /// share to (1) bool returns the 0th SIMD value of the 0th wire, (2) BitVector returns all SIMD
  /// values on the 0th wire, and (3) std::vector<BitVector> all SIMD values on all wires.
  template <typename T>
  T As() const;

 private:
  SharePointer share_;

  template <typename T>
  ShareWrapper Add(SharePointer share, SharePointer other) const;

  template <typename T>
  ShareWrapper Sub(SharePointer share, SharePointer other) const;

  template <typename T>
  ShareWrapper Mul(SharePointer share, SharePointer other) const;

  template <typename T>
  ShareWrapper HybridMul(SharePointer share, SharePointer other) const;

  template <typename T>
  ShareWrapper GreaterThan(SharePointer share, SharePointer other) const;

  template <typename T>
  ShareWrapper Square(SharePointer share) const;
  
  template <typename T>
  ShareWrapper DotProduct(std::span<ShareWrapper> a, std::span<ShareWrapper> b) const;

  ShareWrapper ArithmeticGmwToBmr() const;

  ShareWrapper BooleanGmwToArithmeticGmw() const;

  ShareWrapper BooleanGmwToBmr() const;

  ShareWrapper BmrToBooleanGmw() const;

  void ShareConsistencyCheck() const;
};

ShareWrapper DotProduct(std::span<ShareWrapper> a, std::span<ShareWrapper> b);

}  // namespace encrypto::motion
