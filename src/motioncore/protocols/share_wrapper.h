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

// added by Liang Zhao
#include <cmath>
#include "algorithm/algorithm_description.h"
#include "utility/MOTION_dp_mechanism_helper/fixed_point_operation.h"
#include "utility/MOTION_dp_mechanism_helper/floating_point_operation.h"
#include "utility/MOTION_dp_mechanism_helper/snapping_mechanism.h"
#include "utility/meta.hpp"

namespace encrypto::motion {

// added by Liang Zhao
struct FloatingPointShareStruct;
struct FixedPointShareStruct;
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

  // added by Liang Zhao
  // <a>: bit
  // <b>: vector
  // return: <a> & <b> using C-OT
  ShareWrapper XCOTMul(const ShareWrapper& b) const;

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

  // reshape shares in input into a larger share with num_of_wires wires and num_of_simd bits in
  // each wire
  // for example: num_of_wires = 2, num_of_simd = 3
  // input: std::vector {s_0, s_1, s_2, s_3, s_4, s_5} -> output: wire_1, wire_2,
  // where wire_1: {s_0, s_2, s_4}, wire_2: {s_1, s_3, s_5}
  static std::vector<ShareWrapper> SimdifyReshapeHorizontal(std::vector<ShareWrapper> input,
                                                            std::size_t num_of_wires,
                                                            std::size_t num_of_simd);

  // reshape shares in input into a larger share with num_of_wires wires and num_of_simd bits in
  // each wire
  // for example: num_of_wires = 2, num_of_simd = 3
  // input: std::vector {s_0, s_1, s_2, s_3, s_4, s_5} -> output: wire_1, wire_2,
  // where wire_1: {s_0, s_1, s_2}, wire_2: {s_3, s_4, s_5}
  static std::vector<ShareWrapper> SimdifyReshapeVertical(std::vector<ShareWrapper> input,
                                                          std::size_t num_of_wires,
                                                          std::size_t num_of_simd);

  // reshape shares in input into a larger share with num_of_wires wires and num_of_simd bits in
  // each wire
  // for example: num_of_wires = 2, num_of_simd = 3
  // input: std::vector {s_0, s_1, s_2} -> output: wire_1, wire_2,
  // where wire_1: {s_0, s_1, s_2}, wire_2: {s_0, s_1, s_2}
  static std::vector<ShareWrapper> SimdifyDuplicateHorizontal(std::vector<ShareWrapper> input,
                                                              std::size_t num_of_wires);

  // reshape shares in input into a larger share with num_of_wires wires and num_of_simd bits in
  // each wire
  // for example: num_of_wires = 2, num_of_simd = 3
  // input: std::vector {s_0, s_1} -> output: wire_1, wire_2,
  // where wire_1: {s_0, s_0}, wire_2: {s_1, s_1}
  static std::vector<ShareWrapper> SimdifyDuplicateVertical(std::vector<ShareWrapper> input,
                                                            std::size_t num_of_simd);

  // added by Liang Zhao
  // k-ary OR with log rounds based on SecureSCM-D.9.2, ref:
  // (https://faui1-files.cs.fau.de/filepool/publications/octavian_securescm/SecureSCM-D.9.2.pdf)
  ShareWrapper KOrL() const;

  // added by Liang Zhao
  // k-ary OR with log rounds based on SecureSCM-D.9.2, ref:
  // (https://faui1-files.cs.fau.de/filepool/publications/octavian_securescm/SecureSCM-D.9.2.pdf)
  // and MP-SPDZ (https://github.com/data61/MP-SPDZ)
  ShareWrapper KOrL(const std::vector<ShareWrapper>& boolean_gmw_share_x, std::size_t head,
                    std::size_t tail) const;

  // added by Liang Zhao
  // k-ary AND with log rounds based on SecureSCM-D.9.2, ref:
  // (https://faui1-files.cs.fau.de/filepool/publications/octavian_securescm/SecureSCM-D.9.2.pdf)
  ShareWrapper KAndL() const;

  // added by Liang Zhao
  // k-ary AND with log rounds based on SecureSCM-D.9.2, ref:
  // (https://faui1-files.cs.fau.de/filepool/publications/octavian_securescm/SecureSCM-D.9.2.pdf)
  // and MP-SPDZ (https://github.com/data61/MP-SPDZ)
  ShareWrapper KAndL(const std::vector<ShareWrapper>& boolean_gmw_share_x, std::size_t head,
                     std::size_t tail) const;

  // // added by Liang Zhao
  // ShareWrapper KMulL() const;

  // added by Liang Zhao
  ShareWrapper KMulL(const std::vector<ShareWrapper>& arithmetic_gmw_share_x_vector,
                     std::size_t head, std::size_t tail) const;

  // added by Liang Zhao
  // Naive PreOr algorithm based on SecureSCM-D.9.2, ref:
  // (https://faui1-files.cs.fau.de/filepool/publications/octavian_securescm/SecureSCM-D.9.2.pdf)
  // and MP-SPDZ (https://github.com/data61/MP-SPDZ)
  ShareWrapper PreOr() const;

  // added by Liang Zhao
  // Naive PreOr algorithm based on SecureSCM-D.9.2, ref:
  // (https://faui1-files.cs.fau.de/filepool/publications/octavian_securescm/SecureSCM-D.9.2.pdf)
  // and MP-SPDZ (https://github.com/data61/MP-SPDZ)
  ShareWrapper PreOr(const ShareWrapper& boolean_share_x) const;

  // added by Liang Zhao
  // PreOr algorithm with O(log(k) rounds based on SecureSCM-D.9.2, ref:
  // (https://faui1-files.cs.fau.de/filepool/publications/octavian_securescm/SecureSCM-D.9.2.pdf)
  // and MP-SPDZ (https://github.com/data61/MP-SPDZ)
  ShareWrapper PreOrL() const;

  // added by Liang Zhao
  // PreOr algorithm with O(log(k) rounds based on SecureSCM-D.9.2, ref:
  // (https://faui1-files.cs.fau.de/filepool/publications/octavian_securescm/SecureSCM-D.9.2.pdf)
  // and MP-SPDZ (https://github.com/data61/MP-SPDZ)
  ShareWrapper PreOrL(const ShareWrapper& boolean_share_x) const;

  // added by Liang Zhao
  // if arithmetic share a equals to arithmetic share b
  // based on paper (Multiparty Computation for Interval, Equality, and Comparison Without
  // Bit-Decomposition Protocol)
  template <typename T>
  ShareWrapper EQ(const ShareWrapper& arithmetic_gmw_share_a,
                  const ShareWrapper& arithmetic_gmw_share_b,
                  std::size_t bit_length_l = sizeof(T) * 8) const;

  // added by Liang Zhao
  // if arithmetic share a equals to constant b
  // based on paper (Multiparty Computation for Interval, Equality, and Comparison Without
  // Bit-Decomposition Protocol)
  template <typename T>
  ShareWrapper EQC(const ShareWrapper& arithmetic_gmw_share_a,
                   const ShareWrapper& arithmetic_value_b,
                   std::size_t bit_length_l = sizeof(T) * 8) const;

  // added by Liang Zhao
  // if arithmetic share a equals to zero
  // based on paper (Multiparty Computation for Interval, Equality, and Comparison Without
  // Bit-Decomposition Protocol)
  template <typename T>
  ShareWrapper EQZ(const ShareWrapper& arithmetic_gmw_share_a,
                   std::size_t bit_length_l = sizeof(T) * 8) const;

  // added by Liang Zhao
  // Comparison between Boolean gmw share and publicly known value R
  // based on paper (Rabbit: Efficient Comparison for Secure Multi-Party Computation)
  // R: R >= 0, publicly known Boolean bits (either publicly known before evaluation (stored as
  // constant wire) or publicly known after online evaluation (stored as Boolean gmw share) of
  // previous gates. <x>^B: Boolean gmw share return: R <= <x>^B
  ShareWrapper LTBits(const ShareWrapper& boolean_value_R,
                      const ShareWrapper& boolean_gmw_share_x) const;

  // added by Liang Zhao
  // Comparison between Boolean gmw share and publicly known value R
  // R: R >= 0, publicly known Boolean bits (either publicly known before evaluation (stored as
  // constant wire) or publicly known after online evaluation (stored as Boolean gmw share) of
  // previous gates. <x>^B: Boolean gmw share return: R < <x>^B inspired by paper (Rabbit: Efficient
  // Comparison for Secure Multi-Party Computation)
  ShareWrapper LTTBits(const ShareWrapper& boolean_value_R,
                       const ShareWrapper& boolean_gmw_share_x) const;

  //   // added by Liang Zhao
  //   // Comparison between an arithmetic gmw share x and a publicly known value R
  //   // based on paper (Rabbit: Efficient Comparison for Secure Multi-Party Computation)
  //   // R: R >= 0 (original paper assume R > 0, we extend it to the case when R >= 0),
  //   // R is a publicly known arithmetic value:
  //   // (i) either publicly known before evaluation (stored as constant wire)
  //   // (ii) publicly known after online evaluation (stored as arithmetic gmw share) of previous
  //   gates.
  //   // <x>^A: arithmetic gmw share
  //   // return: <x>^A < R

  // added by Liang Zhao
  // Comparison between an arithmetic gmw share x and a publicly known value R
  // based on paper (Rabbit: Efficient Comparison for Secure Multi-Party Computation)
  // R: R > 0 (original paper assume R > 0),
  // R is a publicly known arithmetic value:
  // (i) either publicly known before evaluation (stored as constant wire)
  // (ii) publicly known after online evaluation (stored as arithmetic gmw share) of previous gates.
  // <x>^A: arithmetic gmw share
  // return: <x>^A < R
  template <typename T>
  std::vector<ShareWrapper> LTC_MRVW(const ShareWrapper& arithemtic_gmw_share_x,
                                     const ShareWrapper& arithmetic_value_R) const;

  // added by Liang Zhao
  // R: constant value with R >= 0
  // return: <x>^A <= R
  template <typename T>
  ShareWrapper LTEQC(const ShareWrapper& arithemtic_gmw_share_x,
                     const ShareWrapper& arithmetic_value_R) const;

  // added by Liang Zhao
  // Comparison between arithmetic gmw share a and arithmetic gmw share b: a <= b (under assumption:
  // a can't be zero, original paper ignore this assumption)
  // based on paper (Rabbit: Efficient Comparison for Secure Multi-Party Computation)
  template <typename M>
  std::vector<ShareWrapper> LTS_MRVW(const ShareWrapper& arithemtic_gmw_share_a,
                                     const ShareWrapper& arithemtic_gmw_share_b) const;

  // added by Liang Zhao
  // Comparison between arithmetic gmw share a and arithmetic gmw share b: a <= b
  template <typename T>
  ShareWrapper LTEQS(const ShareWrapper& arithemtic_gmw_share_a,
                     const ShareWrapper& arithemtic_gmw_share_b) const;

  // added by Liang Zhao
  // a is taked as signed integer and MSB(a) is the sign
  // return: a < 0
  // use MSB(a) = trunc(a,k-1) to compute if a < 0
  // based on paper (Improved Primitives for MPC over Mixed Arithmetic-Binary Circuits, SCALE-MAMBA
  // v1.14: Documentation)
  template <typename T>
  ShareWrapper LTZ(const ShareWrapper& arithemtic_gmw_share_a) const;

  // added by Liang Zhao
  // a, b is taked as signed integer and MSB(a) is the sign
  // LT cannot compare when both a and b are taken unsigned integer as the MSB(a-b) is not the sign
  // of a - b return: a - b < 0 use MSB(a-b) = trunc(a-b,k-1) to compute if a-b < 0 based on paper
  // (Improved Primitives for MPC over Mixed Arithmetic-Binary Circuits, SCALE-MAMBA v1.14:
  // Documentation)
  template <typename T>
  ShareWrapper LT(const ShareWrapper& arithemtic_gmw_share_a,
                  const ShareWrapper& arithemtic_gmw_share_b) const;

  // added by Liang Zhao
  // compute <x>^A mod 2^m
  // 0 < m < sizeof(T) * 8
  // based on paper (Improved Primitives for MPC over Mixed Arithmetic-Binary Circuits)
  // <x>^A: arithmetic gmw share
  template <typename T>
  ShareWrapper ModPow2m(const ShareWrapper& arithmetic_gmw_share_x, std::size_t m) const;

  // added by Liang Zhao
  // compute <x>^A mod <2^m>^A
  // based on paper (Secure Computation on Floating Point Numbers (may contain errors), SCALE-MAMBA
  // v1.14: Documentation (14.3.8 Oblivious_Trunc)) the last element of output is <2^a>^A/ <x>^A:
  // arithmetic gmw share <m>^A: arithmetic gmw share 0 <= m < sizeof(T) * 8
  template <typename T>
  std::vector<ShareWrapper> ObliviousModPow2m(const ShareWrapper& arithmetic_gmw_share_a,
                                              const ShareWrapper& arithmetic_gmw_share_m) const;

  // added by Liang Zhao
  // compute logical right shift of <x>^A
  // based on paper (Improved Primitives for MPC over Mixed Arithmetic-Binary Circuits)
  // <x>^A: arithmetic gmw share
  // Note: consumes much memory and slow
  template <typename T>
  ShareWrapper LogicalRightShift_EGKRS(const ShareWrapper& arithmetic_gmw_share_x, std::size_t m,
                                       std::size_t l = sizeof(T) * 8) const;

  // added by Liang Zhao
  // compute logical right shift of <x>^A by converting arithmetic gmw share to boolean gmw share
  // bit, then directly shift the bits
  template <typename T>
  ShareWrapper LogicalRightShift_BitDecomposition(const ShareWrapper& arithmetic_gmw_share_x,
                                                  std::size_t m,
                                                  std::size_t l = sizeof(T) * 8) const;

  // added by Liang Zhao
  // compute logical left shift of <x>^A
  // based on paper (Improved Primitives for MPC over Mixed Arithmetic-Binary Circuits)
  // <x>^A: arithmetic gmw share
  template <typename T>
  ShareWrapper LogicalLeftShift(const ShareWrapper& arithmetic_gmw_share_x, std::size_t m,
                                std::size_t l = sizeof(T) * 8) const;

  // added by Liang Zhao
  // compute arithmetic right shift of <x>^A: <x>^A * 2^(-m), x is in interval [0, 2^l)
  // based on paper (Improved Primitives for MPC over Mixed Arithmetic-Binary Circuits)
  // <x>^A: arithmetic gmw share
  template <typename T>
  ShareWrapper ArithmeticRightShift(const ShareWrapper& arithmetic_gmw_share_x, std::size_t m,
                                    std::size_t l = sizeof(T) * 8) const;

  // added by Liang Zhao
  // compute arithmetic left shift of <x>^A: <x>^A * 2^(m), x is in interval [0, 2^l)
  // <x>^A: arithmetic gmw share
  template <typename T>
  ShareWrapper ArithmeticLeftShift(const ShareWrapper& arithmetic_gmw_share_x, std::size_t m,
                                   std::size_t l = sizeof(T) * 8) const;

  // added by Liang Zhao
  // truncation of x by right shifting m bits
  // to x/2^m under assumption that MSB(x) = 0, based on paper (Secure Evaluation of Quantized
  // Neural Networks). k = sizeof(T) * 8, assumption: m < (k-1), because when m = k - 1, the result
  // is always 0, as MSB(x) = 0
  // TODO: change return to ShareWrapper
  template <typename T>
  std::vector<ShareWrapper> TruncPr(const ShareWrapper& arithmetic_gmw_share_x,
                                    std::size_t m) const;

  // added by Liang Zhao
  // truncate x by a secret value m,
  // M: publicly known upper bound of m,
  // under assumption: no overflow for 2^(M-m) * x,
  // based on paper (Secure Evaluation of Quantized Neural Networks).
  template <typename T>
  ShareWrapper ObliviousTrunc(const ShareWrapper& arithmetic_gmw_share_x,
                              const ShareWrapper& arithmetic_gmw_share_m, std::size_t M) const;

  // added by Liang Zhao
  // compute arithmetic right shift of <x>^A and reduce it to field U
  // m: sizeof(U)
  // based on paper: SIRNN: A Math Library for Secure RNN Inference
  // <x>^A: arithmetic gmw share in field T
  template <typename T, typename U>
  ShareWrapper TruncateAndReduce(const ShareWrapper& arithmetic_gmw_share_x) const;

  // added by Liang Zhao
  // compute arithmetic/logical right shift of <x>^A: <x>^A >> s and reduce it to field U
  // return: (<x>^A >> m) mod 2^(l-s)
  // l: sizeof(T) * 8
  // require that: l - s <= sizeof(U) * 8
  // based on paper: SIRNN: A Math Library for Secure RNN Inference
  // <x>^A: arithmetic gmw share in field T
  template <typename T, typename U>
  ShareWrapper TruncateAndReduce(const ShareWrapper& arithmetic_gmw_share_x, std::size_t s,
                                 bool arithmetic_shift = false) const;

  // added by Liang Zhao
  // Extend arithmetic gmw share x (represent unsigned integer) from field M to field N
  // based on paper: SIRNN: A Math Library for Secure RNN Inference,
  // ZExt-protocol
  template <typename M, typename N>
  ShareWrapper UnsignedExtension(const ShareWrapper& arithmetic_gmw_share_x) const;

  // added by Liang Zhao
  // Extend arithmetic gmw share x (represent signed integer) from field T to field N
  // based on paper: SIRNN: A Math Library for Secure RNN Inference,
  // SExt-protocol
  template <typename M, typename N>
  ShareWrapper SignedExtension(const ShareWrapper& arithmetic_gmw_share_x) const;

  // added by Liang Zhao
  // Multiply x (field M) and y (field N), both represent unsigned integer and extend the result to
  // field L (L = M + N)
  // based on paper: SIRNN: A Math Library for Secure RNN Inference,
  template <typename M, typename N, typename L>
  ShareWrapper UnsignedMultiplicationWithExtension(
      const ShareWrapper& arithmetic_gmw_share_x, const ShareWrapper& arithmetic_gmw_share_y) const;

  // added by Liang Zhao
  // Multiply x (field M) and y (field N), both represent signed integer and extend the result to
  // field L (L = M + N)
  // based on paper: SIRNN: A Math Library for Secure RNN Inference,
  template <typename M, typename N, typename L>
  ShareWrapper SignedMultiplicationWithExtension(const ShareWrapper& arithmetic_gmw_share_x,
                                                 const ShareWrapper& arithmetic_gmw_share_y) const;

  // added by Liang Zhao
  // precompute the edaBit, i.e., generate random Boolean GMW shares: <r>^B = (<r_0>^B, ...,
  // <r_l>^B), and arithmetic share <r>^A = B2A(<r>^B), based on ideas from paper
  // (Improved Primitives for MPC over Mixed Arithmetic-Binary Circuits)
  template <typename T>
  ShareWrapper PrecomputationEdaBit() const;

  // added by Liang Zhao
  // precompute the edaBit, i.e., generate random Boolean GMW shares: <r>^B = (<r_0>^B, ...,
  // <r_l>^B), and arithmetic share <r>^A = B2A(<r>^B), based on ideas from paper
  // (Improved Primitives for MPC over Mixed Arithmetic-Binary Circuits)
  template <typename T>
  std::vector<ShareWrapper> EdaBit(std::size_t bit_size = sizeof(T) * 8,
                                   std::size_t num_of_simd = 1) const;

  // added by Liang Zhao
  // convert a (a <= l) to unary bits (original paper assume a < l)
  // the last element of output is <2^a>^A
  // based on paper (Secure Computation on Floating Point Numbers, SCALE-MAMBA v1.14: Documentation)
  template <typename T>
  std::vector<ShareWrapper> B2U(const ShareWrapper& arithmetic_gmw_share_a,
                                std::size_t l = sizeof(T) * 8,
                                bool return_boolean_share_vector = true,
                                bool return_pow2_a = false) const;

  // added by Liang Zhao
  std::vector<ShareWrapper> CreateFloatingPointShareVector(
      const ShareWrapper& arithmetic_gmw_share_v, const ShareWrapper& arithmetic_gmw_share_p,
      const ShareWrapper& arithmetic_gmw_share_z, const ShareWrapper& arithmetic_gmw_share_s,
      std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  template <typename T>
  std::vector<ShareWrapper> CreateConstantFloatingPointShareVector(
      T v, T p, T z, T s, std::size_t l = 53, std::size_t k = 11,
      std::size_t num_of_simd = 1) const;

  // added by Liang Zhao
  template <typename T>
  std::vector<ShareWrapper> CreateConstantFloatingPointShareVector(
      double floating_point_number, std::size_t l = 53, std::size_t k = 11,
      std::size_t num_of_simd = 1) const;

  // added by Liang Zhao
  FloatingPointShareStruct CreateFloatingPointShareStruct(
      const ShareWrapper& arithmetic_gmw_share_v, const ShareWrapper& arithmetic_gmw_share_p,
      const ShareWrapper& arithmetic_gmw_share_z, const ShareWrapper& arithmetic_gmw_share_s,
      std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  template <typename T>
  FloatingPointShareStruct CreateConstantFloatingPointShareStruct(T v, T p, T z, T s,
                                                                  std::size_t l = 53,
                                                                  std::size_t k = 11) const;

  // added by Liang Zhao
  template <typename T>
  FloatingPointShareStruct CreateConstantFloatingPointShareStruct(double floating_point_number,
                                                                  std::size_t l = 53,
                                                                  std::size_t k = 11) const;

  // added by Liang Zhao
  // floating-point addition
  // based on paper (Secure Computation on Floating Point Numbers, SCALE-MAMBA v1.14: Documentation)
  // v: mantissa
  // p: exponent
  // z: zero
  // s: sign
  template <typename T>
  std::vector<ShareWrapper> FLAdd_ABZS(
      const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
      const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
      const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
      const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
      std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  // floating-point subtraction
  // based on paper (Secure Computation on Floating Point Numbers, SCALE-MAMBA v1.14: Documentation)
  template <typename T>
  std::vector<ShareWrapper> FLSub_ABZS(
      const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
      const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
      const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
      const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
      std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  // "simple" division
  // approximate a / b
  // based on paper (Secure Computation on Floating Point Numbers, SCALE-MAMBA v1.14: Documentation)
  template <typename T>
  ShareWrapper SDiv_ABZS(const ShareWrapper& arithmetic_gmw_share_a,
                         const ShareWrapper& arithmetic_gmw_share_b, std::size_t l = 53) const;

  // added by Liang Zhao
  // floating-point division
  // a / b
  // based on paper (Secure Computation on Floating Point Numbers, SCALE-MAMBA v1.14: Documentation)
  template <typename T>
  std::vector<ShareWrapper> FLDiv_ABZS(
      const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
      const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
      const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
      const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
      std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  // floating-point multiplication
  // a * b
  // based on paper (Secure Computation on Floating Point Numbers, SCALE-MAMBA v1.14: Documentation)
  template <typename T>
  std::vector<ShareWrapper> FLMul_ABZS(
      const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
      const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
      const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
      const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
      std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  // floating-point less than
  // a < b
  // based on paper (Secure Computation on Floating Point Numbers, SCALE-MAMBA v1.14: Documentation)
  template <typename T>
  ShareWrapper FLLT_ABZS(
      const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
      const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
      const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
      const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
      std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  // floating-point equality
  // a == b
  // based on paper (Secure Computation on Floating Point Numbers, SCALE-MAMBA v1.14: Documentation
  // (may contain error))
  template <typename T>
  ShareWrapper FLEQ_ABZS(
      const ShareWrapper& arithmetic_gmw_share_v1, const ShareWrapper& arithmetic_gmw_share_p1,
      const ShareWrapper& arithmetic_gmw_share_z1, const ShareWrapper& arithmetic_gmw_share_s1,
      const ShareWrapper& arithmetic_gmw_share_v2, const ShareWrapper& arithmetic_gmw_share_p2,
      const ShareWrapper& arithmetic_gmw_share_z2, const ShareWrapper& arithmetic_gmw_share_s2,
      std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  // floating-point equality
  // ceil(a) or floor(a)
  // based on paper (Secure Computation on Floating Point Numbers, SCALE-MAMBA v1.14: Documentation)
  // mode = 0: floor
  // mode = 1: ceil
  template <typename T>
  std::vector<ShareWrapper> FLRound_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
                                         const ShareWrapper& arithmetic_gmw_share_p1,
                                         const ShareWrapper& arithmetic_gmw_share_z1,
                                         const ShareWrapper& arithmetic_gmw_share_s1,
                                         std::size_t mode = 0, std::size_t l = 53,
                                         std::size_t k = 11) const;

  // added by Liang Zhao
  // convert gamma-bit signed integer to floating-point
  // based on paper (Secure Computation on Floating Point Numbers, SCALE-MAMBA v1.14: Documentation)
  template <typename IntType, typename FLType = IntType>
  std::vector<ShareWrapper> Int2FL_ABZS(const ShareWrapper& arithmetic_gmw_share_a,
                                        std::size_t gamma = sizeof(IntType) * 8, std::size_t l = 53,
                                        std::size_t k = 11) const;
  // added by Liang Zhao
  // convert a floating-point number to a signed integer
  // we simplify the protocol from paper (Secure Computation on Floating Point Numbers)
  // assume the integer is large enough to hold the floating-point number
  template <typename FLType, typename IntType>
  std::vector<ShareWrapper> FL2Int_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
                                        const ShareWrapper& arithmetic_gmw_share_p1,
                                        const ShareWrapper& arithmetic_gmw_share_z1,
                                        const ShareWrapper& arithmetic_gmw_share_s1,
                                        std::size_t l = 53, std::size_t k = 11);

  // added by Liang Zhao
  // compute sqrt(<x>^A)
  // based on paper (Secure Computation on Floating Point Numbers (may contain error), SCALE-MAMBA
  // v1.14: Documentation )
  template <typename T>
  std::vector<ShareWrapper> FLSqrt_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
                                        const ShareWrapper& arithmetic_gmw_share_p1,
                                        const ShareWrapper& arithmetic_gmw_share_z1,
                                        const ShareWrapper& arithmetic_gmw_share_s1,
                                        std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  // compute sqrt(<x>^A)
  // based on paper (Secure Computation on Floating Point Numbers (may contain errors), SCALE-MAMBA
  // v1.14: Documentation)
  template <typename T>
  std::vector<ShareWrapper> FLExp2_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
                                        const ShareWrapper& arithmetic_gmw_share_p1,
                                        const ShareWrapper& arithmetic_gmw_share_z1,
                                        const ShareWrapper& arithmetic_gmw_share_s1,
                                        std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  // compute log2(<x>^A)
  // based on paper (Secure Computation on Floating Point Numbers (may contain errors), SCALE-MAMBA
  // v1.14: Documentation)
  template <typename T>
  std::vector<ShareWrapper> FLLog2_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
                                        const ShareWrapper& arithmetic_gmw_share_p1,
                                        const ShareWrapper& arithmetic_gmw_share_z1,
                                        const ShareWrapper& arithmetic_gmw_share_s1,
                                        std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  // compute e^(<x>)
  // based on paper (Secure Computation on Floating Point Numbers (may contain errors)
  template <typename T>
  std::vector<ShareWrapper> FLExp_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
                                       const ShareWrapper& arithmetic_gmw_share_p1,
                                       const ShareWrapper& arithmetic_gmw_share_z1,
                                       const ShareWrapper& arithmetic_gmw_share_s1,
                                       std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  // compute ln(<x>^A)
  // based on paper (Secure Computation on Floating Point Numbers (may contain errors), SCALE-MAMBA
  // v1.14: Documentation)
  template <typename T>
  std::vector<ShareWrapper> FLLn_ABZS(const ShareWrapper& arithmetic_gmw_share_v1,
                                      const ShareWrapper& arithmetic_gmw_share_p1,
                                      const ShareWrapper& arithmetic_gmw_share_z1,
                                      const ShareWrapper& arithmetic_gmw_share_s1,
                                      std::size_t l = 53, std::size_t k = 11) const;

  // ------------------------------------------------------------
  // TODO: wrap floating point operation in struct or class
  template <typename T>
  std::vector<ShareWrapper> FLAdd_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
                                       const std::vector<ShareWrapper>& arithmetic_gmw_share_2,
                                       std::size_t l = 53, std::size_t k = 11) const;

  template <typename T>
  std::vector<ShareWrapper> FLSub_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
                                       const std::vector<ShareWrapper>& arithmetic_gmw_share_2,
                                       std::size_t l = 53, std::size_t k = 11) const;

  template <typename T>
  std::vector<ShareWrapper> FLDiv_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
                                       const std::vector<ShareWrapper>& arithmetic_gmw_share_2,
                                       std::size_t l = 53, std::size_t k = 11) const;

  template <typename T>
  std::vector<ShareWrapper> FLMul_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
                                       const std::vector<ShareWrapper>& arithmetic_gmw_share_2,
                                       std::size_t l = 53, std::size_t k = 11) const;

  template <typename T>
  ShareWrapper FLLT_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
                         const std::vector<ShareWrapper>& arithmetic_gmw_share_2,
                         std::size_t l = 53, std::size_t k = 11) const;

  template <typename T>
  ShareWrapper FLEQ_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
                         const std::vector<ShareWrapper>& arithmetic_gmw_share_2,
                         std::size_t l = 53, std::size_t k = 11) const;

  template <typename T>
  std::vector<ShareWrapper> FLRound_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
                                         std::size_t mode, std::size_t l = 53,
                                         std::size_t k = 11) const;

  template <typename T>
  std::vector<ShareWrapper> FLSqrt_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
                                        std::size_t l = 53, std::size_t k = 11) const;

  template <typename T>
  std::vector<ShareWrapper> FLExp2_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
                                        std::size_t l = 53, std::size_t k = 11) const;

  template <typename T>
  std::vector<ShareWrapper> FLLog2_ABZS(const std::vector<ShareWrapper>& arithmetic_gmw_share_1,
                                        std::size_t l = 53, std::size_t k = 11) const;

  // ------------------------------------------------------------

  template <typename T>
  FloatingPointShareStruct FLMul_ABZS(const FloatingPointShareStruct& arithmetic_gmw_share_1,
                                      const FloatingPointShareStruct& arithmetic_gmw_share_2,
                                      std::size_t l = 53, std::size_t k = 11) const;

  // added by Liang Zhao
  // floating-point numbers product with log(n) multiplications
  // a0 * a1 * ... * a_(n-1)
  template <typename T>
  FloatingPointShareStruct FLProd_ABZS(
      const std::vector<FloatingPointShareStruct>& floating_point_struct_vector, std::size_t head,
      std::size_t tail, std::size_t l = 53, std::size_t k = 11) const;

  // ------------------------------------------------------------
  // added by Liang Zhao
  FixedPointShareStruct CreateFixedPointShareStruct(const ShareWrapper& arithmetic_gmw_share_v,
                                                    std::size_t k = 41, std::size_t f = 20) const;

  // added by Liang Zhao
  template <typename T>
  FixedPointShareStruct CreateFixedPointShareStruct(T v, std::size_t k = 41, std::size_t f = 20,
                                                    std::size_t num_of_simd = 1) const;

  // added by Liang Zhao
  template <typename T>
  FixedPointShareStruct CreateFixedPointShareStruct(double fixed_point_number, std::size_t k = 41,
                                                    std::size_t f = 20,
                                                    std::size_t num_of_simd = 1) const;

  // based on paper (Secure Computation With Fixed-Point Numbers)
  template <typename T>
  FixedPointShareStruct FxAdd_CS(const FixedPointShareStruct& fixed_point_a,
                                 const FixedPointShareStruct& fixed_point_b) const;

  // based on paper (Secure Computation With Fixed-Point Numbers)
  template <typename T>
  FixedPointShareStruct FxSub_CS(const FixedPointShareStruct& fixed_point_a,
                                 const FixedPointShareStruct& fixed_point_b) const;

  // based on paper (Secure Computation With Fixed-Point Numbers)
  template <typename T>
  FixedPointShareStruct FxMul_CS(const FixedPointShareStruct& fixed_point_a,
                                 const FixedPointShareStruct& fixed_point_b) const;

  // fixed_point_b is a constant value
  // based on paper (SCALE-MAMBA v1.14: Documentation)
  template <typename T, typename T_int>
  FixedPointShareStruct FxDivSimple_CS(const FixedPointShareStruct& fixed_point_a,
                                       const T fixed_point_b) const;

  // based on paper (Secure Computation With Fixed-Point Numbers)
  template <typename T>
  FixedPointShareStruct FxDiv_CS(const FixedPointShareStruct& fixed_point_a,
                                 const FixedPointShareStruct& fixed_point_b) const;

  template <typename T>
  ShareWrapper FxAppRcr_CS(const ShareWrapper& arithmetic_gmw_share_b, std::size_t k = 41,
                           std::size_t f = 20) const;

  template <typename T>
  std::vector<ShareWrapper> FxNorm_CS(const ShareWrapper& arithmetic_gmw_share_b,
                                      std::size_t k = 41, std::size_t f = 20) const;

  template <typename T>
  ShareWrapper FxLT_CS(const FixedPointShareStruct& fixed_point_a,
                       const FixedPointShareStruct& fixed_point_b) const;

  template <typename T>
  ShareWrapper FxEQ_CS(const FixedPointShareStruct& fixed_point_a,
                       const FixedPointShareStruct& fixed_point_b) const;

  template <typename T, typename T_int>
  FixedPointShareStruct FxSqrt(const FixedPointShareStruct& fixed_point_a) const;

  // based on paper (Secure Distributed Computation of the Square Root and Applications, SCALE-MAMBA
  // v1.14: Documentation)
  template <typename T, typename T_int>
  FixedPointShareStruct FxParamFxSqrt_CS(const ShareWrapper& arithmetic_gmw_share_x,
                                         std::size_t k = 41, std::size_t f = 20) const;

  template <typename T, typename T_int>
  ShareWrapper FxLinAppSQ(const ShareWrapper& arithmetic_gmw_share_x, std::size_t k = 41,
                          std::size_t f = 20) const;

  template <typename T>
  std::vector<ShareWrapper> FxNormSQ(const ShareWrapper& arithmetic_gmw_share_x, std::size_t k = 41,
                                     std::size_t f = 20) const;

  template <typename T>
  FloatingPointShareStruct Fx2FL(const FixedPointShareStruct& fixed_point_a, std::size_t gamma,
                                 std::size_t f, std::size_t l, std::size_t k) const;

  // TODO: need test
  template <typename T>
  FixedPointShareStruct Int2Fx(const ShareWrapper& arithmetic_gmw_share_a, std::size_t k,
                               std::size_t f) const;

  // template <typename T>
  // ShareWrapper Fx2Int(const ShareWrapper& arithmetic_gmw_share_a, std::size_t k,
  //                              std::size_t f) const;

  // based on paper (Benchmarking Privacy Preserving Scientific Operations, SCALE-MAMBA v1.14:
  // Documentation)
  template <typename T>
  FixedPointShareStruct FxSqrt_P0132(const FixedPointShareStruct& fixed_point_a) const;

  // based on paper (Benchmarking Privacy Preserving Scientific Operations)
  template <typename T>
  FixedPointShareStruct FxExp2_P1045(const FixedPointShareStruct& fixed_point_a) const;

  // based on paper (Benchmarking Privacy Preserving Scientific Operations)
  template <typename T>
  FixedPointShareStruct FxLog2_P2508(const FixedPointShareStruct& fixed_point_a) const;

  template <typename T>
  FixedPointShareStruct FxExp(const FixedPointShareStruct& fixed_point_a) const;

  template <typename T>
  FixedPointShareStruct FxLn(const FixedPointShareStruct& fixed_point_a) const;

  // based on paper (SCALE-MAMBA v1.14: Documentation)
  template <typename T>
  FixedPointShareStruct FxPolyEval(const FixedPointShareStruct& fixed_point_x,
                                   const double coefficient[], std::size_t array_size) const;

  // ------------------------------------------------------------

  // // TODO: implement
  // remove later
  //   template <typename T>
  //   ShareWrapper FxFloor_CS(const ShareWrapper& v1, std::size_t k = 41, std::size_t f = 20)
  //   const;

  // // TODO: implement
  // remove later
  //   template <typename T>
  //   ShareWrapper FxCeil_CS(const ShareWrapper& v1, std::size_t k = 41, std::size_t f = 20) const;

  template <typename T>
  ShareWrapper Fx2IntWithRoundTowardsZero_CS(const ShareWrapper& v1, std::size_t k = 41,
                                             std::size_t f = 20) const;

  template <typename T>
  FixedPointShareStruct FxNeg_CS(const ShareWrapper& v1, std::size_t k = 41,
                                 std::size_t f = 20) const;

  template <typename T>
  FixedPointShareStruct FxAbs_CS(const ShareWrapper& v1, std::size_t k = 41,
                                 std::size_t f = 20) const;

  template <typename T>
  ShareWrapper FxLTZ_CS(const ShareWrapper& v1, std::size_t k = 41, std::size_t f = 20) const;

  template <typename T>
  ShareWrapper FxEQZ_CS(const ShareWrapper& v1, std::size_t k = 41, std::size_t f = 20) const;

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

  // added by Liang Zhao
  // partie reshare their local Boolean gmw share as private input with other parties
  std::vector<ShareWrapper> ReshareBooleanGmw() const;

  // // added by Liang Zhao
  // // compute the wrap (carry bits) of 64-bit Boolean shares
  // ??? not correct to compute wrap function
  // std::vector<ShareWrapper> Summation64BitBooleanGMWWithWrap(
  //     std::vector<ShareWrapper> boolean_share_vector) const;

  // added by Liang Zhao
  // compute the summation of boolean gmw shares (treated as SecureUnsignedInteger)
  // template <typename T>
  ShareWrapper SummationBooleanGMW(const std::vector<ShareWrapper>& boolean_gwm_share_vector) const;

  // added by Liang Zhao
  // compute the summation of arithmetic gmw shares
  ShareWrapper SummationArithmeticGMW(
      const std::vector<ShareWrapper>& arithmetic_gmw_share_vector) const;

  // added by Liang Zhao
  // convert Boolean gmw bit share to arithmetic shares and calculate their sum
  // may not very useful, remove later
  template <typename T>
  ShareWrapper SummationBooleanGmwBitToArithmeticGmw(
      const std::vector<ShareWrapper>& boolean_gmw_share_vector) const;

  // added by Liang Zhao
  // reconstruct the share in a larger number field (e.g., reconstruct std::uint8_t arithmetic as
  // std::uint16_t value)
  ShareWrapper ReconstructInLargerField(
      std::size_t output_owner = std::numeric_limits<std::int64_t>::max()) const;

  // added by Liang Zhao
  // compute the wrap of arithmetic shares holding by all parties, where wrap is an arithmetic
  // value.
  // For example, when we compute the sum of arithmetic share of x and left shift it to get the wrap
  // value: wrap = <x>^A_0 + ... + <x>^A_(N-1) >> l, where l is the number of bits in field T and
  // <x>^A_0 is in field T. x can be reconstructed as: x = <x>^A_0 + ... + <x>^A_(N-1) mod 2^l. Note
  // the wrap is ignored when we reconstruct x in field T. To compute the wrap, we need to compute
  // the sum of <x>^A_i in a larger field (e.g., U). U is a larger number field than T that used to
  // calculate <x>^A_0 + ... + <x>^A_(N-1) without overflow.
  // output is in field T (T < U)
  // See paper (SIRNN: A Math Library for Secure RNN Inference, 2021.pdf)
  template <typename T, typename U>
  std::vector<ShareWrapper> SummationArithmeticGMWAndOutputArithmeticGmwWrapInSmallField(
      const ShareWrapper& arithmetic_gmw_share_x) const;

  // added by Liang Zhao
  // same function as SummationArithmeticGMWAndOutputArithmeticGmwWrapInSmallField
  // but the output is in larger field U (T < U)
  template <typename T, typename U>
  std::vector<ShareWrapper> SummationArithmeticGMWAndOutputArithmeticGmwWrapInLargeField(
      const ShareWrapper& arithmetic_gmw_share_x) const;

  // added by Liang Zhao
  // x: publicly known arithmetic value (stored as arithmetic share) after online evaluation of
  // previous gates. return: remainder = x mod U_max, x is in number field of T (T > U). wrap = x >>
  // l, where l = sizeof(U) is the number of bits in field U.
  template <typename T, typename U>
  std::vector<ShareWrapper> ArithmeticValueModularReductionWithWrap(
      const ShareWrapper& arithmetic_value_x) const;

  // added by Liang Zhao
  // x: publicly known arithmetic value (stored as arithmetic share) after online evaluation of
  // previous gates.
  // compute x mod m
  template <typename T>
  ShareWrapper ArithmeticValueModularReduction(const ShareWrapper& arithmetic_value_x,
                                               const ShareWrapper& arithmetic_value_modulo) const;

  // added by Liang Zhao
  // x: publicly known arithmetic value (stored as arithmetic share) after online evaluation of
  // previous gates.
  // compute x >> m
  template <typename T>
  ShareWrapper ArithmeticValueLogicalRightShift(const ShareWrapper& arithmetic_value_x,
                                                std::size_t m) const;

  // added by Liang Zhao
  // convert this share to arithmetic GMW share of data type T
  // ??? todo: replace gate creation with this function
  template <typename T>
  ShareWrapper BooleanGmwBitsToArithmeticGmw(std::size_t bit_size = 1) const;

  // added by Liang Zhao
  // convert boolean_gmw_share_a to arithmetic GMW share of data type T
  template <typename T>
  ShareWrapper BooleanGmwBitsToArithmeticGmw(const ShareWrapper& boolean_gmw_share_a,
                                             std::size_t bit_size = 1) const;

  // added by Liang Zhao
  // extract the least significnat bit of arithmetic share and convert it to arithmetic share
  // used for arithmetic share (field T) that equals to 1 or 0, and we want to convert it to another
  // arithmetic share (field U)
  template <typename T, typename U>
  ShareWrapper ArithmeticGmwToBooleanGmwBit(const ShareWrapper& arithmetic_gmw_share_a) const;

  // added by Liang Zhao
  // the bit size of share need to be a power of two,
  // e.g., bit_size = 8, the output has 2^8 bits
  // see paper (Efficient Lookup-Table Protocol in Secure Multiparty Computation)
  ShareWrapper Demux(const ShareWrapper& boolean_gmw_share) const;

  // added by Liang Zhao
  // reconstruct the arithmetic gmw share <h> and choose the elements in the vector according to h
  template <typename T>
  ShareWrapper ReconstructArithmeticGmwShareAndSelectFromShareVector(
      const ShareWrapper& arithmetic_gmw_share_index_head, std::size_t offset,
      std::size_t num_of_select_elements,
      const ShareWrapper& boolean_gmw_share_vector_to_select) const;

  // added by Liang Zhao
  // reconstruct the arithmetic gmw share x and bit decompose it
  template <typename T>
  std::vector<ShareWrapper> ReconstructArithmeticGmwShareAndBitDecompose(
      const ShareWrapper& arithmetic_gmw_share_x) const;

  // added by Liang Zhao
  // prepare the lookup table with Demux
  // see paper (Faster Secure Multi-Party Computation of AES and DES Using Lookup Tables)
  // generate the secret shared lookup table
  // modify the original protocol:
  // <T(i+s)> = (T(i) & <s_0'>) ^ (T(i+1) & <s_1'>) ^ ... ^ (T(i+2^l-1) & <s_(2^l-1)'>)
  // only <s_s'> = 1, others equal to 0
  // i is in [0,2^l-1]
  // l: num_of_rows (i.e., input bit length of the lookup table)
  // we convert T(i) to boolean bits, otherwise we need to convert <s_i'> to arithmetic gmw shares,
  // which is expensive.
  // then all the operations are boolean operations
  // Note that T(i) is publicly known, means that T(i) & <s_0'> can be computed locally without
  // interaction T(i) first need to convert to constant boolean share
  template <typename T>
  ShareWrapper SecretShareLookupTable(
      const std::vector<std::vector<bool>>& lookup_table,
      const ShareWrapper& arithmetic_gmw_share_lookup_table_index) const;

  // added by Liang Zhao
  // ??? has potential problem
  // may remove later
  // decompose 16-bit integer x into c = l/d digits (integers) of length d-bits
  // l: sizeof(T)
  // d: decomposition_bit_size_d
  // based on paper (SIRNN: A Math Library for Secure RNN Inference)
  template <typename XType, typename DigitType = get_shrink_type_t<XType>>
  std::vector<ShareWrapper> DigitDecomposition(const ShareWrapper& arithmetic_gmw_share_x,
                                               std::size_t final_digit_bit_size_d = 8) const;

  // added by Liang Zhao
  // MSNZB(x) computes to the index of the most significant non-zero-bit of arithmetic gmw share x
  // based on paper (SIRNN: A Math Library for Secure RNN Inference)
  // TODO: not consider when input x = 0. current would ouput 0, may fix later by adding an ...
  // TODO: additional lookup table full of ones as the entension of x string
  template <typename XType, typename DigitType, typename OutputType>
  std::vector<ShareWrapper> MSNZB_SIRNN(const ShareWrapper& arithmetic_gmw_share_x,
                                        const std::vector<std::vector<bool>>& lookup_table_MSNZB,
                                        std::size_t input_bit_size_d = 8) const;

  // added by Liang Zhao
  // MSNZB(x) computes to the index of the most significant non-zero-bit of arithmetic gmw share x
  // l: valid bit length of x
  // based on paper (Secure Computation on Floating Point Numbers)
  // can't deal with x = 0, output sizeof(T)*8, that is incorrect
  template <typename T>
  ShareWrapper MSNZB_ABZS(const ShareWrapper& arithmetic_gmw_share_x,
                          std::size_t l = sizeof(T) * 8) const;

  // TODO: move to private later, for test only
  // added by Liang Zhao
  // convert arithmetic value to digits (integer of length digit_bit_size_d)
  template <typename T, typename DigitType>
  std::vector<ShareWrapper> ArithmeticValueDigitDecomposition(const ShareWrapper& arithmetic_value,
                                                              std::size_t digit_bit_size_d) const;

  // added by Liang Zhao
  // use the inverted binary tree to select the first element from y (y = y0||c0,...,yn||cn) that
  // has ci = 1 boolean_gmw_share_x_vector: y0 || ... || yn || c
  ShareWrapper InvertBinaryTreeSelection(const std::vector<ShareWrapper>& share_y_c_vector) const;

  std::vector<ShareWrapper> InvertBinaryTreeSelection(
      const std::vector<ShareWrapper>& share_y_vector,
      const std::vector<ShareWrapper>& share_c_vector) const;

  // added by Liang Zhao
  // compute <2^a>^A, where <2^a> <= T_max
  // l: the value range for a, i.e., a is in [0,l)
  // m: bit length of a
  // based on paper (Secure Computation on Floating Point Numbers)
  template <typename T>
  ShareWrapper Pow2(ShareWrapper arithmetic_gmw_share_a, std::size_t m = sizeof(T) * 8) const;

  // added by Liang Zhao
  // input constant unsigned integer as boolean gmw input
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper CreateConstantArithmeticGmwInput(T constant_value,
                                                std::size_t num_of_simd = 1) const;

  // added by Liang Zhao
  // input constant unsigned integer vector as boolean gmw input
  template <typename T, typename A>
  ShareWrapper CreateConstantArithmeticGmwInput(std::vector<T, A> constant_value_vector) const;

  // added by Liang Zhao
  // input constant unsigned integer vector as Boolean GMW input
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper CreateConstantAsBooleanGmwInput(T constant_value, std::size_t num_of_simd) const;
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper CreateConstantAsBooleanGmwInput(T constant_value) const;

  // added by Liang Zhao
  // input constant bool value as Boolean GMW input
  ShareWrapper CreateConstantAsBooleanGmwInput(bool constant_value, std::size_t num_of_simd) const;
  ShareWrapper CreateConstantAsBooleanGmwInput(bool constant_value) const;

  // added by Liang Zhao
  // input constant double value as Boolean GMW input
  ShareWrapper CreateConstantAsBooleanGmwInput(float constant_value, std::size_t num_of_simd) const;
  ShareWrapper CreateConstantAsBooleanGmwInput(float constant_value) const;
  ShareWrapper CreateConstantAsBooleanGmwInput(double constant_value,
                                               std::size_t num_of_simd) const;
  ShareWrapper CreateConstantAsBooleanGmwInput(double constant_value) const;

  // ================================

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper CreateConstantAsBmrInput(T constant_value, std::size_t num_of_simd) const;
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper CreateConstantAsBmrInput(T constant_value) const;

  // added by Liang Zhao
  // input constant bool value as BMR input
  ShareWrapper CreateConstantAsBmrInput(bool constant_value) const;
  ShareWrapper CreateConstantAsBmrInput(bool constant_value, std::size_t num_of_simd) const;

  // added by Liang Zhao
  // input constant double value as BMR input
  ShareWrapper CreateConstantAsBmrInput(float constant_value, std::size_t num_of_simd) const;
  ShareWrapper CreateConstantAsBmrInput(float constant_value) const;
  ShareWrapper CreateConstantAsBmrInput(double constant_value, std::size_t num_of_simd) const;
  ShareWrapper CreateConstantAsBmrInput(double constant_value) const;

  // ================================

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper CreateConstantAsGCInput(T constant_value, std::size_t num_of_simd) const;
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper CreateConstantAsGCInput(T constant_value) const;

  // added by Liang Zhao
  // input constant bool value as Garbled Circuit input
  ShareWrapper CreateConstantAsGCInput(bool constant_value) const;
  ShareWrapper CreateConstantAsGCInput(bool constant_value, std::size_t num_of_simd) const;

  // added by Liang Zhao
  // input constant double value as Garbled Circuit input
  ShareWrapper CreateConstantAsGCInput(float constant_value, std::size_t num_of_simd) const;
  ShareWrapper CreateConstantAsGCInput(float constant_value) const;
  ShareWrapper CreateConstantAsGCInput(double constant_value, std::size_t num_of_simd) const;
  ShareWrapper CreateConstantAsGCInput(double constant_value) const;

  // ================================

  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper CreateConstantAsBooleanGmwBmrGCInput(T constant_value,
                                                    std::size_t num_of_simd) const;
  template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  ShareWrapper CreateConstantAsBooleanGmwBmrGCInput(T constant_value) const;

  // added by Liang Zhao
  // input constant bool value
  ShareWrapper CreateConstantAsBooleanGmwBmrGCInput(bool constant_value) const;
  ShareWrapper CreateConstantAsBooleanGmwBmrGCInput(bool constant_value,
                                                    std::size_t num_of_simd) const;

  // added by Liang Zhao
  // input constant double value
  ShareWrapper CreateConstantAsBooleanGmwBmrGCInput(float constant_value,
                                                    std::size_t num_of_simd) const;
  ShareWrapper CreateConstantAsBooleanGmwBmrGCInput(float constant_value) const;
  ShareWrapper CreateConstantAsBooleanGmwBmrGCInput(double constant_value,
                                                    std::size_t num_of_simd) const;
  ShareWrapper CreateConstantAsBooleanGmwBmrGCInput(double constant_value) const;

  // added by Liang Zhao
  // input constant fixed value as boolean gmw input
  template <typename T>
  ShareWrapper CreateConstantAsBooleanGmwInputFromFixedPoint(
      double constant_value, std::size_t num_of_simd,
      std::size_t fixed_point_fraction_bit_size) const;

  template <typename T>
  ShareWrapper CreateConstantAsBooleanGmwInputFromFixedPoint(
      double constant_value, std::size_t fixed_point_fraction_bit_size) const;

  template <typename T>
  ShareWrapper CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint(
      double constant_value, std::size_t num_of_simd,
      std::size_t fixed_point_fraction_bit_size) const;

  template <typename T>
  ShareWrapper CreateConstantAsBooleanGmwBmrGCInputFromFixedPoint(
      double constant_value, std::size_t fixed_point_fraction_bit_size) const;

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

  // added by Liang Zhao
  // TODO: improve according to ABY paper using OT, which is more efficient
  ShareWrapper BooleanGmwToGC() const;

  // added by Liang Zhao
  ShareWrapper GCToBooleanGmw() const;

  // added by Liang Zhao
// TODO:
  ShareWrapper ArithmeticGmwToGC() const;

  void ShareConsistencyCheck() const;

 public:
  // added by Liang Zhao
  // used to precompute MPC protocols
  std::size_t number_of_parties_;

  // added by Liang Zhao
  // compare the plaintext values (hold as arithmetic share) of a and b
  // return: boolean gmw share or arithmetic share
  // when set_zero_as_maximum is true and b is zero, return a < T_max
  template <typename T>
  ShareWrapper ArithmeticValueLessThan(const ShareWrapper& arithmetic_value_a,
                                       const ShareWrapper& arithmetic_value_b,
                                       bool return_boolean_value = true,
                                       bool set_zero_as_maximum = false) const;

  // added by Liang Zhao
  // addition of the plaintext values (hold as arithmetic share) of a and b
  template <typename T>
  ShareWrapper ArithmeticValueAddition(const ShareWrapper& arithmetic_value_a,
                                       const ShareWrapper& arithmetic_value_b) const;

  // added by Liang Zhao
  // subtraction of the plaintext values (hold as arithmetic share) of a and b
  template <typename T>
  ShareWrapper ArithmeticValueSubtraction(const ShareWrapper& arithmetic_value_a,
                                          const ShareWrapper& arithmetic_value_b) const;

  // added by Liang Zhao
  // negation of the plaintext value (hold as arithmetic share) of a
  template <typename T>
  ShareWrapper ArithmeticValueMinus(const ShareWrapper& arithmetic_value) const;

  // added by Liang Zhao
  // multiplication of the plaintext values (hold as arithmetic share) of a and b
  template <typename T>
  ShareWrapper ArithmeticValueMultiplication(const ShareWrapper& arithmetic_value_a,
                                             const ShareWrapper& arithmetic_value_b) const;

  // added by Liang Zhao
  // division of the plaintext values (hold as arithmetic share) of a and b
  template <typename T>
  ShareWrapper ArithmeticValueDivision(const ShareWrapper& arithmetic_value_a,
                                       const ShareWrapper& arithmetic_value_b) const;

  // added by Liang Zhao
  // convert arithmetic value to boolean value
  template <typename T>
  ShareWrapper ArithmeticValueBitDecomposition(const ShareWrapper& arithmetic_value) const;

  // added by Liang Zhao
  // convert arithmetic value (field T) to boolean value (bit length equals to sizeof(U))
  template <typename T, typename U>
  ShareWrapper ArithmeticValueToBooleanValue(const ShareWrapper& arithmetic_value) const;

  // added by Liang Zhao
  // convert boolean value to arithmetic value
  template <typename T>
  ShareWrapper BooleanValueToArithmeticValue(const ShareWrapper& boolean_share) const;

  // added by Liang Zhao
  // convert constant arithmetic share (publicly known before online evaluation) to arithmetic gmw
  // share (the value is publicly known after online evaluation)
  template <typename T>
  ShareWrapper ConstantArithmeticGmwToArithmeticValue(
      const ShareWrapper& constant_arithmetic_gmw_share) const;

  // added by Liang Zhao
  // convert constant arithmetic share (publicly known before online evaluation) to boolean gmw
  // share (the value is publicly known after online evaluation)
  // if as_boolean_gmw_share = true, the converted gmw share after reconstruction is the same as
  // constant arithmetic value, otherwise, when each party hold the same value of constant
  // arithmetic value, the reconstructed gmw share equals to zero.
  template <typename T>
  ShareWrapper ConstantArithmeticGmwToBooleanValue(
      const ShareWrapper& constant_arithmetic_gmw_share, bool as_boolean_gmw_share = false) const;

  // added by Liang Zhao
  // x: arithmetic value (hold as arithmetic share) after online evaluation of
  // previous gates.
  // return: {b, c}
  // b = x >> l, where l = sizeof(U) is the number of bits in field U, c = x mod U_max, x is in
  // number field of T (T > U).
  template <typename T, typename U>
  std::vector<ShareWrapper> ArithmeticValueSplit(const ShareWrapper& arithmetic_value_x) const;

  // added by Liang Zhao
  // x: arithmetic value (hold as arithmetic share) after online evaluation of
  // previous gates.
  // return: arithmetic value of x in field U
  // if U is larger than T, we extend x to field U
  // if U is smaller than T, we truncate x to field U
  template <typename T, typename U>
  ShareWrapper ArithmeticValueFieldConversion(const ShareWrapper& arithmetic_value_x) const;

  // added by Liang Zhao
  // boolean value operation where a or b is a boolean GMW share (publicly known value after online
  // evaluation)
  ShareWrapper BooleanValueXor(const ShareWrapper& boolean_gmw_share_a,
                               const ShareWrapper& boolean_gmw_share_b) const;

  // added by Liang Zhao
  // boolean value operation where a or b is a boolean value (publicly known value after online
  // evaluation)
  ShareWrapper BooleanValueAnd(const ShareWrapper& boolean_gmw_share_a,
                               const ShareWrapper& boolean_gmw_share_b) const;

  // added by Liang Zhao
  // see paper (Efficient Lookup-Table Protocol in Secure Multiparty Computation)
  ShareWrapper BooleanGmwBitDemux(const ShareWrapper& boolean_gmw_share_a) const;

  // added by Liang Zhao
  // see paper (Efficient Lookup-Table Protocol in Secure Multiparty Computation)
  ShareWrapper BooleanValueExpand(const ShareWrapper& boolean_gmw_share_a) const;

  // added by Liang Zhao
  // see paper (Efficient Lookup-Table Protocol in Secure Multiparty Computation)
  ShareWrapper BooleanValueReplicate(const ShareWrapper& boolean_gmw_share_a) const;

  // added by Liang Zhao
  // see paper (Efficient Lookup-Table Protocol in Secure Multiparty Computation)
  std::vector<ShareWrapper> BooleanValueExpandAndReplicateAndMultiply(
      const std::vector<ShareWrapper>& boolean_gmw_share_a_vector) const;

  // added by Liang Zhao
  ShareWrapper BooleanValueSelection(const ShareWrapper& boolean_gmw_share_a,
                                     const ShareWrapper& boolean_gmw_share_b,
                                     const ShareWrapper& boolean_gmw_share_c) const;
};

ShareWrapper DotProduct(std::span<ShareWrapper> a, std::span<ShareWrapper> b);

struct FloatingPointShareStruct {
  ShareWrapper mantissa;
  ShareWrapper exponent;
  ShareWrapper zero;
  ShareWrapper sign;
  ShareWrapper error;  // we currently ignore errors
  std::size_t l = 53;
  std::size_t k = 11;
};
struct FixedPointShareStruct {
  ShareWrapper v;
  ShareWrapper error;  // we currently ignore errors
  std::size_t k = 41;
  std::size_t f = 20;
};

}  // namespace encrypto::motion
