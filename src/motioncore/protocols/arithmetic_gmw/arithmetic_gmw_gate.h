// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko, Lennart Braun
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

#include "arithmetic_gmw_share.h"
#include "arithmetic_gmw_wire.h"

#include <memory>
#include <span>

#include "base/motion_base_provider.h"
#include "multiplication_triple/mt_provider.h"
#include "multiplication_triple/sp_provider.h"
#include "oblivious_transfer/1_out_of_n/kk13_ot_flavors.h"
#include "protocols/gate.h"
#include "utility/reusable_future.h"

// added by Liang Zhao
#include "multiplication_triple/sb_provider.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/constant/constant_wire.h"
//  Forward Declaration
namespace encrypto::motion::proto::boolean_gmw {

class Wire;
using WirePointer = std::shared_ptr<boolean_gmw::Wire>;

class Share;
using SharePointer = std::shared_ptr<boolean_gmw::Share>;

}  // namespace encrypto::motion::proto::boolean_gmw

namespace encrypto::motion::proto::arithmetic_gmw {

//
//     | <- one unsigned integer input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one SharePointer(new arithmetic_gmw::Share) output
//

template <typename T>
class InputGate final : public motion::InputGate {
  using Base = motion::InputGate;

 public:
  InputGate(std::span<const T> input, std::size_t input_owner, Backend& backend);
  InputGate(std::vector<T>&& input, std::size_t input_owner, Backend& backend);

  void InitializationHelper();

  ~InputGate() final = default;

  void EvaluateSetup() final override;
  // non-interactive input sharing based on distributed in advance randomness seeds
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();
  arithmetic_gmw::WirePointer<T> GetOutputArithmeticWire();

 private:
  std::size_t arithmetic_sharing_id_;

  std::vector<T> input_;
};

constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max();

template <typename T>
class OutputGate final : public motion::OutputGate {
  using Base = motion::OutputGate;

 public:
  OutputGate(const arithmetic_gmw::WirePointer<T>& parent, std::size_t output_owner = kAll);
  OutputGate(const arithmetic_gmw::SharePointer<T>& parent, std::size_t output_owner);
  OutputGate(const motion::SharePointer& parent, std::size_t output_owner);

  ~OutputGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the  case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

 protected:
  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>> output_message_futures_;

  std::mutex m;
};

template <typename T>
class AdditionGate final : public motion::TwoGate {
 public:
  AdditionGate(const arithmetic_gmw::WirePointer<T>& a, const arithmetic_gmw::WirePointer<T>& b);
  ~AdditionGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  AdditionGate() = delete;
  AdditionGate(Gate&) = delete;
};

template <typename T>
class SubtractionGate final : public motion::TwoGate {
 public:
  SubtractionGate(const arithmetic_gmw::WirePointer<T>& a, const arithmetic_gmw::WirePointer<T>& b);
  ~SubtractionGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  SubtractionGate() = delete;
  SubtractionGate(Gate&) = delete;
};

template <typename T>
class MultiplicationGate final : public motion::TwoGate {
 public:
  MultiplicationGate(const arithmetic_gmw::WirePointer<T>& a,
                     const arithmetic_gmw::WirePointer<T>& b);
  ~MultiplicationGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  MultiplicationGate() = delete;
  MultiplicationGate(Gate&) = delete;

 private:
  arithmetic_gmw::WirePointer<T> d_, e_;
  std::shared_ptr<OutputGate<T>> d_output_, e_output_;

  std::size_t number_of_mts_, mt_offset_;
};

// Multiplication of an arithmetic share with a boolean bit.
// Based on [ST21]: https://iacr.org/2021/029.pdf
template <typename T>
class HybridMultiplicationGate final : public motion::TwoGate {
 public:
  HybridMultiplicationGate(const boolean_gmw::WirePointer& bit,
                           const arithmetic_gmw::WirePointer<T>& integer);

  ~HybridMultiplicationGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the
  // case we need it multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  HybridMultiplicationGate() = delete;

  HybridMultiplicationGate(Gate&) = delete;

 private:
  std::unique_ptr<BasicOtReceiver> ot_receiver_;
  std::unique_ptr<BasicOtSender> ot_sender_;
};

template <typename T>
class SquareGate final : public motion::OneGate {
 public:
  SquareGate(const arithmetic_gmw::WirePointer<T>& a);
  ~SquareGate() final = default;

  void EvaluateSetup() final override;
  void EvaluateOnline() final override;

  bool NeedsSetup() const override { return false; }

  // perhaps, we should return a copy of the pointer and not move it for the case we need it
  // multiple times
  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  SquareGate() = delete;
  SquareGate(Gate&) = delete;

 private:
  arithmetic_gmw::WirePointer<T> d_;
  std::shared_ptr<OutputGate<T>> d_output_;

  std::size_t number_of_sps_, sp_offset_;
};

template <typename T>
class GreaterThanGate final : public motion::TwoGate {
 public:
  GreaterThanGate(arithmetic_gmw::WirePointer<T>& a, arithmetic_gmw::WirePointer<T>& b,
                  std::size_t l_s);

  ~GreaterThanGate() override {}

  void RunSender1ooNOt(encrypto::motion::BitVector<> messages, std::size_t ot_index);

  BitVector<> RunReceiver1ooNOt(std::vector<std::uint8_t> selection_index, std::size_t ot_index);

  bool NeedsSetup() const override { return false; }

  void EvaluateSetup() override{};

  void EvaluateOnline() override;

  const boolean_gmw::SharePointer GetOutputAsGmwShare();

  GreaterThanGate() = delete;
  GreaterThanGate(Gate&) = delete;

 private:
  std::size_t number_of_parties_, number_of_simd_, my_id_, chunk_bit_length_;

  std::vector<std::unique_ptr<GKk13OtBitReceiver>> ot_1oon_receiver_;
  std::vector<std::unique_ptr<GKk13OtBitSender>> ot_1oon_sender_;
};

// added by Liang Zhao
// reconstruct the arithmetic share and convert the reconstructed arithmetic value into
// boolean values
template <typename T>
class ReconstructArithmeticGmwShareAndBitDecomposeGate final : public motion::OneGate {
 public:
  ReconstructArithmeticGmwShareAndBitDecomposeGate(const arithmetic_gmw::WirePointer<T>& parent,
                                                   std::size_t output_owner = kAll);

  ReconstructArithmeticGmwShareAndBitDecomposeGate(const arithmetic_gmw::SharePointer<T>& parent_a,
                                                   std::size_t output_owner = kAll);

  // ReconstructArithmeticGmwShareAndBitDecomposeGate(const motion::SharePointer& parent_a,
  // std::size_t output_owner =   kAll)
  // {
  //   assert(parent_a);

  //   const arithmetic_gmw::SharePointer<T>& airthmetic_share_parent_a =
  //       std::dynamic_pointer_cast<const arithmetic_gmw::Share<T>>(parent_a);
  //   ReconstructArithmeticGmwShareAndBitDecomposeGate(airthmetic_share_parent_a, output_owner);
  // }

  ~ReconstructArithmeticGmwShareAndBitDecomposeGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  // the output value is publicly known after EvaluateOnline()
  const motion::proto::boolean_gmw::SharePointer GetOutputAsBooleanGmwValue();

  // the output value is publicly known value after EvaluateOnline()
  const arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticGmwValue();

  ReconstructArithmeticGmwShareAndBitDecomposeGate() = delete;

  ReconstructArithmeticGmwShareAndBitDecomposeGate(Gate&) = delete;

 private:
  // // indicates whether this party obtains the output
  // bool is_my_output_ = false;

  // wires to store the bits of after bit-decomposition
  std::vector<motion::WirePointer> boolean_output_wires_;

  // wires to store the arithmetic value after reconstruction
  std::vector<arithmetic_gmw::WirePointer<T>> arithmetic_output_wires_;

  // std::int64_t output_owner_ = -1;
  // std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>> output_message_futures_;
  // std::mutex m;

  // arithmetic_gmw::WirePointer<T> parent_R_;
  // arithmetic_gmw::WirePointer<T> parent_M_;
  // std::size_t M_;

  std::shared_ptr<motion::proto::arithmetic_gmw::OutputGate<T>> arithmetic_reconstruct_gate_;

  // motion::proto::arithmetic_gmw::SharePointer<T> arithmetic_reconstruct_share;

  std::size_t num_of_simd_;
  std::size_t bit_size_;
};

// added by Liang Zhao
// generate random Boolean GMW shares: <r>^B = (<r_0>^B, ..., <r_l>^B), and arithmetic share <r>^A
// = B2A(<r>^B), similar to the edaBits (see paper - Improved Primitives for MPC over Mixed
// Arithmetic-Binary Circuits), but generated in the the semi-honest setting (basd on b2a_gate.h)
template <typename T>
class edaBitGate final : public Gate {
 public:
  edaBitGate(Backend& backend, std::size_t bit_size = sizeof(T) * 8, std::size_t num_of_simd = 1);

  ~edaBitGate() final = default;

  void EvaluateSetup() final override;

  void EvaluateOnline() final override;

  edaBitGate() = delete;

  edaBitGate(const Gate&) = delete;

  arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare();

  motion::proto::boolean_gmw::SharePointer GetOutputAsBooleanShare();

  std::vector<motion::SharePointer> GetOutputAsArithmeticShareOfEachBit();

 private:
  std::size_t num_of_sbs_;
  std::size_t sb_offset_;

  std::vector<arithmetic_gmw::WirePointer<T>> arithmetic_gmw_output_wire_r_vector_;
  std::vector<motion::WirePointer> boolean_gmw_output_wire_r_vector_;

  std::vector<std::vector<arithmetic_gmw::WirePointer<T>>>
      arithmetic_gmw_output_wire_vector_of_each_boolean_gmw_share_bit_;

  std::size_t num_of_simd_;
  std::size_t bit_size_;
  std::size_t total_bit_size_;
};

// // added by Liang Zhao
// // reconstruct the arithmetic gmw share (shared in field T) in a larger field U
// template <typename T, typename U>
// class OutputInLargerFieldGate final : public motion::OutputGate {
//   using Base = motion::OutputGate;

//  public:
//   OutputInLargerFieldGate(const arithmetic_gmw::WirePointer<T>& parent,
//                           std::size_t output_owner = kAll);

//   OutputInLargerFieldGate(const arithmetic_gmw::SharePointer<T>& parent, std::size_t
//   output_owner);

//   OutputInLargerFieldGate(const motion::SharePointer& parent, std::size_t output_owner);

//   ~OutputInLargerFieldGate() final = default;

//   void EvaluateSetup() final override;

//   void EvaluateOnline() final override;

//   arithmetic_gmw::SharePointer<U> GetOutputAsArithmeticShare();

//  protected:
//   // indicates whether this party obtains the output
//   bool is_my_output_ = false;

//   std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>> output_message_futures_;

//   std::mutex m;
// };

// // added by Liang Zhao
// // reconstruct the arithmetic share and use it as index to selection from the given boolean gmw
// // share vectors
// template <typename T>
// class ReconstructArithmeticGmwShareAndSelectFromShareVectorGate final : public motion::OneGate {
//  public:
//   ReconstructArithmeticGmwShareAndSelectFromShareVectorGate(
//       const arithmetic_gmw::WirePointer<T>& parent_index_head, std::size_t offset,
//       std::size_t num_of_select_elements,
//       const motion::SharePointer& boolean_gmw_share_vector_to_select,

//       std::size_t output_owner = kAll)
//       : OneGate(parent_index_head->GetBackend()) {
//     // std::cout << "ReconstructArithmeticGmwShareAndSelectFromShareVectorGate" << std::endl;
//     assert(parent_index_head);
//     assert(boolean_gmw_share_vector_to_select);

//     if (parent_index_head->GetProtocol() != MpcProtocol::kArithmeticGmw) {
//       auto sharing_type = to_string(parent_index_head->GetProtocol());

//       std::cout << "sharing_type: " << sharing_type << std::endl;
//       throw(std::runtime_error(
//           (fmt::format("Arithmetic ReconstructArithmeticGmwShareAndSelectFromShareVectorGate "
//                        "expects an arithmetic share, "
//                        "got a share of type {}",
//                        sharing_type))));
//     }

//     parent_ = {parent_index_head};

//     // std::cout << "boolean_gmw_share_vector_to_select->GetWires" << std::endl;
//     boolean_gmw_share_vector_to_select_ = boolean_gmw_share_vector_to_select->GetWires();
//     num_of_select_elements_ = num_of_select_elements;
//     offset_ = offset;

//     // ??? not support SIMD yet
//     num_of_simd_ = parent_[0]->GetNumberOfSimdValues();

//     requires_online_interaction_ = true;
//     gate_type_ = GateType::kInteractive;

//     // create the arithmetic output wires
//     // std::cout << "create the arithmetic output wires" << std::endl;
//     arithmetic_output_wires_.emplace_back(
//         std::make_shared<motion::proto::arithmetic_gmw::Wire<T>>(backend_, num_of_simd_));
//     arithmetic_output_wires_.at(0)->SetAsPubliclyKnownWire();
//     GetRegister().RegisterNextWire(arithmetic_output_wires_.at(0));

//     // create the boolean output wires to store the select boolean gmw wires
//     // std::cout << "create the boolean output wires to store the select boolean gmw
//     // wires"<<std::endl;
//     boolean_output_wires_.reserve(num_of_select_elements);
//     for (size_t i = 0; i < num_of_select_elements; i++) {
//       auto& w = boolean_output_wires_.emplace_back(std::static_pointer_cast<motion::Wire>(
//           std::make_shared<boolean_gmw::Wire>(backend_, num_of_simd_)));
//       GetRegister().RegisterNextWire(w);
//     }

//     // create the output gate to reconstruct the a
//     // std::cout<<"create the output gate to reconstruct the a"<<std::endl;
//     auto arithmetic_input_wire =
//         std::dynamic_pointer_cast<motion::proto::arithmetic_gmw::Wire<T>>(parent_.at(0));
//     arithmetic_reconstruct_gate_ =
//         std::make_shared<motion::proto::arithmetic_gmw::OutputGate<T>>(arithmetic_input_wire);
//     GetRegister().RegisterNextGate(arithmetic_reconstruct_gate_);

//     // register this gate
//     gate_id_ = GetRegister().NextGateId();

//     // register this gate with the parent_ wires
//     for (auto& wire : parent_) {
//       RegisterWaitingFor(wire->GetWireId());
//       wire->RegisterWaitingGate(gate_id_);
//     }

//     if constexpr (kDebug) {
//       auto gate_info = fmt::format("gate id {}", gate_id_);
//       GetLogger().LogDebug(
//           fmt::format("Allocate an ReconstructArithmeticGmwShareAndSelectFromShareVectorGate with
//           "
//                       "following properties: {}",
//                       gate_info));
//     }

//     // std::cout << "finish create ReconstructArithmeticGmwShareAndSelectFromShareVectorGate" <<
//     // std::endl;
//   }

//   //  ReconstructArithmeticGmwShareAndSelectFromShareVectorGate(
//   //      const arithmetic_gmw::SharePointer<T>& parent_a, std::size_t output_owner = kAll)
//   //      :
//   ReconstructArithmeticGmwShareAndSelectFromShareVectorGate(parent_a->GetArithmeticWire(),
//   //                                                                  output_owner) {
//   //    assert(parent_a);
//   //  }

//   // ReconstructArithmeticGmwShareAndSelectFromShareVectorGate(const motion::SharePointer&
//   parent_a,
//   // std::size_t output_owner =   kAll)
//   // {
//   //   assert(parent_a);

//   //   const arithmetic_gmw::SharePointer<T>& airthmetic_share_parent_a =
//   //       std::dynamic_pointer_cast<const arithmetic_gmw::Share<T>>(parent_a);
//   //   ReconstructArithmeticGmwShareAndSelectFromShareVectorGate(airthmetic_share_parent_a,
//   //   output_owner);
//   // }

//   ~ReconstructArithmeticGmwShareAndSelectFromShareVectorGate() final = default;

//   void EvaluateSetup() final override {
//     SetSetupIsReady();
//     GetRegister().IncrementEvaluatedGatesSetupCounter();
//   }

//   void EvaluateOnline() final override {
//     // std::cout << "ReconstructArithmeticGmwShareAndSelectFromShareVectorGate EvaluateOnline"
//     //           << std::endl;

//     // setup needs to be done first
//     WaitSetup();
//     assert(setup_is_ready_);

//     // wait for the parent wires to obtain their values
//     for (const auto& wire : parent_) {
//       wire->GetIsReadyCondition().Wait();
//     }
//     for (const auto& wire : boolean_gmw_share_vector_to_select_) {
//       wire->GetIsReadyCondition().Wait();
//     }

//     // wait for output gate to reconstruct
//     arithmetic_reconstruct_gate_->WaitOnline();
//     const auto reconstruct_arithmetic_gmw_share =
//         arithmetic_reconstruct_gate_->GetOutputAsArithmeticShare();
//     const auto& reconstruct_wire = reconstruct_arithmetic_gmw_share->GetWires().at(0);
//     const auto reconstruct_arithmetic_gmw_wire =
//         std::dynamic_pointer_cast<const arithmetic_gmw::Wire<T>>(reconstruct_wire);

//     // assign reconstructed value to arithmetic_gmw_output_wire
//     auto arithmetic_gmw_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(arithmetic_output_wires_.at(0));
//     assert(arithmetic_gmw_output_wire);
//     arithmetic_gmw_output_wire->GetMutableValues() =
//     reconstruct_arithmetic_gmw_wire->GetValues();

//     // reconstruct the index
//     T reconstruct_arithmetic_index_head = arithmetic_gmw_output_wire->GetValues()[0];
//     arithmetic_gmw_output_wire->SetAsPubliclyKnownWire();
//     arithmetic_gmw_output_wire->SetOnlineFinished();

//     for (auto i = 0ull; i < num_of_select_elements_; i++) {
//       auto boolean_gmw_output_wire =
//           std::dynamic_pointer_cast<boolean_gmw::Wire>(boolean_output_wires_.at(i));

//       auto boolean_gmw_wire_to_select = std::dynamic_pointer_cast<boolean_gmw::Wire>(
//           boolean_gmw_share_vector_to_select_[reconstruct_arithmetic_index_head * offset_ + i]);
//       boolean_gmw_output_wire->GetMutableValues() = boolean_gmw_wire_to_select->GetValues();
//       boolean_gmw_output_wire->SetOnlineFinished();
//     }

//     // std::cout << "SetOnlineIsReady: " << std::endl;
//     //    SetOnlineIsReady();
//     {
//       std::scoped_lock lock(online_is_ready_condition_.GetMutex());
//       online_is_ready_ = true;
//     }
//     online_is_ready_condition_.NotifyAll();

//     GetRegister().IncrementEvaluatedGatesOnlineCounter();
//     // std::cout << "Evaluate online finish: " << std::endl;
//   }

//   // the output value is publicly known after EvaluateOnline()
//   const motion::proto::boolean_gmw::SharePointer GetSelectBooleanGmwShareAsBooleanShare() {
//     auto boolean_output_share =
//         std::make_shared<motion::proto::boolean_gmw::Share>(boolean_output_wires_);
//     assert(boolean_output_share);
//     // auto output_share = std::static_pointer_cast<motion::Share>(boolean_output_share);
//     // assert(output_share);
//     return boolean_output_share;
//   }

//   // the output value is publicly known value after EvaluateOnline()
//   const arithmetic_gmw::SharePointer<T> GetReconstructArithmeticShare() {
//     auto arithmetic_output_wire =
//         std::dynamic_pointer_cast<arithmetic_gmw::Wire<T>>(arithmetic_output_wires_.at(0));
//     assert(arithmetic_output_wire);
//     auto arithmetic_output_share =
//         std::make_shared<arithmetic_gmw::Share<T>>(arithmetic_output_wire);
//     arithmetic_output_share->SetAsPubliclyKnownShare();
//     return arithmetic_output_share;
//   }

//   ReconstructArithmeticGmwShareAndSelectFromShareVectorGate() = delete;

//   ReconstructArithmeticGmwShareAndSelectFromShareVectorGate(Gate&) = delete;

//  private:
//   // // indicates whether this party obtains the output
//   // bool is_my_output_ = false;

//   // wires to store the bits of after selection
//   std::vector<motion::WirePointer> boolean_output_wires_;
//   std::size_t num_of_select_elements_;
//   std::size_t offset_;

//   // wires to store the arithmetic value after reconstruction
//   std::vector<arithmetic_gmw::WirePointer<T>> arithmetic_output_wires_;
//   std::vector<motion::WirePointer> boolean_gmw_share_vector_to_select_;

//   // std::int64_t output_owner_ = -1;
//   // std::vector<motion::ReusableFiberFuture<std::vector<std::uint8_t>>> output_message_futures_;
//   // std::mutex m;

//   // arithmetic_gmw::WirePointer<T> parent_R_;
//   // arithmetic_gmw::WirePointer<T> parent_M_;
//   // std::size_t M_;

//   std::shared_ptr<motion::proto::arithmetic_gmw::OutputGate<T>> arithmetic_reconstruct_gate_;

//   // motion::proto::arithmetic_gmw::SharePointer<T> arithmetic_reconstruct_share;

//   std::size_t num_of_simd_;
//   //  std::size_t bit_size_;
// };

}  // namespace encrypto::motion::proto::arithmetic_gmw
