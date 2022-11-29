// MIT License
//
// Copyright (c) 2019 Lennart Braun
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

#include <type_traits>
#include "base/register.h"
#include "multiplication_triple/sb_provider.h"
#include "protocols/arithmetic_gmw/arithmetic_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_gate.h"
#include "protocols/boolean_gmw/boolean_gmw_share.h"
#include "protocols/boolean_gmw/boolean_gmw_wire.h"
#include "protocols/gate.h"
#include "protocols/share.h"
#include "utility/constants.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"

namespace encrypto::motion {

// modified by Liang Zhao
template <typename T>
// template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class GmwToArithmeticGate final : public OneGate {
 public:
  GmwToArithmeticGate(const SharePointer& parent) : OneGate(parent->GetBackend()) {
    parent_ = parent->GetWires();
    const auto number_of_simd{parent->GetNumberOfSimdValues()};
    constexpr auto bit_size = sizeof(T) * 8;

    // check that we have enough input wires to represent an element of T
    assert(parent_.size() == bit_size);
    for ([[maybe_unused]] const auto& wire : parent_) {
      assert(wire->GetBitLength() == 1);
      assert(wire->GetNumberOfSimdValues() == number_of_simd);
      assert(wire->GetProtocol() == MpcProtocol::kBooleanGmw);
    }

    // create the output wire
    output_wires_.emplace_back(GetRegister().template EmplaceWire<proto::arithmetic_gmw::Wire<T>>(
        backend_, number_of_simd));

    std::vector<WirePointer> dummy_wires;

    // ! comment by Liang Zhao
    // here should be: dummy_wires.reserve(bit_size);
    dummy_wires.reserve(number_of_simd);
    for (std::size_t i = 0; i < bit_size; ++i) {
      dummy_wires.emplace_back(
          GetRegister().template EmplaceWire<proto::boolean_gmw::Wire>(backend_, number_of_simd));
    }
    ts_ = std::make_shared<proto::boolean_gmw::Share>(dummy_wires);
    // also create an output gate for the ts
    ts_output_ = GetRegister().template EmplaceGate<proto::boolean_gmw::OutputGate>(ts_);

    // register the required number of shared bits
    number_of_sbs_ = number_of_simd * bit_size;
    sb_offset_ = GetSbProvider().template RequestSbs<T>(number_of_sbs_);

    if constexpr (kDebug) {
      auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
      for (const auto& wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
      gate_info.append(fmt::format(" output wire: {}", output_wires_.at(0)->GetWireId()));
      GetLogger().LogDebug(fmt::format(
          "Created a Boolean GMW to Arithmetic GMW conversion gate with following properties: {}",
          gate_info));
    }
  }

  ~GmwToArithmeticGate() final = default;

  void EvaluateSetup() final {}

  void EvaluateOnline() final {
    // nothing to setup, no need to wait/check

    // wait for the parent wires to obtain their values
    for (const auto& wire : parent_) {
      wire->GetIsReadyCondition().Wait();
    }

    // wait for the SbProvider to finish
    auto& sb_provider = GetSbProvider();
    sb_provider.WaitFinished();

    const auto number_of_simd{parent_.at(0)->GetNumberOfSimdValues()};
    constexpr auto bit_size = sizeof(T) * 8;

    // mask the input bits with the shared bits
    // and assign the result to t
    const auto& sbs = sb_provider.template GetSbsAll<T>();
    auto& ts_wires = ts_->GetMutableWires();
    for (std::size_t wire_i = 0; wire_i < bit_size; ++wire_i) {
      auto t_wire = std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(ts_wires.at(wire_i));
      auto parent_gmw_wire =
          std::dynamic_pointer_cast<const proto::boolean_gmw::Wire>(parent_.at(wire_i));
      t_wire->GetMutableValues() = parent_gmw_wire->GetValues();
      // xor them with the shared bits
      for (std::size_t j = 0; j < number_of_simd; ++j) {
        auto b = t_wire->GetValues().Get(j);
        bool sb = sbs.at(sb_offset_ + wire_i * number_of_simd + j) & 1;
        t_wire->GetMutableValues().Set(b ^ sb, j);
      }
      t_wire->SetOnlineFinished();
    }

    // reconstruct t
    ts_output_->WaitOnline();
    const auto& ts_clear = ts_output_->GetOutputWires();
    std::vector<std::shared_ptr<proto::boolean_gmw::Wire>> ts_clear_b;
    ts_clear_b.reserve(ts_clear.size());
    std::transform(ts_clear.cbegin(), ts_clear.cend(), std::back_inserter(ts_clear_b),
                   [](auto& w) { return std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(w); });

    auto output = std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    output->GetMutableValues().resize(number_of_simd);
    for (std::size_t j = 0; j < number_of_simd; ++j) {
      T output_value = 0;
      for (std::size_t wire_i = 0; wire_i < bit_size; ++wire_i) {
        if (GetCommunicationLayer().GetMyId() == 0) {
          T t(ts_clear_b.at(wire_i)->GetValues().Get(j));         // the masked bit
          T r(sbs.at(sb_offset_ + wire_i * number_of_simd + j));  // the arithmetically shared bit
          output_value += T(t + r - 2 * t * r) << wire_i;
        } else {
          T t(ts_clear_b.at(wire_i)->GetValues().Get(j));         // the masked bit
          T r(sbs.at(sb_offset_ + wire_i * number_of_simd + j));  // the arithmetically shared bit
          output_value += T(r - 2 * t * r) << wire_i;
        }
      }
      output->GetMutableValues().at(j) = output_value;
    }

    GetLogger().LogDebug(fmt::format("Evaluated B2AGate with id#{}", gate_id_));
  }

  bool NeedsSetup() const override { return false; }

  const proto::arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare() const {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<proto::arithmetic_gmw::Share<T>>(arithmetic_wire);
    return result;
  }

  const SharePointer GetOutputAsShare() const {
    return std::dynamic_pointer_cast<Share>(GetOutputAsArithmeticShare());
  }

  GmwToArithmeticGate() = delete;

  GmwToArithmeticGate(const Gate&) = delete;

 private:
  std::size_t number_of_sbs_;
  std::size_t sb_offset_;
  proto::boolean_gmw::SharePointer ts_;
  std::shared_ptr<proto::boolean_gmw::OutputGate> ts_output_;
};

// TODO: implement
// added by Liang Zhao
// convert aribitary number of Boolean gmw wires to an arithmetic wire
// based on GmwToArithmeticGate
template <typename T>
class BooleanGmwBitsToArithmeticGmwGate final : public OneGate {
 public:
  BooleanGmwBitsToArithmeticGmwGate(const SharePointer& parent, std::size_t bit_size = 1)
      : OneGate(parent->GetBackend()) {
    // std::cout << "BooleanGmwBitsToArithmeticGmwGate" << std::endl;
    parent_ = parent->GetWires();
    const auto number_of_simd{parent->GetNumberOfSimdValues()};
    // constexpr auto bit_size_ = sizeof(T) * 8;
    bit_size_ = bit_size;

    // T t = 0;
    // std::size_t bit_size_of_type_T = GetBitSizeOfTypeT<T>(t) * 8;
    std::size_t bit_size_of_type_T = sizeof(T) * 8;

    // check that we have enough input wires to represent an element of T
    assert(bit_size_ >= 1 && bit_size_ <= bit_size_of_type_T);
    for ([[maybe_unused]] const auto& wire : parent_) {
      assert(wire->GetBitLength() == 1);
      assert(wire->GetNumberOfSimdValues() == number_of_simd);
      assert(wire->GetProtocol() == MpcProtocol::kBooleanGmw);
    }

    // create the output wire
    // output_wires_.emplace_back(
    //     std::make_shared<proto::arithmetic_gmw::Wire<T>>(backend_, number_of_simd));
    // GetRegister().RegisterNextWire(output_wires_.at(0));

    output_wires_.emplace_back(GetRegister().template EmplaceWire<proto::arithmetic_gmw::Wire<T>>(
        backend_, number_of_simd));

    std::vector<WirePointer> dummy_wires;
    dummy_wires.reserve(bit_size);
    for (std::size_t i = 0; i < bit_size_; ++i) {
      // auto w = std::make_shared<proto::boolean_gmw::Wire>(backend_, number_of_simd);
      // GetRegister().RegisterNextWire(w);
      dummy_wires.emplace_back(
          GetRegister().template EmplaceWire<proto::boolean_gmw::Wire>(backend_, number_of_simd));
    }
    ts_ = std::make_shared<proto::boolean_gmw::Share>(dummy_wires);
    // also create an output gate for the ts
    ts_output_ = GetRegister().template EmplaceGate<proto::boolean_gmw::OutputGate>(ts_);

    // GetRegister().RegisterNextGate(ts_output_);

    // register the required number of shared bits
    number_of_sbs_ = number_of_simd * bit_size_;
    sb_offset_ = GetSbProvider().template RequestSbs<T>(number_of_sbs_);

    // // register this gate
    // gate_id_ = GetRegister().NextGateId();

    // // register this gate with the parent wires
    // for (auto& wire : parent_) {
    //   RegisterWaitingFor(wire->GetWireId());
    //   wire->RegisterWaitingGate(gate_id_);
    // }

    if constexpr (kDebug) {
      auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
      for (const auto& wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
      gate_info.append(fmt::format(" output wire: {}", output_wires_.at(0)->GetWireId()));
      GetLogger().LogDebug(fmt::format(
          "Created a BooleanGmwBitsToArithmeticGmwGate with following properties: {}", gate_info));
    }
  }

  ~BooleanGmwBitsToArithmeticGmwGate() final = default;

  void EvaluateSetup() final {
    // SetSetupIsReady();
    // GetRegister().IncrementEvaluatedGatesSetupCounter();
  }

  void EvaluateOnline() final {
    // std::cout << "BooleanGmwBitsToArithmeticGmwGate evaluate online" << std::endl;
    // WaitSetup();
    // assert(setup_is_ready_);

    // wait for the parent wires to obtain their values
    for (const auto& wire : parent_) {
      wire->GetIsReadyCondition().Wait();
    }

    // wait for the SbProvider to finish
    auto& sb_provider = GetSbProvider();
    sb_provider.WaitFinished();

    const auto number_of_simd{parent_.at(0)->GetNumberOfSimdValues()};
    // constexpr auto bit_size_ = sizeof(T) * 8;

    // mask the input bits with the shared bits
    // and assign the result to t
    const auto& sbs = sb_provider.template GetSbsAll<T>();
    auto& ts_wires = ts_->GetMutableWires();
    for (std::size_t wire_i = 0; wire_i < bit_size_; ++wire_i) {
      auto t_wire = std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(ts_wires.at(wire_i));
      auto parent_gmw_wire =
          std::dynamic_pointer_cast<const proto::boolean_gmw::Wire>(parent_.at(wire_i));
      t_wire->GetMutableValues() = parent_gmw_wire->GetValues();

      // std::cout << "parent_gmw_wire->GetValues: " << parent_gmw_wire->GetValues() << std::endl;
      // xor them with the shared bits
      for (std::size_t j = 0; j < number_of_simd; ++j) {
        auto b = t_wire->GetValues().Get(j);
        bool sb = sbs.at(sb_offset_ + wire_i * number_of_simd + j) & 1;
        t_wire->GetMutableValues().Set(b ^ sb, j);
      }
      t_wire->SetOnlineFinished();
    }

    // reconstruct t
    ts_output_->WaitOnline();
    const auto& ts_clear = ts_output_->GetOutputWires();
    std::vector<std::shared_ptr<proto::boolean_gmw::Wire>> ts_clear_b;
    ts_clear_b.reserve(ts_clear.size());
    std::transform(ts_clear.cbegin(), ts_clear.cend(), std::back_inserter(ts_clear_b),
                   [](auto& w) { return std::dynamic_pointer_cast<proto::boolean_gmw::Wire>(w); });

    auto output = std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    output->GetMutableValues().resize(number_of_simd);
    for (std::size_t j = 0; j < number_of_simd; ++j) {
      T output_value = 0;
      for (std::size_t wire_i = 0; wire_i < bit_size_; ++wire_i) {
        if (GetCommunicationLayer().GetMyId() == 0) {
          T t(ts_clear_b.at(wire_i)->GetValues().Get(j));         // the masked bit
          T r(sbs.at(sb_offset_ + wire_i * number_of_simd + j));  // the arithmetically shared bit
          output_value += T(t + r - 2 * t * r) << wire_i;
        } else {
          T t(ts_clear_b.at(wire_i)->GetValues().Get(j));         // the masked bit
          T r(sbs.at(sb_offset_ + wire_i * number_of_simd + j));  // the arithmetically shared bit
          output_value += T(r - 2 * t * r) << wire_i;
        }
      }
      output->GetMutableValues().at(j) = output_value;
      // std::cout << "output_value: " << output->GetMutableValues().at(j) << std::endl;
    }

    GetLogger().LogDebug(
        fmt::format("Evaluated BooleanGmwBitsToArithmeticGmwGate with id#{}", gate_id_));
    // SetOnlineIsReady();
    // GetRegister().IncrementEvaluatedGatesOnlineCounter();
  }

  const proto::arithmetic_gmw::SharePointer<T> GetOutputAsArithmeticShare() const {
    auto arithmetic_wire =
        std::dynamic_pointer_cast<proto::arithmetic_gmw::Wire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<proto::arithmetic_gmw::Share<T>>(arithmetic_wire);
    return result;
  }

  const SharePointer GetOutputAsShare() const {
    return std::dynamic_pointer_cast<Share>(GetOutputAsArithmeticShare());
  }

  BooleanGmwBitsToArithmeticGmwGate() = delete;

  BooleanGmwBitsToArithmeticGmwGate(const Gate&) = delete;

 private:
  std::size_t number_of_sbs_;
  std::size_t sb_offset_;
  std::size_t bit_size_;
  proto::boolean_gmw::SharePointer ts_;
  std::shared_ptr<proto::boolean_gmw::OutputGate> ts_output_;
};

}  // namespace encrypto::motion
