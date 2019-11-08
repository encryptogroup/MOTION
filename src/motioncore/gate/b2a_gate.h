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
#include "base/configuration.h"
#include "base/register.h"
#include "boolean_gmw_gate.h"
#include "crypto/multiplication_triple/sb_provider.h"
#include "gate.h"
#include "share/arithmetic_gmw_share.h"
#include "share/boolean_gmw_share.h"
#include "share/share.h"
#include "utility/constants.h"
#include "utility/fiber_condition.h"
#include "utility/logger.h"
#include "wire/boolean_gmw_wire.h"

namespace MOTION {
namespace Gates {
namespace Conversions {

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class GMWToArithmeticGate final : public Gates::Interfaces::OneGate {
 public:
  GMWToArithmeticGate(const Shares::SharePtr& parent) {
    parent_ = parent->GetWires();
    const auto num_simd{parent->GetNumOfSIMDValues()};
    constexpr auto bit_size = sizeof(T) * 8;

    // check that we have enough input wires to represent an element of T
    assert(parent_.size() == bit_size);
    for ([[maybe_unused]] const auto& wire : parent_) {
      assert(wire->GetBitLength() == 1);
      assert(wire->GetNumOfSIMDValues() == num_simd);
      assert(wire->GetProtocol() == MPCProtocol::BooleanGMW);
    }

    backend_ = parent_.at(0)->GetBackend();

    requires_online_interaction_ = true;
    gate_type_ = GateType::InteractiveGate;

    // create the output wire
    const std::vector<T> dummy_v(num_simd);
    output_wires_.emplace_back(std::make_shared<Wires::ArithmeticWire<T>>(dummy_v, backend_));
    GetRegister()->RegisterNextWire(output_wires_.at(0));

    // create shares for the intermediate values t
    // - we need some dummy values to create wires ...
    const ENCRYPTO::BitVector<> dummy_bv(num_simd);
    // - then we need dummy (?) wires to create shares ...
    std::vector<Wires::WirePtr> dummy_ws;
    dummy_ws.reserve(num_simd);
    for (std::size_t i = 0; i < bit_size; ++i) {
      auto w = std::make_shared<Wires::GMWWire>(dummy_bv, backend_);
      GetRegister()->RegisterNextWire(w);
      dummy_ws.emplace_back(std::move(w));
    }
    ts_ = std::make_shared<Shares::GMWShare>(dummy_ws);
    // also create an output gate for the ts
    ts_out_ = std::make_shared<Gates::GMW::GMWOutputGate>(ts_);
    GetRegister()->RegisterNextGate(ts_out_);

    // register the required number of shared bits
    num_sbs_ = num_simd * bit_size;
    sb_offset_ = GetSBProvider()->template RequestSBs<T>(num_sbs_);

    // register this gate
    gate_id_ = GetRegister()->NextGateId();

    // register this gate with the parent wires
    for (auto& wire : parent_) {
      RegisterWaitingFor(wire->GetWireId());
      wire->RegisterWaitingGate(gate_id_);
    }

    if constexpr (MOTION_DEBUG) {
      auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
      for (const auto& wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
      gate_info.append(fmt::format(" output wire: {}", output_wires_.at(0)->GetWireId()));
      GetLogger()->LogDebug(fmt::format(
          "Created a Boolean GMW to Arithmetic GMW conversion gate with following properties: {}",
          gate_info));
    }
  }

  ~GMWToArithmeticGate() final = default;

  void EvaluateSetup() final {
    SetSetupIsReady();
    GetRegister()->IncrementEvaluatedGateSetupsCounter();
  }

  void EvaluateOnline() final {
    WaitSetup();
    assert(setup_is_ready_);

    // wait for the parent wires to obtain their values
    for (const auto& wire : parent_) {
      wire->GetIsReadyCondition()->Wait();
    }

    // wait for the SBProvider to finish
    auto sb_provider = GetSBProvider();
    sb_provider->WaitFinished();

    const auto num_simd{parent_.at(0)->GetNumOfSIMDValues()};
    constexpr auto bit_size = sizeof(T) * 8;

    // mask the input bits with the shared bits
    // and assign the result to t
    const auto& sbs = sb_provider->template GetSBsAll<T>();
    auto& ts_wires = ts_->GetMutableWires();
    for (std::size_t wire_i = 0; wire_i < bit_size; ++wire_i) {
      auto t_wire = std::dynamic_pointer_cast<Wires::GMWWire>(ts_wires.at(wire_i));
      auto parent_gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(parent_.at(wire_i));
      t_wire->GetMutableValues() = parent_gmw_wire->GetValues();
      // xor them with the shared bits
      for (std::size_t j = 0; j < num_simd; ++j) {
        auto b = t_wire->GetValues().Get(j);
        bool sb = sbs.at(sb_offset_ + wire_i * num_simd + j) & 1;
        t_wire->GetMutableValues().Set(b ^ sb, j);
      }
      t_wire->SetOnlineFinished();
    }

    // reconstruct t
    ts_out_->WaitOnline();
    const auto& ts_clear = ts_out_->GetOutputWires();
    std::vector<std::shared_ptr<Wires::GMWWire>> ts_clear_b;
    ts_clear_b.reserve(ts_clear.size());
    std::transform(ts_clear.cbegin(), ts_clear.cend(), std::back_inserter(ts_clear_b),
                   [](auto& w) { return std::dynamic_pointer_cast<Wires::GMWWire>(w); });

    auto out = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(output_wires_.at(0));
    for (std::size_t j = 0; j < num_simd; ++j) {
      auto& out_val = out->GetMutableValues().at(j);
      out_val = 0;
      for (std::size_t wire_i = 0; wire_i < bit_size; ++wire_i) {
        if (GetConfig()->GetMyId() == 0) {
          T t(ts_clear_b.at(wire_i)->GetValues().Get(j));   // the masked bit
          T r(sbs.at(sb_offset_ + wire_i * num_simd + j));  // the arithmetically shared bit
          out_val += T(t + r - 2 * t * r) << wire_i;
        } else {
          T t(ts_clear_b.at(wire_i)->GetValues().Get(j));   // the masked bit
          T r(sbs.at(sb_offset_ + wire_i * num_simd + j));  // the arithmetically shared bit
          out_val += T(r - 2 * t * r) << wire_i;
        }
      }
    }

    GetLogger()->LogDebug(fmt::format("Evaluated B2AGate with id#{}", gate_id_));
    SetOnlineIsReady();
    GetRegister()->IncrementEvaluatedGatesCounter();
  }

  const Shares::ArithmeticSharePtr<T> GetOutputAsArithmeticShare() const {
    auto arithmetic_wire = std::dynamic_pointer_cast<Wires::ArithmeticWire<T>>(output_wires_.at(0));
    assert(arithmetic_wire);
    auto result = std::make_shared<Shares::ArithmeticShare<T>>(arithmetic_wire);
    return result;
  }

  const Shares::SharePtr GetOutputAsShare() const {
    return std::dynamic_pointer_cast<Shares::Share>(GetOutputAsArithmeticShare());
  }

  GMWToArithmeticGate() = delete;

  GMWToArithmeticGate(const Gate&) = delete;

 private:
  std::size_t num_sbs_;
  std::size_t sb_offset_;
  Shares::GMWSharePtr ts_;
  std::shared_ptr<Gates::GMW::GMWOutputGate> ts_out_;
};

}  // namespace Conversions
}  // namespace Gates
}  // namespace MOTION
