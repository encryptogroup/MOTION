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

#include "boolean_gmw_gate.h"

#include "fmt/format.h"

#include "base/backend.h"
#include "base/register.h"
#include "communication/output_message.h"
#include "crypto/multiplication_triple/mt_provider.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "crypto/sharing_randomness_generator.h"
#include "share/boolean_gmw_share.h"
#include "utility/bit_vector.h"
#include "utility/helpers.h"
#include "wire/boolean_gmw_wire.h"

namespace MOTION::Gates::GMW {

GMWInputGate::GMWInputGate(const std::vector<ENCRYPTO::BitVector<>> &input, std::size_t party_id,
                           std::weak_ptr<Backend> backend)
    : input_(input) {
  input_owner_id_ = party_id;
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  backend_ = backend;
  InitializationHelper();
}

GMWInputGate::GMWInputGate(std::vector<ENCRYPTO::BitVector<>> &&input, std::size_t party_id,
                           std::weak_ptr<Backend> backend)
    : input_(std::move(input)) {
  input_owner_id_ = party_id;
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  backend_ = backend;
  InitializationHelper();
}

void GMWInputGate::InitializationHelper() {
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  if (static_cast<std::size_t>(input_owner_id_) >= ptr_backend->GetConfig()->GetNumOfParties()) {
    throw std::runtime_error(fmt::format("Invalid input owner: {} of {}", input_owner_id_,
                                         ptr_backend->GetConfig()->GetNumOfParties()));
  }

  gate_id_ = ptr_backend->GetRegister()->NextGateId();

  assert(input_.size() > 0u);           // assert >=1 wire
  assert(input_.at(0).GetSize() > 0u);  // assert >=1 SIMD bits
  // assert SIMD lengths of all wires are equal
  assert(ENCRYPTO::BitVector<>::EqualSizeDimensions(input_));

  boolean_sharing_id_ = ptr_backend->GetRegister()->NextBooleanGMWSharingId(input_.size() * bits_);

  if constexpr (MOTION_VERBOSE_DEBUG) {
    ptr_backend->GetLogger()->LogTrace(
        fmt::format("Created a BooleanGMWInputGate with global id {}", gate_id_));
  }

  output_wires_.reserve(input_.size());
  for (auto &v : input_) {
    auto wire = std::make_shared<Wires::GMWWire>(v, backend_);
    output_wires_.push_back(std::static_pointer_cast<MOTION::Wires::Wire>(wire));
  }

  for (auto &w : output_wires_) {
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {},", gate_id_);
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BooleanGMWInputGate with following properties: {}", gate_info));
  }
}

void GMWInputGate::EvaluateSetup() {
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  auto my_id = ptr_backend->GetConfig()->GetMyId();

  if (static_cast<std::size_t>(input_owner_id_) == my_id) {
    // we always generate our own seeds for the input sharing before we start evaluating
    // the circuit, hence, nothing to wait here for
  } else {
    auto &rand_generator = ptr_backend->GetConfig()
                               ->GetCommunicationContext(input_owner_id_)
                               ->GetTheirRandomnessGenerator();

    Helpers::WaitFor(*rand_generator->GetInitializedCondition());
  }
  SetSetupIsReady();
}

void GMWInputGate::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  auto my_id = ptr_backend->GetConfig()->GetMyId();

  std::vector<ENCRYPTO::BitVector<>> result(input_.size());
  auto sharing_id = boolean_sharing_id_;
  for (auto i = 0ull; i < result.size(); ++i) {
    if (static_cast<std::size_t>(input_owner_id_) == my_id) {
      result.at(i) = input_.at(i);
      auto log_string = std::string("");
      for (auto j = 0u; j < ptr_backend->GetConfig()->GetNumOfParties(); ++j) {
        if (j == my_id) {
          continue;
        }
        auto &rand_generator =
            ptr_backend->GetConfig()->GetCommunicationContext(j)->GetMyRandomnessGenerator();
        auto randomness = rand_generator->GetBits(sharing_id, bits_);

        if constexpr (MOTION_VERBOSE_DEBUG) {
          log_string.append(fmt::format("id#{}:{} ", j, randomness.AsString()));
        }

        result.at(i) ^= randomness;
      }
      sharing_id += bits_;

      if constexpr (MOTION_VERBOSE_DEBUG) {
        auto s = fmt::format(
            "My (id#{}) Boolean input sharing for gate#{}, my input: {}, my "
            "share: {}, expected shares of other parties: {}",
            input_owner_id_, gate_id_, input_.at(i).AsString(), result.at(i).AsString(),
            log_string);
        ptr_backend->GetLogger()->LogTrace(s);
      }
    } else {
      auto &rand_generator = ptr_backend->GetConfig()
                                 ->GetCommunicationContext(input_owner_id_)
                                 ->GetTheirRandomnessGenerator();
      auto randomness = rand_generator->GetBits(sharing_id, bits_);
      result.at(i) = randomness;

      if constexpr (MOTION_VERBOSE_DEBUG) {
        auto s = fmt::format(
            "Boolean input sharing (gate#{}) of Party's#{} input, got a "
            "share {} from the seed",
            gate_id_, input_owner_id_, result.at(i).AsString());
        ptr_backend->GetLogger()->LogTrace(s);
      }
      sharing_id += bits_;
    }
  }
  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto my_wire = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(i));
    assert(my_wire);
    auto buf = result.at(i);
    my_wire->GetMutableValues() = buf;
  }
  ptr_backend->GetRegister()->IncrementEvaluatedGatesCounter();
  if constexpr (MOTION_VERBOSE_DEBUG) {
    ptr_backend->GetLogger()->LogTrace(
        fmt::format("Evaluated Boolean GMWInputGate with id#{}", gate_id_));
  }
  SetOnlineIsReady();
}  // namespace MOTION::Gates::GMW

const Shares::GMWSharePtr GMWInputGate::GetOutputAsGMWShare() {
  auto result = std::make_shared<Shares::GMWShare>(output_wires_);
  assert(result);
  return result;
}

GMWOutputGate::GMWOutputGate(const Shares::SharePtr &parent, std::size_t output_owner) {
  if (parent->GetWires().at(0)->GetProtocol() != MPCProtocol::BooleanGMW) {
    auto sharing_type = Helpers::Print::ToString(parent->GetWires().at(0)->GetProtocol());
    throw std::runtime_error(
        fmt::format("Boolean output gate expects an Boolean share, "
                    "got a share of type {}",
                    sharing_type));
  }

  if (parent->GetWires().size() == 0) {
    throw std::runtime_error("Trying to construct an output gate with no wires");
  }

  parent_ = parent->GetWires();

  output_owner_ = output_owner;
  output_.resize(parent_.size());
  requires_online_interaction_ = true;
  gate_type_ = GateType::InteractiveGate;

  backend_ = parent_.at(0)->GetBackend();
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  if (output_owner >= ptr_backend->GetConfig()->GetNumOfParties() && output_owner != ALL) {
    throw std::runtime_error(fmt::format("Invalid output owner: {} of {}", output_owner,
                                         ptr_backend->GetConfig()->GetNumOfParties()));
  }

  gate_id_ = ptr_backend->GetRegister()->NextGateId();

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());  // mark this gate as waiting for @param wire
    wire->RegisterWaitingGate(gate_id_);    // register this gate in @param wire as waiting
  }

  const auto my_id = ptr_backend->GetConfig()->GetMyId();
  is_my_output_ = static_cast<std::size_t>(output_owner_) == my_id ||
                  static_cast<std::size_t>(output_owner_) == ALL;

  for (auto &bv : output_) {
    output_wires_.push_back(std::static_pointer_cast<MOTION::Wires::Wire>(
        std::make_shared<Wires::GMWWire>(bv, ptr_backend)));
  }

  for (auto &wire : output_wires_) {
    ptr_backend->GetRegister()->RegisterNextWire(wire);
  }

  auto gate_info =
      fmt::format("bitlength {}, gate id {}, owner {}", output_.size(), gate_id_, output_owner_);

  if constexpr (MOTION_DEBUG) {
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BooleanGMW OutputGate with following properties: {}", gate_info));
  }
}

void GMWOutputGate::EvaluateSetup() { SetSetupIsReady(); }

void GMWOutputGate::EvaluateOnline() {
  WaitSetup();
  std::vector<Wires::GMWWirePtr> wires;
  std::size_t i = 0, j = 0;
  for (auto &wire : parent_) {
    Helpers::WaitFor(*wire->GetIsReadyCondition());
    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(wire);
    assert(gmw_wire);
    wires.push_back(gmw_wire);
    output_.at(i) = wires.at(i)->GetValues();
    ++i;
  }
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  if (static_cast<std::size_t>(output_owner_) == ALL || !is_my_output_) {
    std::vector<std::size_t> output_owners;
    if (static_cast<std::size_t>(output_owner_) == ALL) {
      for (i = 0; i < GetConfig()->GetNumOfParties(); ++i) {
        if (i != GetConfig()->GetMyId()) {
          output_owners.emplace_back(i);
        }
      }
    } else {
      output_owners.emplace_back(output_owner_);
    }

    std::vector<std::vector<uint8_t>> payloads;
    const auto size = output_.at(0).GetData().size();
    for (i = 0; i < output_.size(); ++i) {
      const auto data_ptr = reinterpret_cast<const uint8_t *>(output_.at(i).GetData().data());
      payloads.emplace_back(data_ptr, data_ptr + size);
    }

    for (const auto id : output_owners) {
      ptr_backend->Send(id, MOTION::Communication::BuildOutputMessage(gate_id_, payloads));
    }
  }

  if (is_my_output_) {
    // wait until all conditions are fulfilled
    for (auto &wire : wires) {
      Helpers::WaitFor(*wire->GetIsReadyCondition());
    }
    const auto &config = ptr_backend->GetConfig();
    shared_outputs_.resize(ptr_backend->GetConfig()->GetNumOfParties());
    for (i = 0; i < config->GetNumOfParties(); ++i) {
      if (i == config->GetMyId()) {
        continue;
      }
      const auto &data_storage = config->GetCommunicationContext(i)->GetDataStorage();
      shared_outputs_.at(i).resize(output_.size());
      const auto message = data_storage->GetOutputMessage(gate_id_);
      assert(message);
      for (j = 0; j < message->wires()->size(); ++j) {
        auto payload = message->wires()->Get(j)->payload();
        auto ptr = reinterpret_cast<const std::byte *>(payload->data());
        std::vector<std::byte> byte_vector(ptr, ptr + payload->size());
        shared_outputs_.at(i).at(j) =
            ENCRYPTO::BitVector(byte_vector, parent_.at(0)->GetNumOfSIMDValues());
        assert(shared_outputs_.at(i).size() == output_.size());
      }
    }
    shared_outputs_.at(config->GetMyId()) = output_;
    output_ = ENCRYPTO::BitVector<>::XORBitVectors(shared_outputs_);
    if constexpr (MOTION_VERBOSE_DEBUG) {
      std::string shares{""};
      for (i = 0; i < config->GetNumOfParties(); ++i) {
        shares.append(fmt::format("id#{}:{} ", i, shared_outputs_.at(i).at(0).AsString()));
      }

      ptr_backend->GetLogger()->LogTrace(
          fmt::format("Received output shares: {} from other parties, "
                      "reconstructed result is {}",
                      shares, output_.at(0).AsString()));
    }
  }

  for (i = 0ull; i < output_wires_.size(); ++i) {
    auto wire = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(i));
    assert(wire);
    wire->GetMutableValues() = output_.at(i);
  }
  if constexpr (MOTION_DEBUG) {
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Evaluated Boolean GMWOutputGate with id#{}", gate_id_));
  }
  SetOnlineIsReady();
  ptr_backend->GetRegister()->IncrementEvaluatedGatesCounter();
}

const Shares::GMWSharePtr GMWOutputGate::GetOutputAsGMWShare() const {
  auto result = std::make_shared<Shares::GMWShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr GMWOutputGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsGMWShare());
  assert(result);
  return result;
}

GMWXORGate::GMWXORGate(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_a_.at(0)->GetBitLength() > 0);

  backend_ = parent_a_.at(0)->GetBackend();

  requires_online_interaction_ = false;
  gate_type_ = GateType::NonInteractiveGate;

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  gate_id_ = ptr_backend->GetRegister()->NextGateId();

  for (auto &wire : parent_a_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  for (auto &wire : parent_b_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  output_wires_.resize(parent_a_.size());
  const ENCRYPTO::BitVector tmp_bv(a->GetNumOfSIMDValues());
  for (auto &w : output_wires_) {
    w = std::static_pointer_cast<Wires::Wire>(std::make_shared<Wires::GMWWire>(tmp_bv, backend_));
  }

  for (auto &w : output_wires_) {
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BooleanGMW XOR gate with following properties: {}", gate_info));
  }
}

void GMWXORGate::EvaluateSetup() { SetSetupIsReady(); }

void GMWXORGate::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  for (auto &wire : parent_a_) {
    Helpers::WaitFor(*wire->GetIsReadyCondition());
  }

  for (auto &wire : parent_b_) {
    Helpers::WaitFor(*wire->GetIsReadyCondition());
  }

  for (auto i = 0ull; i < parent_a_.size(); ++i) {
    auto wire_a = std::dynamic_pointer_cast<Wires::GMWWire>(parent_a_.at(i));
    auto wire_b = std::dynamic_pointer_cast<Wires::GMWWire>(parent_b_.at(i));

    assert(wire_a);
    assert(wire_b);

    auto output = wire_a->GetValues() ^ wire_b->GetValues();

    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(i));
    assert(gmw_wire);
    gmw_wire->GetMutableValues() = std::move(output);
  }

  SetOnlineIsReady();

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  ptr_backend->GetRegister()->IncrementEvaluatedGatesCounter();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    ptr_backend->GetLogger()->LogTrace(
        fmt::format("Evaluated BooleanGMW XOR Gate with id#{}", gate_id_));
  }
}

const Shares::GMWSharePtr GMWXORGate::GetOutputAsGMWShare() const {
  auto result = std::make_shared<Shares::GMWShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr GMWXORGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsGMWShare());
  assert(result);
  return result;
}

GMWINVGate::GMWINVGate(const Shares::SharePtr &parent) {
  parent_ = parent->GetWires();

  assert(parent_.size() > 0);
  assert(parent_.at(0)->GetBitLength() > 0);

  backend_ = parent_.at(0)->GetBackend();

  requires_online_interaction_ = false;
  gate_type_ = GateType::NonInteractiveGate;

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  gate_id_ = ptr_backend->GetRegister()->NextGateId();

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  output_wires_.resize(parent_.size());
  const ENCRYPTO::BitVector tmp_bv(parent->GetNumOfSIMDValues());
  for (auto &w : output_wires_) {
    w = std::static_pointer_cast<Wires::Wire>(std::make_shared<Wires::GMWWire>(tmp_bv, backend_));
  }

  for (auto &w : output_wires_) {
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
    for (const auto &wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    gate_info.append(" output wires: ");
    for (const auto &wire : output_wires_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BooleanGMW INV gate with following properties: {}", gate_info));
  }
}

void GMWINVGate::EvaluateSetup() { SetSetupIsReady(); }

void GMWINVGate::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  for (auto i = 0ull; i < parent_.size(); ++i) {
    auto wire = std::dynamic_pointer_cast<Wires::GMWWire>(parent_.at(i));
    assert(wire);
    Helpers::WaitFor(*wire->GetIsReadyCondition());
    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(i));
    assert(gmw_wire);
    const bool inv = (wire->GetWireId() % GetConfig()->GetNumOfParties()) == GetConfig()->GetMyId();
    gmw_wire->GetMutableValues() = inv ? ~wire->GetValues() : wire->GetValues();
  }

  SetOnlineIsReady();

  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  ptr_backend->GetRegister()->IncrementEvaluatedGatesCounter();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    ptr_backend->GetLogger()->LogTrace(
        fmt::format("Evaluated BooleanGMW INV Gate with id#{}", gate_id_));
  }
}

const Shares::GMWSharePtr GMWINVGate::GetOutputAsGMWShare() const {
  auto result = std::make_shared<Shares::GMWShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr GMWINVGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsGMWShare());
  assert(result);
  return result;
}

GMWANDGate::GMWANDGate(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_a_.at(0)->GetBitLength() > 0);

  backend_ = parent_a_.at(0)->GetBackend();
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  requires_online_interaction_ = true;
  gate_type_ = GateType::InteractiveGate;

  const ENCRYPTO::BitVector<> dummy_bv(a->GetNumOfSIMDValues());
  std::vector<Wires::WirePtr> dummy_wires_e(parent_a_.size()), dummy_wires_d(parent_a_.size());

  for (auto &w : dummy_wires_d) {
    w = std::make_shared<Wires::GMWWire>(dummy_bv, backend_);
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  for (auto &w : dummy_wires_e) {
    w = std::make_shared<Wires::GMWWire>(dummy_bv, backend_);
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  d_ = std::make_shared<Shares::GMWShare>(dummy_wires_d);
  e_ = std::make_shared<Shares::GMWShare>(dummy_wires_e);

  d_out_ = std::make_shared<GMWOutputGate>(d_);
  e_out_ = std::make_shared<GMWOutputGate>(e_);

  GetRegister()->RegisterNextGate(d_out_);
  GetRegister()->RegisterNextGate(e_out_);

  gate_id_ = ptr_backend->GetRegister()->NextGateId();

  for (auto &wire : parent_a_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  for (auto &wire : parent_b_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  output_wires_.resize(parent_a_.size());
  for (auto &w : output_wires_) {
    w = std::make_shared<Wires::GMWWire>(dummy_bv, backend_);
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  auto backend = backend_.lock();
  assert(backend);

  auto &mt_provider = backend->GetMTProvider();
  mt_bitlen_ = parent_a_.size() * parent_a_.at(0)->GetNumOfSIMDValues();
  mt_offset_ = mt_provider->RequestBinaryMTs(mt_bitlen_);

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BooleanGMW AND gate with following properties: {}", gate_info));
  }
}

void GMWANDGate::EvaluateSetup() { SetSetupIsReady(); }

void GMWANDGate::EvaluateOnline() {
  WaitSetup();
  for (auto &wire : parent_a_) {
    Helpers::WaitFor(*wire->GetIsReadyCondition());
  }

  for (auto &wire : parent_b_) {
    Helpers::WaitFor(*wire->GetIsReadyCondition());
  }

  auto backend = backend_.lock();
  assert(backend);
  auto &mt_provider = backend->GetMTProvider();
  mt_provider->WaitFinished();
  const auto &mts = mt_provider->GetBinaryAll();

  auto &d_mut = d_->GetMutableWires();
  for (auto i = 0ull; i < d_mut.size(); ++i) {
    auto d = std::dynamic_pointer_cast<Wires::GMWWire>(d_mut.at(i));
    const auto x = std::dynamic_pointer_cast<Wires::GMWWire>(parent_a_.at(i));
    assert(d);
    assert(x);
    d->GetMutableValues() = mts.a.Subset(mt_offset_ + i * x->GetNumOfSIMDValues(),
                                         mt_offset_ + (i + 1) * x->GetNumOfSIMDValues());
    d->GetMutableValues() ^= x->GetValues();
    d->SetOnlineFinished();
  }

  auto &e_mut = e_->GetMutableWires();
  for (auto i = 0ull; i < e_mut.size(); ++i) {
    auto e = std::dynamic_pointer_cast<Wires::GMWWire>(e_mut.at(i));
    const auto y = std::dynamic_pointer_cast<Wires::GMWWire>(parent_b_.at(i));
    assert(e);
    assert(y);
    e->GetMutableValues() = mts.b.Subset(mt_offset_ + i * y->GetNumOfSIMDValues(),
                                         mt_offset_ + (i + 1) * y->GetNumOfSIMDValues());
    e->GetMutableValues() ^= y->GetValues();
    e->SetOnlineFinished();
  }

  d_out_->WaitOnline();
  e_out_->WaitOnline();

  const auto &d_clear = d_out_->GetOutputWires();
  const auto &e_clear = e_out_->GetOutputWires();

  for (auto &w : d_clear) {
    Helpers::WaitFor(*w->GetIsReadyCondition());
  }
  for (auto &w : e_clear) {
    Helpers::WaitFor(*w->GetIsReadyCondition());
  }

  for (auto i = 0ull; i < d_clear.size(); ++i) {
    const auto d_w = std::dynamic_pointer_cast<Wires::GMWWire>(d_clear.at(i));
    const auto x_i_w = std::dynamic_pointer_cast<Wires::GMWWire>(parent_a_.at(i));
    const auto e_w = std::dynamic_pointer_cast<Wires::GMWWire>(e_clear.at(i));
    const auto y_i_w = std::dynamic_pointer_cast<Wires::GMWWire>(parent_b_.at(i));

    assert(d_w);
    assert(x_i_w);
    assert(e_w);
    assert(y_i_w);

    auto out = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(i));
    assert(out);
    out->GetMutableValues() =
        mts.c.Subset(mt_offset_ + i * parent_a_.at(0)->GetNumOfSIMDValues(),
                     mt_offset_ + (i + 1) * parent_a_.at(0)->GetNumOfSIMDValues());

    const auto &d = d_w->GetValues();
    const auto &x_i = x_i_w->GetValues();
    const auto &e = e_w->GetValues();
    const auto &y_i = y_i_w->GetValues();

    if (GetConfig()->GetMyId() == (gate_id_ % GetConfig()->GetNumOfParties())) {
      out->GetMutableValues() ^= (d & y_i) ^ (e & x_i) ^ (e & d);
    } else {
      out->GetMutableValues() ^= (d & y_i) ^ (e & x_i);
    }
  }

  SetOnlineIsReady();
  backend->GetRegister()->IncrementEvaluatedGatesCounter();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    backend->GetLogger()->LogTrace(
        fmt::format("Evaluated BooleanGMW AND Gate with id#{}", gate_id_));
  }
}

const Shares::GMWSharePtr GMWANDGate::GetOutputAsGMWShare() const {
  auto result = std::make_shared<Shares::GMWShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr GMWANDGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsGMWShare());
  assert(result);
  return result;
}

GMWMUXGate::GMWMUXGate(const Shares::SharePtr &a, const Shares::SharePtr &b,
                       const Shares::SharePtr &c) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();
  parent_c_ = c->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_c_.size() == 1);
  assert(parent_a_.at(0)->GetBitLength() > 0);

  backend_ = parent_a_.at(0)->GetBackend();
  auto ptr_backend = backend_.lock();
  assert(ptr_backend);

  requires_online_interaction_ = true;
  gate_type_ = GateType::InteractiveGate;

  const ENCRYPTO::BitVector<> dummy_bv(a->GetNumOfSIMDValues());

  gate_id_ = ptr_backend->GetRegister()->NextGateId();

  for (auto &wire : parent_a_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  for (auto &wire : parent_b_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  for (auto &wire : parent_c_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  output_wires_.resize(parent_a_.size());
  for (auto &w : output_wires_) {
    w = std::make_shared<Wires::GMWWire>(dummy_bv, backend_);
    ptr_backend->GetRegister()->RegisterNextWire(w);
  }

  auto backend = backend_.lock();
  assert(backend);

  const auto n_parties = GetConfig()->GetNumOfParties();
  const auto n_simd = parent_a_.at(0)->GetNumOfSIMDValues();
  const auto n_bits = parent_a_.size();
  constexpr auto XCOT = ENCRYPTO::ObliviousTransfer::OTProtocol::XCOT;

  ot_sender_.resize(n_parties);
  ot_receiver_.resize(n_parties);

  for (auto i = 0ull; i < n_parties; ++i) {
    if (i == GetConfig()->GetMyId()) continue;
    ot_sender_.at(i) = backend->GetOTProvider(i)->RegisterSend(n_bits, n_simd, XCOT);
    ot_receiver_.at(i) = backend->GetOTProvider(i)->RegisterReceive(n_bits, n_simd, XCOT);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    ptr_backend->GetLogger()->LogDebug(
        fmt::format("Created a BooleanGMW AND gate with following properties: {}", gate_info));
  }
}

void GMWMUXGate::EvaluateSetup() { SetSetupIsReady(); }

void GMWMUXGate::EvaluateOnline() {
  WaitSetup();
  for (auto &wire : parent_a_) {
    Helpers::WaitFor(*wire->GetIsReadyCondition());
  }

  for (auto &wire : parent_b_) {
    Helpers::WaitFor(*wire->GetIsReadyCondition());
  }

  for (auto &wire : parent_c_) {
    Helpers::WaitFor(*wire->GetIsReadyCondition());
  }

  auto backend = backend_.lock();
  assert(backend);

  const auto n_bits = parent_a_.size();
  const auto n_simd = parent_a_.at(0)->GetNumOfSIMDValues();
  const auto n_parties = GetConfig()->GetNumOfParties();
  const auto my_id = GetConfig()->GetMyId();

  std::vector<ENCRYPTO::BitVector<>> xored_v;
  for (auto simd_i = 0ull; simd_i < n_simd; ++simd_i) {
    ENCRYPTO::BitVector<> a, b;
    for (auto bit_i = 0ull; bit_i < n_bits; ++bit_i) {
      auto wire_a = std::dynamic_pointer_cast<Wires::GMWWire>(parent_a_.at(bit_i));
      auto wire_b = std::dynamic_pointer_cast<Wires::GMWWire>(parent_b_.at(bit_i));
      assert(wire_a);
      assert(wire_b);
      a.Append(wire_a->GetValues()[simd_i]);
      b.Append(wire_b->GetValues()[simd_i]);
    }
    xored_v.emplace_back(a ^ b);
  }
  auto gmw_wire_selection_bits = std::dynamic_pointer_cast<Wires::GMWWire>(parent_c_.at(0));
  assert(gmw_wire_selection_bits);
  const auto &selection_bits = gmw_wire_selection_bits->GetValues();
  for (auto other_pid = 0ull; other_pid < n_parties; ++other_pid) {
    if (other_pid == my_id) continue;

    ot_receiver_.at(other_pid)->SetChoices(selection_bits);
    ot_receiver_.at(other_pid)->SendCorrections();

    ot_sender_.at(other_pid)->SetInputs(xored_v);
    ot_sender_.at(other_pid)->SendMessages();
  }

  for (auto simd_i = 0ull; simd_i < n_simd; ++simd_i)
    if (!selection_bits[simd_i]) xored_v.at(simd_i).Set(false);

  for (auto other_pid = 0ull; other_pid < n_parties; ++other_pid) {
    if (other_pid == my_id) continue;
    const auto &ot_r = ot_receiver_.at(other_pid)->GetOutputs();
    const auto &ot_s = ot_sender_.at(other_pid)->GetOutputs();
    for (auto simd_i = 0ull; simd_i < n_simd; ++simd_i) {
      xored_v.at(simd_i) ^= ot_r.at(simd_i);
      xored_v.at(simd_i) ^= ot_s.at(simd_i).Subset(0, n_bits);
    }
  }

  for (auto simd_i = 0ull; simd_i < n_simd; ++simd_i) {
    for (auto bit_i = 0ull; bit_i < n_bits; ++bit_i) {
      auto wire_out = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(bit_i));
      assert(wire_out);
      wire_out->GetMutableValues().Set(xored_v.at(simd_i)[bit_i], simd_i);
    }
  }

  for (auto bit_i = 0ull; bit_i < n_bits; ++bit_i) {
    auto wire_out = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(bit_i));
    assert(wire_out);
    auto &out = wire_out->GetMutableValues();

    auto wire_b = std::dynamic_pointer_cast<Wires::GMWWire>(parent_b_.at(bit_i));
    assert(wire_b);
    out ^= wire_b->GetValues();
  }

  SetOnlineIsReady();
  backend->GetRegister()->IncrementEvaluatedGatesCounter();

  if constexpr (MOTION_VERBOSE_DEBUG) {
    backend->GetLogger()->LogTrace(
        fmt::format("Evaluated BooleanGMW AND Gate with id#{}", gate_id_));
  }
}

const Shares::GMWSharePtr GMWMUXGate::GetOutputAsGMWShare() const {
  auto result = std::make_shared<Shares::GMWShare>(output_wires_);
  assert(result);
  return result;
}

const Shares::SharePtr GMWMUXGate::GetOutputAsShare() const {
  auto result = std::static_pointer_cast<Shares::Share>(GetOutputAsGMWShare());
  assert(result);
  return result;
}

}  // namespace MOTION::Gates::GMW