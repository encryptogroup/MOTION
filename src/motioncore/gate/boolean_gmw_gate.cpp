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

#include "boolean_gmw_gate.h"

#include <fmt/format.h>

#include "base/backend.h"
#include "base/register.h"
#include "communication/output_message.h"
#include "crypto/multiplication_triple/mt_provider.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "crypto/sharing_randomness_generator.h"
#include "utility/fiber_condition.h"
#include "utility/helpers.h"
#include "wire/boolean_gmw_wire.h"

namespace MOTION::Gates::GMW {

GMWInputGate::GMWInputGate(const std::vector<ENCRYPTO::BitVector<>> &input, std::size_t party_id,
                           Backend &backend)
    : InputGate(backend), input_(input) {
  input_owner_id_ = party_id;
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  InitializationHelper();
}

GMWInputGate::GMWInputGate(std::vector<ENCRYPTO::BitVector<>> &&input, std::size_t party_id,
                           Backend &backend)
    : InputGate(backend), input_(std::move(input)) {
  input_owner_id_ = party_id;
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  InitializationHelper();
}

void GMWInputGate::InitializationHelper() {
  auto &config = GetConfig();
  auto &_register = GetRegister();

  if (static_cast<std::size_t>(input_owner_id_) >= config.GetNumOfParties()) {
    throw std::runtime_error(
        fmt::format("Invalid input owner: {} of {}", input_owner_id_, config.GetNumOfParties()));
  }

  gate_id_ = _register.NextGateId();

  assert(input_.size() > 0u);           // assert >=1 wire
  assert(input_.at(0).GetSize() > 0u);  // assert >=1 SIMD bits
  // assert SIMD lengths of all wires are equal
  assert(ENCRYPTO::BitVector<>::EqualSizeDimensions(input_));

  boolean_sharing_id_ = _register.NextBooleanGMWSharingId(input_.size() * bits_);

  if constexpr (MOTION_VERBOSE_DEBUG) {
    GetLogger().LogTrace(fmt::format("Created a BooleanGMWInputGate with global id {}", gate_id_));
  }

  output_wires_.reserve(input_.size());
  for (auto &v : input_) {
    auto wire = std::make_shared<Wires::GMWWire>(v, backend_);
    output_wires_.push_back(std::static_pointer_cast<MOTION::Wires::Wire>(wire));
  }

  for (auto &w : output_wires_) {
    _register.RegisterNextWire(w);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {},", gate_id_);
    GetLogger().LogDebug(
        fmt::format("Created a BooleanGMWInputGate with following properties: {}", gate_info));
  }
}

void GMWInputGate::EvaluateSetup() {
  auto &config = GetConfig();

  if (static_cast<std::size_t>(input_owner_id_) == config.GetMyId()) {
    // we always generate our own seeds for the input sharing before we start evaluating
    // the circuit, hence, nothing to wait here for
  } else {
    auto &rand_generator =
        config.GetCommunicationContext(input_owner_id_)->GetTheirRandomnessGenerator();

    Helpers::WaitFor(*rand_generator->GetInitializedCondition());
  }
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGateSetupsCounter();
}

void GMWInputGate::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  auto &config = GetConfig();
  auto my_id = config.GetMyId();
  auto num_of_parties = config.GetNumOfParties();

  std::vector<ENCRYPTO::BitVector<>> result(input_.size());
  auto sharing_id = boolean_sharing_id_;
  for (auto i = 0ull; i < result.size(); ++i) {
    if (static_cast<std::size_t>(input_owner_id_) == my_id) {
      result.at(i) = input_.at(i);
      auto log_string = std::string("");
      for (auto j = 0u; j < num_of_parties; ++j) {
        if (j == my_id) {
          continue;
        }
        auto &rand_generator = config.GetCommunicationContext(j)->GetMyRandomnessGenerator();
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
        GetLogger().LogTrace(s);
      }
    } else {
      auto &rand_generator =
          config.GetCommunicationContext(input_owner_id_)->GetTheirRandomnessGenerator();
      auto randomness = rand_generator->GetBits(sharing_id, bits_);
      result.at(i) = randomness;

      if constexpr (MOTION_VERBOSE_DEBUG) {
        auto s = fmt::format(
            "Boolean input sharing (gate#{}) of Party's#{} input, got a "
            "share {} from the seed",
            gate_id_, input_owner_id_, result.at(i).AsString());
        GetLogger().LogTrace(s);
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
  if constexpr (MOTION_VERBOSE_DEBUG) {
    GetLogger().LogTrace(fmt::format("Evaluated Boolean GMWInputGate with id#{}", gate_id_));
  }
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesCounter();
}

const Shares::GMWSharePtr GMWInputGate::GetOutputAsGMWShare() {
  auto result = std::make_shared<Shares::GMWShare>(output_wires_);
  assert(result);
  return result;
}

GMWOutputGate::GMWOutputGate(const Shares::SharePtr &parent, std::size_t output_owner)
    : OutputGate(parent->GetBackend()) {
  if (parent->GetWires().size() == 0) {
    throw std::runtime_error("Trying to construct an output gate with no wires");
  }

  if (parent->GetWires().at(0)->GetProtocol() != MPCProtocol::BooleanGMW) {
    auto sharing_type = Helpers::Print::ToString(parent->GetWires().at(0)->GetProtocol());
    throw std::runtime_error(
        fmt::format("Boolean output gate expects an Boolean share, "
                    "got a share of type {}",
                    sharing_type));
  }

  parent_ = parent->GetWires();

  // values we need repeatedly
  auto &config = GetConfig();
  auto my_id = config.GetMyId();
  auto num_parties = config.GetNumOfParties();
  auto num_simd_values = parent_.at(0)->GetNumOfSIMDValues();
  auto num_wires = parent_.size();

  if (output_owner >= num_parties && output_owner != ALL) {
    throw std::runtime_error(
        fmt::format("Invalid output owner: {} of {}", output_owner, num_parties));
  }

  output_owner_ = output_owner;
  requires_online_interaction_ = true;
  gate_type_ = GateType::InteractiveGate;
  gate_id_ = GetRegister().NextGateId();
  is_my_output_ = static_cast<std::size_t>(output_owner_) == my_id ||
                  static_cast<std::size_t>(output_owner_) == ALL;

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());  // mark this gate as waiting for @param wire
    wire->RegisterWaitingGate(gate_id_);    // register this gate in @param wire as waiting
  }

  // create output wires
  output_wires_.reserve(num_wires);
  for (size_t i = 0; i < num_wires; ++i) {
    auto &w = output_wires_.emplace_back(std::static_pointer_cast<Wires::Wire>(
        std::make_shared<Wires::GMWWire>(num_simd_values, backend_)));
    GetRegister().RegisterNextWire(w);
  }

  // Tell the DataStorages that we want to receive OutputMessages from the
  // other parties.
  if (is_my_output_) {
    output_message_futures_.reserve(num_parties);
    for (size_t i = 0; i < num_parties; ++i) {
      if (i == my_id) {
        // We don't send a message to ourselves.
        // Just store an invalid future here.
        output_message_futures_.emplace_back();
        continue;
      }
      const auto &data_storage = config.GetCommunicationContext(i)->GetDataStorage();
      // Get a future that will eventually contain the received data.
      output_message_futures_.push_back(data_storage->RegisterForOutputMessage(gate_id_));
    }
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info =
        fmt::format("bitlength {}, gate id {}, owner {}", num_wires, gate_id_, output_owner_);

    GetLogger().LogDebug(
        fmt::format("Created a BooleanGMW OutputGate with following properties: {}", gate_info));
  }
}

void GMWOutputGate::EvaluateSetup() {
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGateSetupsCounter();
}

void GMWOutputGate::EvaluateOnline() {
  // setup needs to be done first
  WaitSetup();
  assert(setup_is_ready_);

  // data we need repeatedly
  const auto &config = GetConfig();
  const auto my_id = config.GetMyId();
  const auto num_parties = config.GetNumOfParties();
  const auto num_wires = parent_.size();

  std::vector<ENCRYPTO::BitVector<>> output;
  output.reserve(num_wires);
  for (std::size_t i = 0; i < num_wires; ++i) {
    // wait for parent wire to obtain a value
    auto gmw_wire = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_.at(i));
    assert(gmw_wire);
    gmw_wire->GetIsReadyCondition()->Wait();
    // initialize output with local share
    output.emplace_back(gmw_wire->GetValues());
  }

  // we need to send shares
  if (!is_my_output_ || output_owner_ == ALL) {
    // prepare payloads
    std::vector<std::vector<uint8_t>> payloads;
    auto byte_size = output.at(0).GetData().size();
    for (std::size_t i = 0; i < num_wires; ++i) {
      const auto data_ptr = reinterpret_cast<const uint8_t *>(output.at(i).GetData().data());
      payloads.emplace_back(data_ptr, data_ptr + byte_size);
    }
    // we need to send shares to one other party:
    if (!is_my_output_) {
      auto output_message = MOTION::Communication::BuildOutputMessage(gate_id_, payloads);
      GetRegister().Send(output_owner_, std::move(output_message));
    }
    // we need to send shares to all other parties:
    else if (output_owner_ == ALL) {
      for (std::size_t i = 0; i < num_parties; ++i) {
        if (i == my_id) continue;
        auto output_message = MOTION::Communication::BuildOutputMessage(gate_id_, payloads);
        GetRegister().Send(i, std::move(output_message));
      }
    }
  }

  // we receive shares from other parties
  if (is_my_output_) {
    // collect shares from all parties
    std::vector<std::vector<ENCRYPTO::BitVector<>>> shared_outputs(num_parties);
    for (std::size_t i = 0; i < num_parties; ++i) {
      if (i == my_id) {
        shared_outputs.at(i) = output;
        continue;
      }
      // we need space for a BitVector per wire
      shared_outputs.at(i).reserve(num_wires);

      // Retrieve the received messsage or wait until it has arrived.
      const auto output_message = output_message_futures_.at(i).get();
      auto message = Communication::GetMessage(output_message.data());
      auto output_message_ptr = Communication::GetOutputMessage(message->payload()->data());
      assert(output_message_ptr);
      assert(output_message_ptr->wires()->size() == num_wires);

      // handle each wire
      for (std::size_t j = 0; j < num_wires; ++j) {
        auto payload = output_message_ptr->wires()->Get(j)->payload();
        auto ptr = reinterpret_cast<const std::byte *>(payload->data());
        // load payload into a vector of bytes ...
        std::vector<std::byte> byte_vector(ptr, ptr + payload->size());
        // ... and construct a new BitVector
        shared_outputs.at(i).emplace_back(std::move(byte_vector),
                                          parent_.at(0)->GetNumOfSIMDValues());
      }
      assert(shared_outputs.at(i).size() == num_wires);
    }

    // reconstruct the shared value
    if constexpr (MOTION_VERBOSE_DEBUG) {
      // we need to copy since we have to keep shared_outputs for the debug output below
      output = ENCRYPTO::BitVector<>::XORBitVectors(shared_outputs);
    } else {
      // we can move
      output = ENCRYPTO::BitVector<>::XORBitVectors(std::move(shared_outputs));
    }

    // set the value of the output wires
    for (std::size_t i = 0; i < output_wires_.size(); ++i) {
      auto wire = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(i));
      assert(wire);
      wire->GetMutableValues() = output.at(i);
    }

    if constexpr (MOTION_VERBOSE_DEBUG) {
      std::string shares{""};
      for (std::size_t i = 0; i < config.GetNumOfParties(); ++i) {
        shares.append(fmt::format("id#{}:{} ", i, shared_outputs.at(i).at(0).AsString()));
      }

      GetLogger().LogTrace(
          fmt::format("Received output shares: {} from other parties, "
                      "reconstructed result is {}",
                      shares, output.at(0).AsString()));
    }
  }

  // we are done with this gate
  if constexpr (MOTION_DEBUG) {
    GetLogger().LogDebug(fmt::format("Evaluated Boolean GMWOutputGate with id#{}", gate_id_));
  }
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesCounter();
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

GMWXORGate::GMWXORGate(const Shares::SharePtr &a, const Shares::SharePtr &b)
    : TwoGate(a->GetBackend()) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_a_.at(0)->GetBitLength() > 0);

  requires_online_interaction_ = false;
  gate_type_ = GateType::NonInteractiveGate;

  auto &_register = GetRegister();
  gate_id_ = _register.NextGateId();

  for (auto &wire : parent_a_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  for (auto &wire : parent_b_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  auto num_wires = parent_a_.size();
  auto num_simd_values = a->GetNumOfSIMDValues();

  // create output wires
  output_wires_.reserve(num_wires);
  for (size_t i = 0; i < num_wires; ++i) {
    auto &w = output_wires_.emplace_back(std::static_pointer_cast<Wires::Wire>(
        std::make_shared<Wires::GMWWire>(num_simd_values, backend_)));
    GetRegister().RegisterNextWire(w);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created a BooleanGMW XOR gate with following properties: {}", gate_info));
  }
}

void GMWXORGate::EvaluateSetup() {
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGateSetupsCounter();
}

void GMWXORGate::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  for (auto &wire : parent_a_) {
    wire->GetIsReadyCondition()->Wait();
  }

  for (auto &wire : parent_b_) {
    wire->GetIsReadyCondition()->Wait();
  }

  for (auto i = 0ull; i < parent_a_.size(); ++i) {
    auto wire_a = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_a_.at(i));
    auto wire_b = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_b_.at(i));

    assert(wire_a);
    assert(wire_b);

    auto output = wire_a->GetValues() ^ wire_b->GetValues();

    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(i));
    assert(gmw_wire);
    gmw_wire->GetMutableValues() = std::move(output);
    assert(gmw_wire->GetValues().GetSize() == parent_a_.at(0)->GetNumOfSIMDValues());
  }

  // we are done with this gate
  if constexpr (MOTION_VERBOSE_DEBUG) {
    GetLogger().LogTrace(fmt::format("Evaluated BooleanGMW XOR Gate with id#{}", gate_id_));
  }
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesCounter();
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

GMWINVGate::GMWINVGate(const Shares::SharePtr &parent) : OneGate(parent->GetBackend()) {
  parent_ = parent->GetWires();

  assert(parent_.size() > 0);
  assert(parent_.at(0)->GetBitLength() > 0);

  requires_online_interaction_ = false;
  gate_type_ = GateType::NonInteractiveGate;

  auto &_register = GetRegister();
  gate_id_ = _register.NextGateId();

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  auto num_wires = parent_.size();
  auto num_simd_values = parent->GetNumOfSIMDValues();

  // create output wires
  output_wires_.reserve(num_wires);
  for (size_t i = 0; i < num_wires; ++i) {
    auto &w = output_wires_.emplace_back(std::static_pointer_cast<Wires::Wire>(
        std::make_shared<Wires::GMWWire>(num_simd_values, backend_)));
    GetRegister().RegisterNextWire(w);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parent wires: ", gate_id_);
    for (const auto &wire : parent_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    gate_info.append(" output wires: ");
    for (const auto &wire : output_wires_) gate_info.append(fmt::format("{} ", wire->GetWireId()));
    GetLogger().LogDebug(
        fmt::format("Created a BooleanGMW INV gate with following properties: {}", gate_info));
  }
}

void GMWINVGate::EvaluateSetup() {
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGateSetupsCounter();
}

void GMWINVGate::EvaluateOnline() {
  WaitSetup();
  assert(setup_is_ready_);

  for (auto i = 0ull; i < parent_.size(); ++i) {
    auto wire = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_.at(i));
    assert(wire);
    wire->GetIsReadyCondition()->Wait();
    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(i));
    assert(gmw_wire);
    const bool inv = (wire->GetWireId() % GetConfig().GetNumOfParties()) == GetConfig().GetMyId();
    gmw_wire->GetMutableValues() = inv ? ~wire->GetValues() : wire->GetValues();
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    GetLogger().LogTrace(fmt::format("Evaluated BooleanGMW INV Gate with id#{}", gate_id_));
  }
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesCounter();
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

GMWANDGate::GMWANDGate(const Shares::SharePtr &a, const Shares::SharePtr &b)
    : TwoGate(a->GetBackend()) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_a_.at(0)->GetBitLength() > 0);

  auto num_wires = parent_a_.size();
  auto num_simd_values = a->GetNumOfSIMDValues();

  requires_online_interaction_ = true;
  gate_type_ = GateType::InteractiveGate;

  std::vector<Wires::WirePtr> dummy_wires_e(num_wires), dummy_wires_d(num_wires);

  auto &_register = GetRegister();

  for (auto &w : dummy_wires_d) {
    w = std::make_shared<Wires::GMWWire>(num_simd_values, backend_);
    _register.RegisterNextWire(w);
  }

  for (auto &w : dummy_wires_e) {
    w = std::make_shared<Wires::GMWWire>(num_simd_values, backend_);
    _register.RegisterNextWire(w);
  }

  d_ = std::make_shared<Shares::GMWShare>(dummy_wires_d);
  e_ = std::make_shared<Shares::GMWShare>(dummy_wires_e);

  d_out_ = std::make_shared<GMWOutputGate>(d_);
  e_out_ = std::make_shared<GMWOutputGate>(e_);

  _register.RegisterNextGate(d_out_);
  _register.RegisterNextGate(e_out_);

  gate_id_ = _register.NextGateId();

  for (auto &wire : parent_a_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  for (auto &wire : parent_b_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  // create output wires
  output_wires_.reserve(num_wires);
  for (size_t i = 0; i < num_wires; ++i) {
    auto &w = output_wires_.emplace_back(std::static_pointer_cast<Wires::Wire>(
        std::make_shared<Wires::GMWWire>(num_simd_values, backend_)));
    GetRegister().RegisterNextWire(w);
  }

  auto &mt_provider = backend_.GetMTProvider();
  mt_bitlen_ = parent_a_.size() * parent_a_.at(0)->GetNumOfSIMDValues();
  mt_offset_ = mt_provider->RequestBinaryMTs(mt_bitlen_);

  if constexpr (MOTION_DEBUG) {
    auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                                 parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created a BooleanGMW AND gate with following properties: {}", gate_info));
  }
}

void GMWANDGate::EvaluateSetup() {
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGateSetupsCounter();
}

void GMWANDGate::EvaluateOnline() {
  WaitSetup();
  for (auto &wire : parent_a_) {
    wire->GetIsReadyCondition()->Wait();
  }

  for (auto &wire : parent_b_) {
    wire->GetIsReadyCondition()->Wait();
  }

  auto &mt_provider = GetMTProvider();
  mt_provider.WaitFinished();
  const auto &mts = mt_provider.GetBinaryAll();

  auto &d_mut = d_->GetMutableWires();
  for (auto i = 0ull; i < d_mut.size(); ++i) {
    auto d = std::dynamic_pointer_cast<Wires::GMWWire>(d_mut.at(i));
    const auto x = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_a_.at(i));
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
    const auto y = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_b_.at(i));
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

  for (auto &wire : d_clear) {
    wire->GetIsReadyCondition()->Wait();
  }
  for (auto &wire : e_clear) {
    wire->GetIsReadyCondition()->Wait();
  }

  for (auto i = 0ull; i < d_clear.size(); ++i) {
    const auto d_w = std::dynamic_pointer_cast<const Wires::GMWWire>(d_clear.at(i));
    const auto x_i_w = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_a_.at(i));
    const auto e_w = std::dynamic_pointer_cast<const Wires::GMWWire>(e_clear.at(i));
    const auto y_i_w = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_b_.at(i));

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

    if (GetConfig().GetMyId() == (gate_id_ % GetConfig().GetNumOfParties())) {
      out->GetMutableValues() ^= (d & y_i) ^ (e & x_i) ^ (e & d);
    } else {
      out->GetMutableValues() ^= (d & y_i) ^ (e & x_i);
    }
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    GetLogger().LogTrace(fmt::format("Evaluated BooleanGMW AND Gate with id#{}", gate_id_));
  }
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesCounter();
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
                       const Shares::SharePtr &c)
    : ThreeGate(a->GetBackend()) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();
  parent_c_ = c->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_a_.size() == parent_b_.size());
  assert(parent_c_.size() == 1);
  assert(parent_a_.at(0)->GetBitLength() > 0);

  requires_online_interaction_ = true;
  gate_type_ = GateType::InteractiveGate;

  auto &_register = GetRegister();
  gate_id_ = _register.NextGateId();

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

  auto num_wires = parent_a_.size();
  auto num_simd_values = a->GetNumOfSIMDValues();

  // create output wires
  // (EvaluateOnline expects the output wires already having buffers)
  output_wires_.reserve(num_wires);
  ENCRYPTO::BitVector dummy_bv(num_simd_values);
  for (size_t i = 0; i < num_wires; ++i) {
    auto &w = output_wires_.emplace_back(std::static_pointer_cast<Wires::Wire>(
        std::make_shared<Wires::GMWWire>(dummy_bv, backend_)));
    GetRegister().RegisterNextWire(w);
  }

  const auto num_parties = GetConfig().GetNumOfParties();
  const auto my_id = GetConfig().GetMyId();
  const auto num_bits = parent_a_.size();
  constexpr auto XCOT = ENCRYPTO::ObliviousTransfer::OTProtocol::XCOT;

  ot_sender_.resize(num_parties);
  ot_receiver_.resize(num_parties);

  for (std::size_t i = 0; i < num_parties; ++i) {
    if (i == my_id) continue;
    ot_sender_.at(i) = GetOTProvider(i).RegisterSend(num_bits, num_simd_values, XCOT);
    ot_receiver_.at(i) = GetOTProvider(i).RegisterReceive(num_bits, num_simd_values, XCOT);
  }

  if constexpr (MOTION_DEBUG) {
    auto gate_info =
        fmt::format("gate id {}, parents: {}, {}, {}", gate_id_, parent_a_.at(0)->GetWireId(),
                    parent_b_.at(0)->GetWireId(), parent_c_.at(0)->GetWireId());
    GetLogger().LogDebug(
        fmt::format("Created a BooleanGMW MUX gate with following properties: {}", gate_info));
  }
}

void GMWMUXGate::EvaluateSetup() {
  SetSetupIsReady();
  GetRegister().IncrementEvaluatedGateSetupsCounter();
}

void GMWMUXGate::EvaluateOnline() {
  WaitSetup();
  for (auto &wire : parent_a_) {
    wire->GetIsReadyCondition()->Wait();
  }

  for (auto &wire : parent_b_) {
    wire->GetIsReadyCondition()->Wait();
  }

  for (auto &wire : parent_c_) {
    wire->GetIsReadyCondition()->Wait();
  }

  const auto num_bits = parent_a_.size();
  const auto num_simd = parent_a_.at(0)->GetNumOfSIMDValues();
  const auto num_parties = GetConfig().GetNumOfParties();
  const auto my_id = GetConfig().GetMyId();

  std::vector<ENCRYPTO::BitVector<>> xored_v;
  xored_v.reserve(num_simd);
  for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
    ENCRYPTO::BitVector<> a, b;
    a.Reserve(MOTION::Helpers::Convert::BitsToBytes(num_bits));
    b.Reserve(MOTION::Helpers::Convert::BitsToBytes(num_bits));
    for (auto bit_i = 0ull; bit_i < num_bits; ++bit_i) {
      auto wire_a = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_a_.at(bit_i));
      auto wire_b = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_b_.at(bit_i));
      assert(wire_a);
      assert(wire_b);
      a.Append(wire_a->GetValues()[simd_i]);
      b.Append(wire_b->GetValues()[simd_i]);
    }
    xored_v.emplace_back(a ^ b);
  }
  auto gmw_wire_selection_bits = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_c_.at(0));
  assert(gmw_wire_selection_bits);
  const auto &selection_bits = gmw_wire_selection_bits->GetValues();
  for (auto other_pid = 0ull; other_pid < num_parties; ++other_pid) {
    if (other_pid == my_id) continue;

    ot_receiver_.at(other_pid)->SetChoices(selection_bits);
    ot_receiver_.at(other_pid)->SendCorrections();

    ot_sender_.at(other_pid)->SetInputs(xored_v);
    ot_sender_.at(other_pid)->SendMessages();
  }

  for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i)
    if (!selection_bits[simd_i]) xored_v.at(simd_i).Set(false);

  for (auto other_pid = 0ull; other_pid < num_parties; ++other_pid) {
    if (other_pid == my_id) continue;
    const auto &ot_r = ot_receiver_.at(other_pid)->GetOutputs();
    const auto &ot_s = ot_sender_.at(other_pid)->GetOutputs();
    for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
      xored_v.at(simd_i) ^= ot_r.at(simd_i);
      ENCRYPTO::BitSpan bs(const_cast<std::byte*>(ot_s.at(simd_i).GetData().data()), num_bits);
      xored_v.at(simd_i) ^= bs;
    }
  }

  for (auto simd_i = 0ull; simd_i < num_simd; ++simd_i) {
    for (auto bit_i = 0ull; bit_i < num_bits; ++bit_i) {
      auto wire_out = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(bit_i));
      assert(wire_out);
      wire_out->GetMutableValues().Set(xored_v.at(simd_i)[bit_i], simd_i);
    }
  }

  for (auto bit_i = 0ull; bit_i < num_bits; ++bit_i) {
    auto wire_out = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(bit_i));
    assert(wire_out);
    auto &out = wire_out->GetMutableValues();

    auto wire_b = std::dynamic_pointer_cast<const Wires::GMWWire>(parent_b_.at(bit_i));
    assert(wire_b);
    out ^= wire_b->GetValues();
  }

  if constexpr (MOTION_VERBOSE_DEBUG) {
    GetLogger().LogTrace(fmt::format("Evaluated BooleanGMW AND Gate with id#{}", gate_id_));
  }
  SetOnlineIsReady();
  GetRegister().IncrementEvaluatedGatesCounter();
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
