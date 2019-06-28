#include "boolean_gmw_gate.h"

#include "fmt/format.h"

#include "base/configuration.h"
#include "communication/context.h"
#include "communication/output_message.h"
#include "crypto/aes_randomness_generator.h"
#include "utility/data_storage.h"
#include "utility/helpers.h"
#include "utility/logger.h"
#include "wire/boolean_gmw_wire.h"

namespace ABYN::Gates::GMW {

GMWInputGate::GMWInputGate(const std::vector<ENCRYPTO::BitVector> &input, std::size_t party_id,
                           std::weak_ptr<Register> reg)
    : input_(input), input_owner_id_(party_id) {
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  register_ = reg;
  InitializationHelper();
}

GMWInputGate::GMWInputGate(std::vector<ENCRYPTO::BitVector> &&input, std::size_t party_id,
                           std::weak_ptr<Register> reg)
    : input_(std::move(input)), input_owner_id_(party_id) {
  bits_ = input_.size() == 0 ? 0 : input_.at(0).GetSize();
  register_ = reg;
  InitializationHelper();
}

void GMWInputGate::InitializationHelper() {
  auto shared_ptr_reg = register_.lock();
  assert(shared_ptr_reg);

  if (input_owner_id_ >= shared_ptr_reg->GetConfig()->GetNumOfParties()) {
    throw std::runtime_error(fmt::format("Invalid input owner: {} of {}", input_owner_id_,
                                         shared_ptr_reg->GetConfig()->GetNumOfParties()));
  }

  gate_id_ = shared_ptr_reg->NextGateId();

  assert(input_.size() > 0u);           // assert >=1 wire
  assert(input_.at(0).GetSize() > 0u);  // assert >=1 SIMD bits
  // assert SIMD lengths of all wires are equal
  assert(ABYN::Helpers::Compare::Dimensions(input_));

  boolean_sharing_id_ = shared_ptr_reg->NextBooleanGMWSharingId(input_.size() * bits_);
  shared_ptr_reg->GetLogger()->LogTrace(
      fmt::format("Created a BooleanGMWInputGate with global id {}", gate_id_));

  output_wires_.reserve(input_.size());
  for (auto &v : input_) {
    auto wire = std::make_shared<Wires::GMWWire>(v, shared_ptr_reg, bits_);
    output_wires_.push_back(std::static_pointer_cast<ABYN::Wires::Wire>(wire));
  }

  for (auto &w : output_wires_) {
    shared_ptr_reg->RegisterNextWire(w);
  }

  auto gate_info = fmt::format("gate id {},", gate_id_);
  shared_ptr_reg->GetLogger()->LogDebug(
      fmt::format("Created a BooleanGMWInputGate with following properties: {}", gate_info));
}

void GMWInputGate::EvaluateSetup() {
  auto shared_ptr_reg = register_.lock();
  assert(shared_ptr_reg);

  auto my_id = shared_ptr_reg->GetConfig()->GetMyId();

  if (input_owner_id_ == my_id) {
    // we always generate our own seeds for the input sharing before we start evaluating
    // the circuit, hence, nothing to wait here for
  } else {
    auto &rand_generator = shared_ptr_reg->GetConfig()
                               ->GetCommunicationContext(input_owner_id_)
                               ->GetTheirRandomnessGenerator();

    while (!rand_generator->IsInitialized()) {
      rand_generator->GetInitializedCondition()->WaitFor(std::chrono::milliseconds(1));
    }
  }
  SetSetupIsReady();
}

void GMWInputGate::EvaluateOnline() {
  assert(setup_is_ready_);

  auto shared_ptr_reg = register_.lock();
  assert(shared_ptr_reg);

  auto my_id = shared_ptr_reg->GetConfig()->GetMyId();

  std::vector<ENCRYPTO::BitVector> result(input_.size());
  auto sharing_id = boolean_sharing_id_;
  for (auto i = 0ull; i < result.size(); ++i) {
    if (input_owner_id_ == my_id) {
      result.at(i) = input_.at(i);
      auto log_string = std::string("");
      for (auto j = 0u; j < shared_ptr_reg->GetConfig()->GetNumOfParties(); ++j) {
        if (j == my_id) {
          continue;
        }
        auto &rand_generator =
            shared_ptr_reg->GetConfig()->GetCommunicationContext(j)->GetMyRandomnessGenerator();
        auto randomness = std::move(rand_generator->GetBits(sharing_id, bits_));
        log_string.append(fmt::format("id#{}:{} ", j, randomness.AsString()));

        result.at(i) ^= randomness;
      }
      sharing_id += bits_;
      auto s = fmt::format(
          "My (id#{}) Boolean input sharing for gate#{}, my input: {}, my "
          "share: {}, expected shares of other parties: {}",
          input_owner_id_, gate_id_, input_.at(i).AsString(), result.at(i).AsString(), log_string);
      shared_ptr_reg->GetLogger()->LogTrace(s);
    } else {
      auto &rand_generator = shared_ptr_reg->GetConfig()
                                 ->GetCommunicationContext(input_owner_id_)
                                 ->GetTheirRandomnessGenerator();
      auto randomness = std::move(rand_generator->GetBits(sharing_id, bits_));
      result.at(i) = randomness;

      auto s = fmt::format(
          "Boolean input sharing (gate#{}) of Party's#{} input, got a "
          "share {} from the seed",
          gate_id_, input_owner_id_, result.at(i).AsString());
      shared_ptr_reg->GetLogger()->LogTrace(s);
      sharing_id += bits_;
    }
  }
  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    auto my_wire = std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_wires_.at(i));
    assert(my_wire);
    auto buf = result.at(i);
    my_wire->GetMutableValuesOnWire() = buf;
  }
  shared_ptr_reg->IncrementEvaluatedGatesCounter();
  shared_ptr_reg->GetLogger()->LogTrace(
      fmt::format("Evaluated Boolean GMWInputGate with id#{}", gate_id_));
  SetOnlineIsReady();
};

const Shares::GMWSharePtr GMWInputGate::GetOutputAsGMWShare() {
  auto result = std::make_shared<Shares::GMWShare>(output_wires_);
  assert(result);
  return result;
}

GMWOutputGate::GMWOutputGate(const std::vector<Wires::WirePtr> &parent, std::size_t output_owner) {
  if (parent.at(0)->GetProtocol() != Protocol::BooleanGMW) {
    auto sharing_type = Helpers::Print::ToString(parent.at(0)->GetProtocol());
    throw std::runtime_error(
        fmt::format("Boolean output gate expects an Boolean share, "
                    "got a share of type {}",
                    sharing_type));
  }

  if (parent.size() == 0) {
    throw std::runtime_error("Trying to construct an output gate with no wires");
  }

  parent_ = parent;

  output_owner_ = output_owner;
  output_.resize(parent.size());
  requires_online_interaction_ = true;
  gate_type_ = GateType::InteractiveGate;

  register_ = parent.at(0)->GetRegister();
  auto shared_ptr_reg = register_.lock();
  assert(shared_ptr_reg);

  if (output_owner >= shared_ptr_reg->GetConfig()->GetNumOfParties()) {
    throw std::runtime_error(fmt::format("Invalid output owner: {} of {}", output_owner,
                                         shared_ptr_reg->GetConfig()->GetNumOfParties()));
  }

  gate_id_ = shared_ptr_reg->NextGateId();

  for (auto &wire : parent_) {
    RegisterWaitingFor(wire->GetWireId());  // mark this gate as waiting for @param wire
    wire->RegisterWaitingGate(gate_id_);    // register this gate in @param wire as waiting
  }

  if (shared_ptr_reg->GetConfig()->GetMyId() == static_cast<std::size_t>(output_owner_)) {
    is_my_output_ = true;
  }

  for (auto &bv : output_) {
    output_wires_.push_back(std::static_pointer_cast<ABYN::Wires::Wire>(
        std::make_shared<Wires::GMWWire>(bv, register_)));
  }

  for (auto &wire : output_wires_) {
    shared_ptr_reg->RegisterNextWire(wire);
  }

  auto gate_info =
      fmt::format("bitlength {}, gate id {}, owner {}", output_.size(), gate_id_, output_owner_);
  shared_ptr_reg->GetLogger()->LogTrace(
      fmt::format("Allocate an Boolean GMWOutputGate with following properties: {}", gate_info));
}

void GMWOutputGate::EvaluateOnline() {
  assert(setup_is_ready_);

  std::vector<Wires::GMWWirePtr> wires;
  {
    std::size_t i = 0;
    for (auto &wire : parent_) {
      auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(wire);
      assert(gmw_wire);
      wires.push_back(gmw_wire);
      output_.at(i) = wires.at(wires.size() - 1)->GetValuesOnWire();
      ++i;
    }
  }
  auto shared_ptr_reg = register_.lock();
  assert(shared_ptr_reg);
  if (is_my_output_) {
    // wait until all conditions are fulfilled
    for (auto &wire : wires) {
      while (!wire->IsReady()) {
        wire->GetIsReadyCondition()->WaitFor(std::chrono::milliseconds(1));
      }
    }

    auto &config = shared_ptr_reg->GetConfig();
    shared_outputs_.resize(shared_ptr_reg->GetConfig()->GetNumOfParties());

    for (auto i = 0ull; i < config->GetNumOfParties(); ++i) {
      if (i == config->GetMyId()) {
        continue;
      }
      bool success = false;
      auto &data_storage = config->GetCommunicationContext(i)->GetDataStorage();
      shared_outputs_.at(i).resize(output_.size());
      while (!success) {
        auto message = data_storage->GetOutputMessage(gate_id_);
        if (message != nullptr) {
          for (auto j = 0ull; j < message->wires()->size(); ++j) {
            auto payload = message->wires()->Get(j)->payload();
            auto ptr = reinterpret_cast<const std::byte *>(payload->data());
            std::vector<std::byte> byte_vector(ptr, ptr + payload->size());
            shared_outputs_.at(i).at(j) =
                ENCRYPTO::BitVector(byte_vector, parent_.at(0)->GetNumOfParallelValues());
            assert(shared_outputs_.at(i).size() == output_.size());
            success = true;
          }
        }
      }
    }

    shared_outputs_.at(config->GetMyId()) = output_;
    output_ = std::move(Helpers::XORBitVectors(shared_outputs_));

    std::string shares{""};
    for (auto i = 0u; i < config->GetNumOfParties(); ++i) {
      shares.append(fmt::format("id#{}:{} ", i, shared_outputs_.at(i).at(0).AsString()));
    }

    shared_ptr_reg->GetLogger()->LogTrace(
        fmt::format("Received output shares: {} from other parties, "
                    "reconstructed result is {}",
                    shares, output_.at(0).AsString()));

  } else {
    std::vector<std::vector<uint8_t>> payloads;
    for (auto i = 0ull; i < output_wires_.size(); ++i) {
      auto size = output_.at(i).GetData().size();
      auto data_ptr = reinterpret_cast<const uint8_t *>(output_.at(i).GetData().data());
      payloads.emplace_back(data_ptr, data_ptr + size);
    }
    auto output_message = ABYN::Communication::BuildOutputMessage(gate_id_, payloads);
    shared_ptr_reg->Send(output_owner_, output_message);
  }
  std::vector<Wires::GMWWirePtr> gmw_output_wires;
  for (auto i = 0ull; i < output_wires_.size(); ++i) {
    gmw_output_wires.push_back(
        std::dynamic_pointer_cast<ABYN::Wires::GMWWire>(output_wires_.at(i)));
    assert(gmw_output_wires.at(i));
    gmw_output_wires.at(i)->GetMutableValuesOnWire() = output_.at(i);
  }
  shared_ptr_reg->IncrementEvaluatedGatesCounter();
  shared_ptr_reg->GetLogger()->LogTrace(
      fmt::format("Evaluated Boolean GMWOutputGate with id#{}", gate_id_));
  SetOnlineIsReady();
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

GMWXORGate::GMWXORGate(const Shares::GMWSharePtr &a, const Shares::GMWSharePtr &b) {
  parent_a_ = a->GetWires();
  parent_b_ = b->GetWires();

  assert(parent_a_.size() > 0);
  assert(parent_b_.size() == parent_b_.size());

  register_ = parent_a_.at(0)->GetRegister();

  requires_online_interaction_ = false;
  gate_type_ = GateType::NonInteractiveGate;

  auto shared_ptr_reg = register_.lock();
  assert(shared_ptr_reg);

  gate_id_ = shared_ptr_reg->NextGateId();

  for (auto &wire : parent_a_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  for (auto &wire : parent_b_) {
    RegisterWaitingFor(wire->GetWireId());
    wire->RegisterWaitingGate(gate_id_);
  }

  output_wires_.resize(parent_a_.size());
  const ENCRYPTO::BitVector tmp_bv(a->GetNumOfParallelValues());
  for (auto &w : output_wires_) {
    w = std::move(
        std::static_pointer_cast<Wires::Wire>(std::make_shared<Wires::GMWWire>(tmp_bv, register_)));
  }

  for (auto &w : output_wires_) {
    shared_ptr_reg->RegisterNextWire(w);
  }

  auto gate_info = fmt::format("gate id {}, parents: {}, {}", gate_id_,
                               parent_a_.at(0)->GetWireId(), parent_b_.at(0)->GetWireId());
  shared_ptr_reg->GetLogger()->LogTrace(
      fmt::format("Created a BooleanGMW XOR gate with following properties: {}", gate_info));
}

void GMWXORGate::EvaluateOnline() {
  assert(setup_is_ready_);

  for (auto &wire : parent_a_) {
    while (!wire->IsReady()) {
      wire->GetIsReadyCondition()->WaitFor(std::chrono::milliseconds(1));
    }
  }

  for (auto &wire : parent_b_) {
    while (!wire->IsReady()) {
      wire->GetIsReadyCondition()->WaitFor(std::chrono::milliseconds(1));
    }
  }

  for (auto i = 0ull; i < parent_a_.size(); ++i) {
    auto wire_a = std::dynamic_pointer_cast<Wires::GMWWire>(parent_a_.at(i));
    auto wire_b = std::dynamic_pointer_cast<Wires::GMWWire>(parent_b_.at(i));

    assert(wire_a);
    assert(wire_b);

    auto output = wire_a->GetValuesOnWire() ^ wire_b->GetValuesOnWire();

    auto gmw_wire = std::dynamic_pointer_cast<Wires::GMWWire>(output_wires_.at(i));
    assert(gmw_wire);
    gmw_wire->GetMutableValuesOnWire() = std::move(output);
  }

  SetOnlineIsReady();

  auto shared_ptr_reg = register_.lock();
  assert(shared_ptr_reg);

  shared_ptr_reg->IncrementEvaluatedGatesCounter();
  shared_ptr_reg->GetLogger()->LogTrace(
      fmt::format("Evaluated BooleanGMW XOR Gate with id#{}", gate_id_));
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

}  // namespace ABYN::Gates::GMW