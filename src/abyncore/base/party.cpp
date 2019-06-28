#include "party.h"

#include <map>

#include "communication/context.h"
#include "utility/logger.h"

namespace ABYN {

Party::Party(std::vector<Communication::ContextPtr> &parties, std::size_t my_id) {
  config_ = std::make_shared<Configuration>(parties, my_id);
  backend_ = std::make_shared<Backend>(config_);
}

Party::Party(std::vector<Communication::ContextPtr> &&parties, std::size_t my_id) {
  config_ = std::make_shared<Configuration>(std::move(parties), my_id);
  backend_ = std::make_shared<Backend>(config_);
}

Party::Party(std::initializer_list<Communication::ContextPtr> &&list_parties, std::size_t my_id) {
  config_ = std::make_shared<Configuration>(std::move(list_parties), my_id);
  backend_ = std::make_shared<Backend>(config_);
}

Party::~Party() {
  backend_->WaitForConnectionEnd();
  backend_->GetLogger()->LogInfo("ABYN::Party has been deallocated");
}

ABYN::Shares::SharePtr Party::BooleanGMWInput(std::size_t party_id, bool input) {
  return BooleanGMWInput(party_id, ENCRYPTO::BitVector(1, input));
}

ABYN::Shares::SharePtr Party::BooleanGMWInput(std::size_t party_id,
                                              const ENCRYPTO::BitVector &input) {
  return BooleanGMWInput(party_id, std::vector<ENCRYPTO::BitVector>{input});
}

ABYN::Shares::SharePtr Party::BooleanGMWInput(std::size_t party_id, ENCRYPTO::BitVector &&input) {
  return BooleanGMWInput(party_id, std::vector<ENCRYPTO::BitVector>{std::move(input)});
}

ABYN::Shares::SharePtr Party::BooleanGMWInput(std::size_t party_id,
                                              const std::vector<ENCRYPTO::BitVector> &input) {
  auto in_gate =
      std::make_shared<Gates::GMW::GMWInputGate>(input, party_id, backend_->GetRegister());
  auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
  backend_->RegisterInputGate(in_gate_cast);
  return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
}

ABYN::Shares::SharePtr Party::BooleanGMWInput(std::size_t party_id,
                                              std::vector<ENCRYPTO::BitVector> &&input) {
  auto in_gate = std::make_shared<Gates::GMW::GMWInputGate>(std::move(input), party_id,
                                                            backend_->GetRegister());
  auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
  backend_->RegisterInputGate(in_gate_cast);
  return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
}

Shares::SharePtr Party::BooleanGMWXOR(const Shares::GMWSharePtr &a, const Shares::GMWSharePtr &b) {
  assert(a);
  assert(b);
  auto xor_gate = std::make_shared<Gates::GMW::GMWXORGate>(a, b);
  backend_->RegisterGate(xor_gate);
  return xor_gate->GetOutputAsShare();
}

Shares::SharePtr Party::BooleanGMWXOR(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  assert(a);
  assert(b);
  auto casted_parent_a_ptr = std::dynamic_pointer_cast<Shares::GMWShare>(a);
  auto casted_parent_b_ptr = std::dynamic_pointer_cast<Shares::GMWShare>(b);
  assert(casted_parent_a_ptr);
  assert(casted_parent_b_ptr);
  return BooleanGMWXOR(casted_parent_a_ptr, casted_parent_b_ptr);
}

Shares::SharePtr Party::BooleanGMWOutput(const Shares::SharePtr &parent, std::size_t output_owner) {
  assert(parent);
  auto out_gate = std::make_shared<Gates::GMW::GMWOutputGate>(parent->GetWires(), output_owner);
  auto out_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(out_gate);
  backend_->RegisterGate(out_gate_cast);
  return std::static_pointer_cast<Shares::Share>(out_gate->GetOutputAsShare());
}

ABYN::Shares::SharePtr Party::OUT(ABYN::Shares::SharePtr parent, std::size_t output_owner) {
  assert(parent);
  switch (parent->GetSharingType()) {
    case ABYN::Protocol::ArithmeticGMW: {
      switch (parent->GetBitLength()) {
        case 8u: {
          return ArithmeticGMWOutput<std::uint8_t>(parent, output_owner);
        }
        case 16u: {
          return ArithmeticGMWOutput<std::uint16_t>(parent, output_owner);
        }
        case 32u: {
          return ArithmeticGMWOutput<std::uint32_t>(parent, output_owner);
        }
        case 64u: {
          return ArithmeticGMWOutput<std::uint64_t>(parent, output_owner);
        }
        default: {
          throw(std::runtime_error(
              fmt::format("Unknown arithmetic ring of {} bilength", parent->GetBitLength())));
        }
      }
    }
    case ABYN::Protocol::BooleanGMW: {
      return BooleanGMWOutput(parent, output_owner);
    }
    case ABYN::Protocol::BMR: {
      throw(std::runtime_error("BMR output gate is not implemented yet"));
      // TODO
    }
    default: {
      throw(std::runtime_error(
          fmt::format("Unknown protocol with id {}", static_cast<uint>(parent->GetSharingType()))));
    }
  }
}

ABYN::Shares::SharePtr Party::ADD(const ABYN::Shares::SharePtr &a,
                                  const ABYN::Shares::SharePtr &b) {
  assert(a);
  assert(b);
  assert(a->GetSharingType() == b->GetSharingType());

  switch (a->GetSharingType()) {
    case ABYN::Protocol::ArithmeticGMW: {
      assert(a->GetBitLength() == b->GetBitLength());
      switch (a->GetBitLength()) {
        case 8u: {
          return ArithmeticGMWAddition<std::uint8_t>(a, b);
        }
        case 16u: {
          return ArithmeticGMWAddition<std::uint16_t>(a, b);
        }
        case 32u: {
          return ArithmeticGMWAddition<std::uint32_t>(a, b);
        }
        case 64u: {
          return ArithmeticGMWAddition<std::uint64_t>(a, b);
        }
        default: {
          throw(std::runtime_error(
              fmt::format("Unknown arithmetic ring of {} bilength", a->GetBitLength())));
        }
      }
    }
    case ABYN::Protocol::BooleanGMW: {
      throw(std::runtime_error("BooleanGMW addition gate is not implemented yet"));
      // return BooleanGMWOutput(parent, output_owner);
    }
    case ABYN::Protocol::BMR: {
      throw(std::runtime_error("BMR addition gate is not implemented yet"));
      // TODO
    }
    default: {
      throw(std::runtime_error(
          fmt::format("Unknown protocol with id {}", static_cast<uint>(a->GetSharingType()))));
    }
  }
}

void Party::Connect() {
  // assign 1 thread for each connection
  auto n = config_->GetNumOfParties();
#pragma omp parallel num_threads(n + 1)
#pragma omp single
  {
#pragma omp taskloop num_tasks(n) default(shared)
    for (auto destination_id = 0u; destination_id < n; ++destination_id) {
      if (destination_id == config_->GetMyId()) {
        continue;
      }
      auto &p = config_->GetCommunicationContext(destination_id);
      backend_->GetLogger()->LogDebug(
          fmt::format("Trying to connect to {}:{}\n", p->GetIp().data(), p->GetPort()));

      auto result = config_->GetCommunicationContext(destination_id)->Connect();
      backend_->GetLogger()->LogInfo(result);
    }
    backend_->InitializeCommunicationHandlers();
  }
  backend_->SendHelloToOthers();
}

void Party::Run(std::size_t repeats) {
  backend_->VerifyHelloMessages();
  for (auto i = 0ull; i < repeats; ++i) {
    EvaluateCircuit();
  }
  Finish();
}

void Party::EvaluateCircuit() {
  if (config_->GetOnlineAfterSetup()) {
    backend_->EvaluateSequential();
  } else {
    backend_->EvaluateParallel();
  }
}

void Party::Finish() { backend_->TerminateCommunication(); }

std::vector<std::unique_ptr<Party>> Party::GetNLocalParties(std::size_t num_parties,
                                                            std::uint16_t port) {
  if (num_parties < 3) {
    throw(std::runtime_error(
        fmt::format("Can generate only >= 3 local parties, current input: {}", num_parties)));
  }

  std::vector<PartyPtr> abyn_parties(num_parties);
  std::map<std::uint32_t, std::uint16_t> assigned_ports;

  // portid generation function - we require symmetric port generation for
  // parties, e.g., parties #4 and #7 independent of the position of the ids,
  // i.e., sort them always in ascending order and generate a bigger number out
  // of two ids.
  auto portid = [](std::uint32_t my_id, std::uint32_t other_id) -> std::uint32_t {
    return other_id < my_id ? (other_id << 16) + (my_id) : (my_id << 16) + (other_id);
  };

  // generate ports sequentially using the map data structure using the offset
  // @param port the generated ports given port=10000 and 4 parties are
  // 10000--10005
  for (auto my_id = 0ul; my_id < num_parties; ++my_id) {
    for (auto other_id = 0ul; other_id < num_parties; ++other_id) {
      if (my_id == other_id) continue;
      std::uint32_t port_id = portid(my_id, other_id);
      if (assigned_ports.find(port_id) == assigned_ports.end()) {
        assigned_ports.insert({port_id, port++});
      }
    }
  }

  // generate parties using separate threads
#pragma omp parallel num_threads(num_parties + 1)
#pragma omp single
#pragma omp taskloop num_tasks(num_parties)
  for (auto my_id = 0ul; my_id < num_parties; ++my_id) {
    std::vector<Communication::ContextPtr> parties;
    for (auto other_id = 0ul; other_id < num_parties; ++other_id) {
      if (my_id == other_id) continue;
      ABYN::Role role = other_id < my_id ? ABYN::Role::Client : ABYN::Role::Server;

      std::uint32_t port_id = portid(my_id, other_id);

      std::uint16_t this_port;
      auto search = assigned_ports.find(port_id);
      if (search != assigned_ports.end()) {
        this_port = search->second;
      } else {
        throw(std::runtime_error(
            fmt::format("Didn't find the port id in the lookup table: {}", port_id)));
      };

      parties.emplace_back(
          std::make_shared<Communication::Context>("127.0.0.1", this_port, role, other_id));
    }
    abyn_parties.at(my_id) = std::make_unique<Party>(std::move(parties), my_id);
    abyn_parties.at(my_id)->Connect();
  }

  return std::move(abyn_parties);
}
}