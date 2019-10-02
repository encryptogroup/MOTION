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

#include "party.h"

#include <map>

#include "base/backend.h"
#include "base/register.h"
#include "communication/context.h"
#include "crypto/oblivious_transfer/ot_provider.h"
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
  Finish();
  backend_->WaitForConnectionEnd();
  backend_->GetLogger()->LogInfo("ABYN::Party has been deallocated");
}

Shares::SharePtr Party::XOR(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  assert(a);
  assert(b);
  assert(a->GetSharingType() != MPCProtocol::ArithmeticGMW);
  assert(a->GetSharingType() == b->GetSharingType());
  switch (a->GetSharingType()) {
    case MPCProtocol::BooleanGMW: {
      return backend_->BooleanGMWXOR(a, b);
    }
    case MPCProtocol::BMR: {
      throw std::runtime_error("BMR protocol is not implemented yet");
      // TODO
    }
    default: {
      throw(std::runtime_error("Unknown protocol"));
    }
  }
}

Shares::SharePtr Party::OUT(Shares::SharePtr parent, std::size_t output_owner) {
  assert(parent);
  switch (parent->GetSharingType()) {
    case MPCProtocol::ArithmeticGMW: {
      switch (parent->GetBitLength()) {
        case 8u: {
          return backend_->ArithmeticGMWOutput<std::uint8_t>(parent, output_owner);
        }
        case 16u: {
          return backend_->ArithmeticGMWOutput<std::uint16_t>(parent, output_owner);
        }
        case 32u: {
          return backend_->ArithmeticGMWOutput<std::uint32_t>(parent, output_owner);
        }
        case 64u: {
          return backend_->ArithmeticGMWOutput<std::uint64_t>(parent, output_owner);
        }
        default: {
          throw(std::runtime_error(
              fmt::format("Unknown arithmetic ring of {} bilength", parent->GetBitLength())));
        }
      }
    }
    case MPCProtocol::BooleanGMW: {
      return backend_->BooleanGMWOutput(parent, output_owner);
    }
    case MPCProtocol::BMR: {
      throw(std::runtime_error("BMR output gate is not implemented yet"));
      // TODO
    }
    default: {
      throw(std::runtime_error(fmt::format("Unknown MPC protocol with id {}",
                                           static_cast<uint>(parent->GetSharingType()))));
    }
  }
}

Shares::SharePtr Party::ADD(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  assert(a);
  assert(b);
  assert(a->GetSharingType() == b->GetSharingType());

  switch (a->GetSharingType()) {
    case MPCProtocol::ArithmeticGMW: {
      assert(a->GetBitLength() == b->GetBitLength());
      switch (a->GetBitLength()) {
        case 8u: {
          return backend_->ArithmeticGMWAddition<std::uint8_t>(a, b);
        }
        case 16u: {
          return backend_->ArithmeticGMWAddition<std::uint16_t>(a, b);
        }
        case 32u: {
          return backend_->ArithmeticGMWAddition<std::uint32_t>(a, b);
        }
        case 64u: {
          return backend_->ArithmeticGMWAddition<std::uint64_t>(a, b);
        }
        default: {
          throw(std::runtime_error(
              fmt::format("Unknown arithmetic ring of {} bilength", a->GetBitLength())));
        }
      }
    }
    case MPCProtocol::BooleanGMW: {
      throw(std::runtime_error("BooleanGMW addition gate is not implemented yet"));
      // return BooleanGMWOutput(parent, output_owner);
    }
    case MPCProtocol::BMR: {
      throw(std::runtime_error("BMR addition gate is not implemented yet"));
      // TODO
    }
    default: {
      throw(std::runtime_error(
          fmt::format("Unknown MPC protocol with id {}", static_cast<uint>(a->GetSharingType()))));
    }
  }
}

Shares::SharePtr Party::AND(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  assert(a);
  assert(b);
  assert(a->GetSharingType() != MPCProtocol::ArithmeticGMW);
  assert(a->GetSharingType() == b->GetSharingType());
  switch (a->GetSharingType()) {
    case MPCProtocol::BooleanGMW: {
      return backend_->BooleanGMWAND(a, b);
    }
    case MPCProtocol::BMR: {
      throw std::runtime_error("BMR protocol is not implemented yet");
      // TODO
    }
    default: {
      throw(std::runtime_error("Unknown protocol"));
    }
  }
}

void Party::Connect() {
  // assign 1 thread for each connection
  auto n = config_->GetNumOfParties();
  std::vector<std::future<void>> futures;
  for (auto destination_id = 0u; destination_id < n; ++destination_id) {
    if (destination_id == config_->GetMyId()) {
      continue;
    }
    futures.emplace_back(std::async(std::launch::async, [destination_id, this]() {
      if constexpr (ABYN_DEBUG) {
        auto &p = config_->GetCommunicationContext(destination_id);
        backend_->GetLogger()->LogDebug(
            fmt::format("Trying to connect to {}:{}\n", p->GetIp().data(), p->GetPort()));
      }
      auto result = config_->GetCommunicationContext(destination_id)->Connect();
      backend_->GetLogger()->LogInfo(result);
    }));
  }
  for (auto &f : futures) f.get();
  backend_->InitializeCommunicationHandlers();
  backend_->SendHelloToOthers();
  connected_ = true;
}  // namespace ABYN

void Party::Run(std::size_t repeats) {
  omp_set_nested(1);
  backend_->GetLogger()->LogDebug("Party run");
  if (!IsConnected()) {
    Connect();
  }

  bool work_exists = backend_->GetRegister()->GetTotalNumOfGates() > 0;
  for (auto i = 0ull; i < backend_->GetConfig()->GetNumOfParties(); ++i) {
    if (i == backend_->GetConfig()->GetMyId()) {
      continue;
    }
    work_exists |= backend_->GetOTProvider(i)->GetNumOTsReceiver() > 0;
    work_exists |= backend_->GetOTProvider(i)->GetNumOTsSender() > 0;
  }
  if (!work_exists) {
    backend_->GetLogger()->LogInfo("Party terminate: no work to do");
    return;
  }

  backend_->VerifyHelloMessages();
  if (!backend_->GetConfig()->IsFixedKeyAESKeyReady()) {
    backend_->GenerateFixedKeyAESKey();
  }

  backend_->Sync();
  for (auto i = 0ull; i < repeats; ++i) {
    if (i > 0u) {
      Clear();
    }
    GetLogger()->LogDebug(fmt::format("Circuit evaluation #{}", i));
    EvaluateCircuit();
  }
}

void Party::Reset() {
  backend_->Sync();
  backend_->GetLogger()->LogDebug("Party reset");
  backend_->Reset();
  backend_->GetLogger()->LogDebug("Party sync");
  backend_->Sync();
}

void Party::Clear() {
  backend_->Sync();
  backend_->GetLogger()->LogDebug("Party clear");
  backend_->Clear();
  backend_->GetLogger()->LogDebug("Party sync");
  backend_->Sync();
}

void Party::EvaluateCircuit() {
  if (config_->GetOnlineAfterSetup()) {
    backend_->EvaluateSequential();
  } else {
    backend_->EvaluateParallel();
  }
}

void Party::Finish() {
  if (!finished_) {
    backend_->TerminateCommunication();
    backend_->GetLogger()->LogInfo(
        fmt::format("Finished evaluating {} gates", backend_->GetRegister()->GetTotalNumOfGates()));
    finished_ = true;
  }
}

std::vector<std::unique_ptr<Party>> GetNLocalParties(const std::size_t num_parties,
                                                     std::uint16_t port, const bool logging) {
  if (num_parties < 2) {
    throw(std::runtime_error(
        fmt::format("Can generate only >= 2 local parties, current input: {}", num_parties)));
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

  std::vector<std::thread> t;
  for (auto my_id = 0ul; my_id < num_parties; ++my_id) {
    t.emplace_back([my_id, num_parties, portid, &assigned_ports, &abyn_parties, logging]() {
      std::vector<Communication::ContextPtr> contexts;
      for (auto other_id = 0ul; other_id < num_parties; ++other_id) {
        if (my_id == other_id) continue;
        auto role = other_id < my_id ? Role::Client : Role::Server;

        std::uint32_t port_id = portid(my_id, other_id);

        std::uint16_t this_port;
        auto search = assigned_ports.find(port_id);
        this_port = search->second;

        contexts.emplace_back(
            std::make_shared<Communication::Context>("127.0.0.1", this_port, role, other_id));
      }
      auto config = std::make_shared<Configuration>(std::move(contexts), my_id);
      config->SetLoggingEnabled(logging);
      abyn_parties.at(my_id) = std::make_unique<Party>(config);
      abyn_parties.at(my_id)->Connect();
    });
  }

  for (auto &tt : t) {
    if (tt.joinable()) tt.join();
  }

  return abyn_parties;
}
}