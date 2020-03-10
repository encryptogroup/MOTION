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

#include "base/backend.h"
#include "base/configuration.h"
#include "base/register.h"
#include "communication/communication_layer.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "utility/logger.h"

namespace MOTION {

Party::Party(std::unique_ptr<Communication::CommunicationLayer> communication_layer)
    : communication_layer_(std::move(communication_layer)),
      config_(std::make_shared<Configuration>(communication_layer_->get_my_id(), communication_layer_->get_num_parties())),
      logger_(std::make_shared<Logger>(communication_layer_->get_my_id(), config_->GetLoggingSeverityLevel())),
      backend_(std::make_shared<Backend>(*communication_layer_, config_, logger_))
  {}

Party::~Party() {
  Finish();
  logger_->LogInfo("MOTION::Party has been deallocated");
}

Shares::SharePtr Party::XOR(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  assert(a);
  assert(b);
  assert(a->GetProtocol() != MPCProtocol::ArithmeticGMW);
  assert(a->GetProtocol() == b->GetProtocol());
  switch (a->GetProtocol()) {
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
  switch (parent->GetProtocol()) {
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
                                           static_cast<uint>(parent->GetProtocol()))));
    }
  }
}

Shares::SharePtr Party::ADD(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  assert(a);
  assert(b);
  assert(a->GetProtocol() == b->GetProtocol());

  switch (a->GetProtocol()) {
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
          fmt::format("Unknown MPC protocol with id {}", static_cast<uint>(a->GetProtocol()))));
    }
  }
}

Shares::SharePtr Party::AND(const Shares::SharePtr &a, const Shares::SharePtr &b) {
  assert(a);
  assert(b);
  assert(a->GetProtocol() != MPCProtocol::ArithmeticGMW);
  assert(a->GetProtocol() == b->GetProtocol());
  switch (a->GetProtocol()) {
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

void Party::Run(std::size_t repeats) {
  logger_->LogDebug("Party run");

  // TODO: fix check if work exists s.t. it does not require knowledge about OT
  // internals etc.
  bool work_exists = backend_->GetRegister()->GetTotalNumOfGates() > 0;
  for (auto party_id = 0ull; party_id < communication_layer_->get_num_parties(); ++party_id) {
    if (party_id == communication_layer_->get_my_id()) {
      continue;
    }
    work_exists |= backend_->GetOTProvider(party_id).GetNumOTsReceiver() > 0;
    work_exists |= backend_->GetOTProvider(party_id).GetNumOTsSender() > 0;
  }
  if (!work_exists) {
    logger_->LogInfo("Party terminate: no work to do");
    return;
  }

  backend_->Sync();
  for (auto i = 0ull; i < repeats; ++i) {
    if (i > 0u) {
      Clear();
    }
    logger_->LogDebug(fmt::format("Circuit evaluation #{}", i));
    EvaluateCircuit();
  }
}

void Party::Reset() {
  backend_->Sync();
  logger_->LogDebug("Party reset");
  backend_->Reset();
  logger_->LogDebug("Party sync");
  backend_->Sync();
}

void Party::Clear() {
  backend_->Sync();
  logger_->LogDebug("Party clear");
  backend_->Clear();
  logger_->LogDebug("Party sync");
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
    communication_layer_->shutdown();
    logger_->LogInfo(
        fmt::format("Finished evaluating {} gates", backend_->GetRegister()->GetTotalNumOfGates()));
    finished_ = true;
  }
}

std::vector<std::unique_ptr<Party>> GetNLocalParties(const std::size_t num_parties, std::uint16_t,
                                                     const bool) {
  if (num_parties < 2) {
    throw(std::runtime_error(
        fmt::format("Can generate only >= 2 local parties, current input: {}", num_parties)));
  }

  auto comm_layers = Communication::make_dummy_communication_layers(num_parties);

  std::vector<PartyPtr> motion_parties;
  motion_parties.reserve(num_parties);
  for (std::size_t party_id = 0; party_id < num_parties; ++party_id) {
    motion_parties.emplace_back(std::make_unique<Party>(std::move(comm_layers.at(party_id))));
  }
  return motion_parties;
}

}
