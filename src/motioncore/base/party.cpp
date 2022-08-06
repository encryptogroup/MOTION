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
#include "oblivious_transfer/1_out_of_n/kk13_ot_provider.h"
#include "oblivious_transfer/ot_provider.h"
#include "utility/logger.h"

namespace encrypto::motion {

Party::Party(std::unique_ptr<communication::CommunicationLayer> communication_layer)
    : configuration_(std::make_shared<Configuration>(communication_layer->GetMyId(),
                                                     communication_layer->GetNumberOfParties())),
      logger_(std::make_shared<Logger>(communication_layer->GetMyId(),
                                       configuration_->GetLoggingSeverityLevel())),
      backend_(std::make_shared<Backend>(std::move(communication_layer), configuration_, logger_)) {
}

Party::~Party() {
  Finish();
  logger_->LogInfo("motion::Party has been deallocated");
}

SharePointer Party::Out(SharePointer parent, std::size_t output_owner) {
  assert(parent);
  switch (parent->GetProtocol()) {
    case MpcProtocol::kArithmeticGmw: {
      switch (parent->GetBitLength()) {
        case 8u: {
          return backend_->ArithmeticGmwOutput<std::uint8_t>(parent, output_owner);
        }
        case 16u: {
          return backend_->ArithmeticGmwOutput<std::uint16_t>(parent, output_owner);
        }
        case 32u: {
          return backend_->ArithmeticGmwOutput<std::uint32_t>(parent, output_owner);
        }
        case 64u: {
          return backend_->ArithmeticGmwOutput<std::uint64_t>(parent, output_owner);
        }
        default: {
          throw(std::runtime_error(
              fmt::format("Unknown arithmetic ring of {} bilength", parent->GetBitLength())));
        }
      }
    }
    case MpcProtocol::kBooleanGmw: {
      return backend_->BooleanGmwOutput(parent, output_owner);
    }
    case MpcProtocol::kBmr: {
      throw(std::runtime_error("BMR output gate is not implemented yet"));
      // TODO
    }
    default: {
      throw(std::runtime_error(fmt::format("Unknown MPC protocol with id {}",
                                           static_cast<unsigned int>(parent->GetProtocol()))));
    }
  }
}

void Party::Run(std::size_t repetitions) {
  logger_->LogDebug("Party run");
  if(repetitions != 1){
    throw std::runtime_error("This functionality is not yet implemented");
  }

  // TODO: fix check if work exists s.t. it does not require knowledge about OT
  // internals etc.
  bool work_exists{backend_->GetOtProviderManager().HasWork() ||
                   backend_->GetKk13OtProviderManager().HasWork() ||
                   !backend_->GetRegister()->GetGates().empty()};
  if (!work_exists) {
    logger_->LogInfo("Party terminate: no work to do");
    return;
  }

  backend_->Synchronize();
  for (auto i = 0ull; i < repetitions; ++i) {
    if (i > 0u) {
      Clear();
    }
    logger_->LogDebug(fmt::format("Circuit evaluation #{}", i));
    EvaluateCircuit();
  }
}

void Party::Reset() {
  logger_->LogError("Not yet implemented");
  backend_->Synchronize();
  logger_->LogDebug("Party reset");
  backend_->Reset();
  logger_->LogDebug("Party sync");
  backend_->Synchronize();
}

void Party::Clear() {
  logger_->LogDebug(
      "Warning: the ::Clear() functionality is not fully implemented yet and may be buggy or not "
      "working properly");
  backend_->Synchronize();
  logger_->LogDebug("Party clear");
  backend_->Clear();
  logger_->LogDebug("Party sync");
  backend_->Synchronize();
}

void Party::EvaluateCircuit() {
  if (configuration_->GetOnlineAfterSetup()) {
    backend_->EvaluateSequential();
  } else {
    backend_->EvaluateParallel();
  }
}

void Party::Finish() {
  bool finished = finished_.exchange(true);
  if (!finished) {
    backend_->GetCommunicationLayer().Shutdown();
    logger_->LogInfo(fmt::format("Finished evaluating {} gates",
                                 backend_->GetRegister()->GetTotalNumberOfGates()));
  }
}

std::vector<std::unique_ptr<Party>> MakeLocallyConnectedParties(const std::size_t number_of_parties,
                                                                std::uint16_t, const bool) {
  if (number_of_parties < 2) {
    throw(std::runtime_error(
        fmt::format("Can generate only >= 2 local parties, current input: {}", number_of_parties)));
  }

  auto comm_layers = communication::MakeDummyCommunicationLayers(number_of_parties);

  std::vector<PartyPointer> motion_parties;
  motion_parties.reserve(number_of_parties);
  for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
    motion_parties.emplace_back(std::make_unique<Party>(std::move(comm_layers.at(party_id))));
  }
  return motion_parties;
}

}  // namespace encrypto::motion
