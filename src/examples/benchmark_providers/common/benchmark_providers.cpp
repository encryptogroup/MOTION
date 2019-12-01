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

#include "benchmark_providers.h"

#include "base/backend.h"
#include "crypto/multiplication_triple/mt_provider.h"
#include "crypto/multiplication_triple/sb_provider.h"
#include "crypto/multiplication_triple/sp_provider.h"
#include "statistics/analysis.h"
#include "statistics/run_time_stats.h"
#include "utility/config.h"

MOTION::Statistics::RunTimeStats BenchmarkProvider(MOTION::PartyPtr& party, std::size_t batch_size,
                                                   Provider provider, std::size_t bit_size) {
  std::shared_ptr<MOTION::Backend> backend{party->GetBackend()};
  std::shared_ptr<MOTION::Configuration> config{backend->GetConfig()};
  const auto my_id{config->GetMyId()};
  std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTProvider> ot_provider =
      my_id == 0 ? backend->GetOTProvider(1) : backend->GetOTProvider(0);
  std::shared_ptr<MOTION::SBProvider> sb_provider{backend->GetSBProvider()};
  std::shared_ptr<MOTION::SPProvider> sp_provider{backend->GetSPProvider()};
  std::shared_ptr<MOTION::MTProvider> mt_provider{backend->GetMTProvider()};

  std::list<MOTION::Statistics::RunTimeStats>& stats = party->GetBackend()->GetMutableRunTimeStats();
  stats.back().record_start<MOTION::Statistics::RunTimeStats::StatID::evaluate>();

  switch (provider) {
    case Provider::AMT: {
      switch (bit_size) {
        case 8:
          mt_provider->RequestArithmeticMTs<std::uint8_t>(batch_size);
          break;
        case 16:
          mt_provider->RequestArithmeticMTs<std::uint16_t>(batch_size);
          break;
        case 32:
          mt_provider->RequestArithmeticMTs<std::uint32_t>(batch_size);
          break;
        case 64:
          mt_provider->RequestArithmeticMTs<std::uint64_t>(batch_size);
          break;
        default:
          throw std::invalid_argument("Unkown bitlength");
      }
      mt_provider->PreSetup();
      backend->OTExtensionSetup();
      mt_provider->Setup();
      break;
    }
    case Provider::BMT: {
      mt_provider->RequestBinaryMTs(batch_size);
      mt_provider->PreSetup();
      backend->OTExtensionSetup();
      mt_provider->Setup();
      break;
    }
    case Provider::ACOT: {
      switch (bit_size) {
        case 8:
          if (my_id == 0) {
            auto ot{ot_provider->RegisterReceive(8, batch_size, ENCRYPTO::ObliviousTransfer::ACOT)};
            ot->SetChoices(ENCRYPTO::BitVector<>(batch_size));
            backend->OTExtensionSetup();
            ot->SendCorrections();
            ot->GetOutputs();
          } else {
            auto ot{ot_provider->RegisterSend(8, batch_size, ENCRYPTO::ObliviousTransfer::ACOT)};
            backend->OTExtensionSetup();
            ot->SetInputs(std::vector<ENCRYPTO::BitVector<>>(batch_size, ENCRYPTO::BitVector<>(8)));
            ot->SendMessages();}
          break;
        case 16:
          if (my_id == 0) {
            auto ot{
                ot_provider->RegisterReceive(16, batch_size, ENCRYPTO::ObliviousTransfer::ACOT)};
            ot->SetChoices(ENCRYPTO::BitVector<>(batch_size));
            backend->OTExtensionSetup();
            ot->SendCorrections();
            ot->GetOutputs();
          } else {
            auto ot{ot_provider->RegisterSend(16, batch_size, ENCRYPTO::ObliviousTransfer::ACOT)};
            backend->OTExtensionSetup();
            ot->SetInputs(
                std::vector<ENCRYPTO::BitVector<>>(batch_size, ENCRYPTO::BitVector<>(16)));        ot->SendMessages();
          }
          break;
        case 32:
          if (my_id == 0) {
            auto ot{
                ot_provider->RegisterReceive(32, batch_size, ENCRYPTO::ObliviousTransfer::ACOT)};
            ot->SetChoices(ENCRYPTO::BitVector<>(batch_size));
            backend->OTExtensionSetup();
            ot->SendCorrections();
            ot->GetOutputs();
          } else {
            auto ot{ot_provider->RegisterSend(32, batch_size, ENCRYPTO::ObliviousTransfer::ACOT)};
            backend->OTExtensionSetup();
            ot->SetInputs(
                std::vector<ENCRYPTO::BitVector<>>(batch_size, ENCRYPTO::BitVector<>(32)));
            ot->SendMessages();
          }
          break;
        case 64:
          if (my_id == 0) {
            auto ot{
                ot_provider->RegisterReceive(64, batch_size, ENCRYPTO::ObliviousTransfer::ACOT)};
            ot->SetChoices(ENCRYPTO::BitVector<>(batch_size));
            backend->OTExtensionSetup();
            ot->SendCorrections();
            ot->GetOutputs();
          } else {
            auto ot{ot_provider->RegisterSend(64, batch_size, ENCRYPTO::ObliviousTransfer::ACOT)};
            backend->OTExtensionSetup();
            ot->SetInputs(
                std::vector<ENCRYPTO::BitVector<>>(batch_size, ENCRYPTO::BitVector<>(64)));
            ot->SendMessages();
          }
          break;
        case 128:
          if (my_id == 0) {
            auto ot{
                ot_provider->RegisterReceive(128, batch_size, ENCRYPTO::ObliviousTransfer::ACOT)};
            ot->SetChoices(ENCRYPTO::BitVector<>(batch_size));
            backend->OTExtensionSetup();
            ot->SendCorrections();
            ot->GetOutputs();
          } else {
            auto ot{ot_provider->RegisterSend(128, batch_size, ENCRYPTO::ObliviousTransfer::ACOT)};
            backend->OTExtensionSetup();
            ot->SetInputs(
                std::vector<ENCRYPTO::BitVector<>>(batch_size, ENCRYPTO::BitVector<>(128)));
            ot->SendMessages();
          }
          break;
        default:
          throw std::invalid_argument("Unkown bitlength");
      }
      break;
    }
    case Provider::XCOT: {
      if (my_id == 0) {
        auto ot{
            ot_provider->RegisterReceive(bit_size, batch_size, ENCRYPTO::ObliviousTransfer::XCOT)};
        ot->SetChoices(ENCRYPTO::BitVector<>(batch_size));
        backend->OTExtensionSetup();
        ot->SendCorrections();
        ot->GetOutputs();
      } else {
        auto ot{ot_provider->RegisterSend(bit_size, batch_size, ENCRYPTO::ObliviousTransfer::XCOT)};
        backend->OTExtensionSetup();
        ot->SetInputs(
            std::vector<ENCRYPTO::BitVector<>>(batch_size, ENCRYPTO::BitVector<>(bit_size)));
        ot->SendMessages();
      }
      break;
    }
    case Provider::GOT: {
      if (my_id == 0) {
        auto ot{
            ot_provider->RegisterReceive(bit_size, batch_size, ENCRYPTO::ObliviousTransfer::GOT)};
        ot->SetChoices(ENCRYPTO::BitVector<>(batch_size));
        backend->OTExtensionSetup();
        ot->SendCorrections();
        ot->GetOutputs();
      } else {
        auto ot{ot_provider->RegisterSend(bit_size, batch_size, ENCRYPTO::ObliviousTransfer::GOT)};
        backend->OTExtensionSetup();
        ot->SetInputs(
            std::vector<ENCRYPTO::BitVector<>>(batch_size, ENCRYPTO::BitVector<>(bit_size * 2)));
        ot->SendMessages();
      }
      break;
    }
    case Provider::ROT: {
      if (my_id == 0) {
        auto ot{
            ot_provider->RegisterReceive(bit_size, batch_size, ENCRYPTO::ObliviousTransfer::ROT)};
        backend->OTExtensionSetup();
        ot->GetOutputs();
      } else {
        auto ot{ot_provider->RegisterSend(bit_size, batch_size, ENCRYPTO::ObliviousTransfer::ROT)};
        backend->OTExtensionSetup();
        ot->GetOutputs();
      }
      break;
    }
    case Provider::SB: {
      switch (bit_size) {
        case 8:
          sb_provider->RequestSBs<std::uint8_t>(batch_size);
          break;
        case 16:
          sb_provider->RequestSBs<std::uint16_t>(batch_size);
          break;
        case 32:
          sb_provider->RequestSBs<std::uint32_t>(batch_size);
          break;
        case 64:
          sb_provider->RequestSBs<std::uint64_t>(batch_size);
          break;
        default:
          throw std::invalid_argument("Unkown bitlength");
      }
      sb_provider->PreSetup();
      sp_provider->PreSetup();
      backend->OTExtensionSetup();
      sp_provider->Setup();
      sb_provider->Setup();
      break;
    }
    case Provider::SP: {
      switch (bit_size) {
        case 8:
          sp_provider->RequestSPs<std::uint8_t>(batch_size);
          break;
        case 16:
          sp_provider->RequestSPs<std::uint16_t>(batch_size);
          break;
        case 32:
          sp_provider->RequestSPs<std::uint32_t>(batch_size);
          break;
        case 64:
          sp_provider->RequestSPs<std::uint64_t>(batch_size);
          break;
        default:
          throw std::invalid_argument("Unkown bitlength");
      }
      sp_provider->PreSetup();
      backend->OTExtensionSetup();
      sp_provider->Setup();
      break;
    }
    default:
      throw std::invalid_argument("Invalid provider");
  }

  stats.back().record_end<MOTION::Statistics::RunTimeStats::StatID::evaluate>();
  party->Finish();

  return stats.front();
}
