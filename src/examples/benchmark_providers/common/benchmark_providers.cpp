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
#include "multiplication_triple/mt_provider.h"
#include "multiplication_triple/sb_provider.h"
#include "multiplication_triple/sp_provider.h"
#include "oblivious_transfer/ot_flavors.h"
#include "statistics/analysis.h"
#include "statistics/run_time_statistics.h"
#include "utility/block.h"
#include "utility/config.h"

encrypto::motion::RunTimeStatistics BenchmarkProvider(encrypto::motion::PartyPointer& party,
                                                      std::size_t batch_size, Provider provider,
                                                      std::size_t bit_size) {
  std::shared_ptr<encrypto::motion::Backend> backend{party->GetBackend()};
  std::shared_ptr<encrypto::motion::Configuration> configuration{backend->GetConfiguration()};
  const auto my_id{configuration->GetMyId()};
  auto& ot_provider = my_id == 0 ? backend->GetOtProvider(1) : backend->GetOtProvider(0);
  auto& sb_provider{backend->GetSbProvider()};
  auto& sp_provider{backend->GetSpProvider()};
  auto& mt_provider{backend->GetMtProvider()};

  std::list<encrypto::motion::RunTimeStatistics>& statistics =
      party->GetBackend()->GetMutableRunTimeStatistics();
  statistics.back().RecordStart<encrypto::motion::RunTimeStatistics::StatisticsId::kEvaluate>();

  switch (provider) {
    case Provider::kAmt: {
      switch (bit_size) {
        case 8:
          mt_provider.RequestArithmeticMts<std::uint8_t>(batch_size);
          break;
        case 16:
          mt_provider.RequestArithmeticMts<std::uint16_t>(batch_size);
          break;
        case 32:
          mt_provider.RequestArithmeticMts<std::uint32_t>(batch_size);
          break;
        case 64:
          mt_provider.RequestArithmeticMts<std::uint64_t>(batch_size);
          break;
        default:
          throw std::invalid_argument("Unknown bitlength");
      }
      mt_provider.PreSetup();
      backend->GetOtProviderManager().PreSetup();
      backend->Synchronize();
      backend->OtExtensionSetup();
      mt_provider.Setup();
      break;
    }
    case Provider::kBmt: {
      mt_provider.RequestBinaryMts(batch_size);
      mt_provider.PreSetup();
      backend->GetOtProviderManager().PreSetup();
      backend->Synchronize();
      backend->OtExtensionSetup();
      mt_provider.Setup();
      break;
    }
    case Provider::kAcOt: {
      switch (bit_size) {
        case 8:
          if (my_id == 0) {
            auto ot{ot_provider.RegisterReceiveAcOt(batch_size, sizeof(std::uint8_t) * 8)};
            auto casted_ot{dynamic_cast<encrypto::motion::AcOtReceiver<std::uint8_t>*>(ot.get())};
            casted_ot->SetChoices(encrypto::motion::BitVector<>(batch_size));
            backend->GetOtProviderManager().PreSetup();
            backend->Synchronize();
            backend->OtExtensionSetup();
            casted_ot->SendCorrections();
            casted_ot->ComputeOutputs();
            casted_ot->GetOutputs();
          } else {
            auto ot{ot_provider.RegisterSendAcOt(batch_size, sizeof(std::uint8_t) * 8)};
            auto casted_ot{dynamic_cast<encrypto::motion::AcOtSender<std::uint8_t>*>(ot.get())};
            backend->GetOtProviderManager().PreSetup();
            backend->Synchronize();
            backend->OtExtensionSetup();
            casted_ot->SetCorrelations(std::vector<std::uint8_t>(batch_size, 0x42));
            casted_ot->SendMessages();
          }
          break;
        case 16:
          if (my_id == 0) {
            auto ot{ot_provider.RegisterReceiveAcOt(batch_size, sizeof(std::uint16_t) * 8)};
            auto casted_ot{dynamic_cast<encrypto::motion::AcOtReceiver<std::uint16_t>*>(ot.get())};
            casted_ot->SetChoices(encrypto::motion::BitVector<>(batch_size));
            backend->GetOtProviderManager().PreSetup();
            backend->Synchronize();
            backend->OtExtensionSetup();
            casted_ot->SendCorrections();
            casted_ot->ComputeOutputs();
            casted_ot->GetOutputs();
          } else {
            auto ot{ot_provider.RegisterSendAcOt(batch_size, sizeof(std::uint16_t) * 8)};
            auto casted_ot{dynamic_cast<encrypto::motion::AcOtSender<std::uint16_t>*>(ot.get())};
            backend->GetOtProviderManager().PreSetup();
            backend->Synchronize();
            backend->OtExtensionSetup();
            casted_ot->SetCorrelations(std::vector<std::uint16_t>(batch_size, 0x42));
            casted_ot->SendMessages();
          }
          break;
        case 32:
          if (my_id == 0) {
            auto ot{ot_provider.RegisterReceiveAcOt(batch_size, sizeof(std::uint32_t) * 8)};
            auto casted_ot{dynamic_cast<encrypto::motion::AcOtReceiver<std::uint32_t>*>(ot.get())};
            casted_ot->SetChoices(encrypto::motion::BitVector<>(batch_size));
            backend->GetOtProviderManager().PreSetup();
            backend->Synchronize();
            backend->OtExtensionSetup();
            casted_ot->SendCorrections();
            casted_ot->ComputeOutputs();
            casted_ot->GetOutputs();
          } else {
            auto ot{ot_provider.RegisterSendAcOt(batch_size, sizeof(std::uint32_t) * 8)};
            auto casted_ot{dynamic_cast<encrypto::motion::AcOtSender<std::uint32_t>*>(ot.get())};
            backend->GetOtProviderManager().PreSetup();
            backend->Synchronize();
            backend->OtExtensionSetup();
            casted_ot->SetCorrelations(std::vector<std::uint32_t>(batch_size, 0x42));
            casted_ot->SendMessages();
          }
          break;
        case 64:
          if (my_id == 0) {
            auto ot{ot_provider.RegisterReceiveAcOt(batch_size, sizeof(std::uint64_t) * 8)};
            auto casted_ot{dynamic_cast<encrypto::motion::AcOtReceiver<std::uint64_t>*>(ot.get())};
            casted_ot->SetChoices(encrypto::motion::BitVector<>(batch_size));
            backend->GetOtProviderManager().PreSetup();
            backend->Synchronize();
            backend->OtExtensionSetup();
            casted_ot->SendCorrections();
            casted_ot->ComputeOutputs();
            casted_ot->GetOutputs();
          } else {
            auto ot{ot_provider.RegisterSendAcOt(batch_size, sizeof(std::uint64_t) * 8)};
            auto casted_ot{dynamic_cast<encrypto::motion::AcOtSender<std::uint64_t>*>(ot.get())};
            backend->GetOtProviderManager().PreSetup();
            backend->Synchronize();
            backend->OtExtensionSetup();
            casted_ot->SetCorrelations(std::vector<std::uint64_t>(batch_size, 0x42));
            casted_ot->SendMessages();
          }
          break;
        case 128:
          if (my_id == 0) {
            auto ot{ot_provider.RegisterReceiveAcOt(batch_size, sizeof(__uint128_t) * 8)};
            auto casted_ot{dynamic_cast<encrypto::motion::AcOtReceiver<__uint128_t>*>(ot.get())};
            casted_ot->SetChoices(encrypto::motion::BitVector<>(batch_size));
            backend->GetOtProviderManager().PreSetup();
            backend->Synchronize();
            backend->OtExtensionSetup();
            casted_ot->SendCorrections();
            casted_ot->ComputeOutputs();
            casted_ot->GetOutputs();
          } else {
            auto ot{ot_provider.RegisterSendAcOt(batch_size, sizeof(__uint128_t) * 8)};
            auto casted_ot{dynamic_cast<encrypto::motion::AcOtSender<__uint128_t>*>(ot.get())};
            backend->GetOtProviderManager().PreSetup();
            backend->Synchronize();
            backend->OtExtensionSetup();
            casted_ot->SetCorrelations(std::vector<__uint128_t>(batch_size, 0x42));
            casted_ot->SendMessages();
          }
          break;
        default:
          throw std::invalid_argument("Unknown bitlength");
      }
      break;
    }
    case Provider::kXcOt: {
      if (bit_size == 128) {
        if (my_id == 0) {
          auto ot{ot_provider.RegisterReceiveFixedXcOt128(batch_size)};
          ot->SetChoices(encrypto::motion::BitVector<>(batch_size));
          backend->GetOtProviderManager().PreSetup();
          backend->Synchronize();
          backend->OtExtensionSetup();
          ot->SendCorrections();
          ot->ComputeOutputs();
          ot->GetOutputs();
        } else {
          auto ot{ot_provider.RegisterSendFixedXcOt128(batch_size)};
          backend->GetOtProviderManager().PreSetup();
          backend->Synchronize();
          backend->OtExtensionSetup();
          const auto b{encrypto::motion::Block128::MakeRandom()};
          ot->SetCorrelation(b);
          ot->SendMessages();
        }
      } else if (bit_size == 1) {
        if (my_id == 0) {
          auto ot{ot_provider.RegisterReceiveXcOtBit(batch_size)};
          ot->SetChoices(encrypto::motion::BitVector<>(batch_size));
          backend->GetOtProviderManager().PreSetup();
          backend->Synchronize();
          backend->OtExtensionSetup();
          ot->SendCorrections();
          ot->ComputeOutputs();
          ot->GetOutputs();
        } else {
          auto ot{ot_provider.RegisterSendXcOtBit(batch_size)};
          backend->GetOtProviderManager().PreSetup();
          backend->Synchronize();
          backend->OtExtensionSetup();
          ot->SetCorrelations(encrypto::motion::BitVector<>(batch_size));
          ot->SendMessages();
        }
      } else {
        throw std::invalid_argument("Only 1 and 128 bits are supported for XCOTs in benchmarks");
      }
      break;
    }
    case Provider::kGOt: {
      if (bit_size == 128) {
        if (my_id == 0) {
          auto ot{ot_provider.RegisterReceiveGOt128(batch_size)};
          ot->SetChoices(encrypto::motion::BitVector<>(batch_size));
          backend->GetOtProviderManager().PreSetup();
          backend->Synchronize();
          backend->OtExtensionSetup();
          ot->SendCorrections();
          ot->ComputeOutputs();
          ot->GetOutputs();
        } else {
          auto ot{ot_provider.RegisterSendGOt128(batch_size)};
          backend->GetOtProviderManager().PreSetup();
          backend->Synchronize();
          backend->OtExtensionSetup();
          ot->SetInputs(encrypto::motion::Block128Vector(2 * batch_size,
                                                         encrypto::motion::Block128::MakeZero()));
          ot->SendMessages();
        }
      } else if (bit_size == 1) {
        if (my_id == 0) {
          auto ot{ot_provider.RegisterReceiveGOtBit(batch_size)};
          ot->SetChoices(encrypto::motion::BitVector<>(batch_size));
          backend->GetOtProviderManager().PreSetup();
          backend->Synchronize();
          backend->OtExtensionSetup();
          ot->SendCorrections();
          ot->ComputeOutputs();
          ot->GetOutputs();
        } else {
          auto ot{ot_provider.RegisterSendGOtBit(batch_size)};
          backend->GetOtProviderManager().PreSetup();
          backend->Synchronize();
          backend->OtExtensionSetup();
          ot->SetInputs(encrypto::motion::BitVector<>(2 * batch_size));
          ot->SendMessages();
        }
      } else {
        throw std::invalid_argument("Only 1 and 128 bits are supported for GOTs in benchmarks");
      }
      break;
    }
    case Provider::kROt: {
      if (my_id == 0) {
        auto ot{ot_provider.RegisterReceiveROt(batch_size, bit_size)};
        backend->GetOtProviderManager().PreSetup();
        backend->Synchronize();
        backend->OtExtensionSetup();
        (void)ot->GetOutputs();
      } else {
        auto ot{ot_provider.RegisterSendROt(batch_size, bit_size)};
        backend->GetOtProviderManager().PreSetup();
        backend->Synchronize();
        backend->OtExtensionSetup();
        ot->GetOutputs();
      }
      break;
    }
    case Provider::kSb: {
      switch (bit_size) {
        case 8:
          sb_provider.RequestSbs<std::uint8_t>(batch_size);
          break;
        case 16:
          sb_provider.RequestSbs<std::uint16_t>(batch_size);
          break;
        case 32:
          sb_provider.RequestSbs<std::uint32_t>(batch_size);
          break;
        case 64:
          sb_provider.RequestSbs<std::uint64_t>(batch_size);
          break;
        default:
          throw std::invalid_argument("Unknown bitlength");
      }
      sb_provider.PreSetup();
      sp_provider.PreSetup();
      backend->GetOtProviderManager().PreSetup();
      backend->Synchronize();
      backend->OtExtensionSetup();
      sp_provider.Setup();
      sb_provider.Setup();
      break;
    }
    case Provider::kSp: {
      switch (bit_size) {
        case 8:
          sp_provider.RequestSps<std::uint8_t>(batch_size);
          break;
        case 16:
          sp_provider.RequestSps<std::uint16_t>(batch_size);
          break;
        case 32:
          sp_provider.RequestSps<std::uint32_t>(batch_size);
          break;
        case 64:
          sp_provider.RequestSps<std::uint64_t>(batch_size);
          break;
        default:
          throw std::invalid_argument("Unknown bitlength");
      }
      sp_provider.PreSetup();
      backend->GetOtProviderManager().PreSetup();
      backend->Synchronize();
      backend->OtExtensionSetup();
      sp_provider.Setup();
      break;
    }
    default:
      throw std::invalid_argument("Invalid provider");
  }

  statistics.back().RecordEnd<encrypto::motion::RunTimeStatistics::StatisticsId::kEvaluate>();
  party->Finish();

  return statistics.front();
}
