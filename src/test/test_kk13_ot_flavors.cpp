// MIT License
//
// Copyright (c) 2021 Arianne Roselina Prananto
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

#include <algorithm>
#include <future>
#include <memory>

#include <fmt/format.h>
#include <gtest/gtest.h>

#include "base/motion_base_provider.h"
#include "communication/communication_layer.h"
#include "oblivious_transfer/1_out_of_n/kk13_ot_flavors.h"
#include "oblivious_transfer/base_ots/base_ot_provider.h"
#include "utility/block.h"

namespace {
using namespace encrypto::motion;

// number of parties, wires, SIMD values, online-after-setup flag
using Kk13OtFlavorParametersType = std::tuple<std::size_t, std::size_t>;

class Kk13OtFlavorTest : public testing::TestWithParam<Kk13OtFlavorParametersType> {
 protected:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(number_of_ots_, number_of_messages_) = parameters;

    communication_layers_ = communication::MakeDummyCommunicationLayers(2);
    base_ot_providers_.resize(2);
    motion_base_providers_.resize(2);
    ot_provider_wrappers_.resize(2);
    for (std::size_t i = 0; i < 2; ++i) {
      base_ot_providers_[i] = std::make_unique<BaseOtProvider>(*communication_layers_[i]);
      motion_base_providers_[i] = std::make_unique<BaseProvider>(*communication_layers_[i]);
      ot_provider_wrappers_[i] = std::make_unique<Kk13OtProviderManager>(
          *communication_layers_[i], *base_ot_providers_[i], *motion_base_providers_[i]);
    }
  }

  void TearDown() override {
    number_of_ots_ = number_of_messages_ = 0;
    std::vector<std::future<void>> futures;
    for (std::size_t i = 0; i < 2; ++i) {
      futures.emplace_back(
          std::async(std::launch::async, [this, i] { communication_layers_[i]->Shutdown(); }));
    }
    std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });
  }

  Kk13OtProvider& GetSenderProvider() {
    return ot_provider_wrappers_[sender_i_]->GetProvider(receiver_i_);
  }

  Kk13OtProvider& GetReceiverProvider() {
    return ot_provider_wrappers_[receiver_i_]->GetProvider(sender_i_);
  }

  void RunPreprocessing() {
    std::vector<std::future<void>> futures;
    for (std::size_t i = 0; i < 2; ++i) {
      futures.emplace_back(std::async(std::launch::async, [this, i] {
        communication_layers_[i]->Start();
        ot_provider_wrappers_[i]->PreSetup();
        base_ot_providers_[i]->PreSetup();
        motion_base_providers_[i]->Setup();
        base_ot_providers_[i]->ComputeBaseOts();
      }));
    }
    std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });
  }

  void RunKk13OtExtensionSetup() {
    std::vector<std::future<void>> futures;
    for (std::size_t i = 0; i < 2; ++i) {
      futures.emplace_back(std::async(std::launch::async, [this, i] {
        ot_provider_wrappers_[i]->GetProvider(1 - i).SendSetup();
      }));
      futures.emplace_back(std::async(std::launch::async, [this, i] {
        ot_provider_wrappers_[i]->GetProvider(1 - i).ReceiveSetup();
      }));
    }
    std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });
  }

  const std::size_t sender_i_ = 0;
  const std::size_t receiver_i_ = 1;

  std::vector<std::unique_ptr<communication::CommunicationLayer>> communication_layers_;
  std::vector<std::unique_ptr<BaseOtProvider>> base_ot_providers_;
  std::vector<std::unique_ptr<BaseProvider>> motion_base_providers_;
  std::vector<std::unique_ptr<Kk13OtProviderManager>> ot_provider_wrappers_;

  std::size_t number_of_ots_ = 0, number_of_messages_ = 0;
};

TEST_P(Kk13OtFlavorTest, GKk13Ot128) {
  const auto sender_input = Block128Vector::MakeRandom(number_of_messages_ * number_of_ots_);
  std::vector<std::uint8_t> choices_(number_of_ots_);
  std::mt19937 gen(std::random_device{}());
  std::uniform_int_distribution<std::uint8_t> dist(0, number_of_messages_ - 1);
  for (auto i = 0ull; i < number_of_ots_; ++i) {
    choices_[i] = dist(gen);
  }

  auto ot_sender = GetSenderProvider().RegisterSendGOt128(number_of_ots_, number_of_messages_);
  auto ot_receiver =
      GetReceiverProvider().RegisterReceiveGOt128(number_of_ots_, number_of_messages_);

  RunPreprocessing();
  RunKk13OtExtensionSetup();

  ot_receiver->SetChoices(choices_);
  ot_receiver->SendCorrections();

  ot_sender->SetInputs(sender_input);
  ot_sender->SendMessages();

  ot_receiver->ComputeOutputs();
  const auto receiver_output = ot_receiver->GetOutputs();

  for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
    ASSERT_TRUE(receiver_output[ot_i] == sender_input[number_of_messages_ * ot_i + choices_[ot_i]]);
  }
}

TEST_P(Kk13OtFlavorTest, GKk13OtBit) {
  const auto sender_input = BitVector<>::SecureRandom(number_of_messages_ * number_of_ots_);
  std::vector<std::uint8_t> choices_(number_of_ots_);
  std::mt19937 gen(std::random_device{}());
  std::uniform_int_distribution<std::uint8_t> dist(0, number_of_messages_ - 1);
  for (auto i = 0ull; i < number_of_ots_; ++i) {
    choices_[i] = dist(gen);
  }

  auto ot_sender = GetSenderProvider().RegisterSendGOtBit(number_of_ots_, number_of_messages_);
  auto ot_receiver =
      GetReceiverProvider().RegisterReceiveGOtBit(number_of_ots_, number_of_messages_);

  RunPreprocessing();
  RunKk13OtExtensionSetup();

  ot_receiver->SetChoices(choices_);
  ot_receiver->SendCorrections();

  ot_sender->SetInputs(sender_input);
  ot_sender->SendMessages();

  ot_receiver->ComputeOutputs();
  const auto receiver_output = ot_receiver->GetOutputs();

  for (std::size_t ot_i = 0; ot_i < number_of_ots_; ++ot_i) {
    ASSERT_EQ(receiver_output[ot_i], sender_input.Get(number_of_messages_ * ot_i + choices_[ot_i]));
  }
}

constexpr std::array<std::size_t, 3> kKK13OtFlavorNumberOfOts{50, 100, 1000};
constexpr std::array<std::size_t, 3> kKK13OtFlavorNumberOfMessages{2, 5, 10};

INSTANTIATE_TEST_SUITE_P(Kk13OtFlavorTestSuite, Kk13OtFlavorTest,
                         testing::Combine(testing::ValuesIn(kKK13OtFlavorNumberOfOts),
                                          testing::ValuesIn(kKK13OtFlavorNumberOfMessages)),
                         [](const testing::TestParamInfo<Kk13OtFlavorTest::ParamType>& info) {
                           std::string name =
                               fmt::format("{}_Ots_with_{}_Messages", std::get<0>(info.param),
                                           std::get<1>(info.param));
                           return name;
                         });

}  // namespace