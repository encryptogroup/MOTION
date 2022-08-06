// MIT License
//
// Copyright (c) 2020 Lennart Braun
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

#include <gtest/gtest.h>
#include <algorithm>
#include <future>
#include <memory>

#include "base/motion_base_provider.h"
#include "communication/communication_layer.h"
#include "oblivious_transfer/base_ots/base_ot_provider.h"
#include "oblivious_transfer/ot_flavors.h"
#include "utility/block.h"

class OtFlavorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    communication_layers_ = encrypto::motion::communication::MakeDummyCommunicationLayers(2);
    base_ot_providers_.resize(2);
    motion_base_providers_.resize(2);
    ot_provider_wrappers_.resize(2);
    for (std::size_t i = 0; i < 2; ++i) {
      base_ot_providers_[i] =
          std::make_unique<encrypto::motion::BaseOtProvider>(*communication_layers_[i]);
      motion_base_providers_[i] =
          std::make_unique<encrypto::motion::BaseProvider>(*communication_layers_[i]);
      ot_provider_wrappers_[i] = std::make_unique<encrypto::motion::OtProviderManager>(
          *communication_layers_[i], *base_ot_providers_[i], *motion_base_providers_[i]);
    }
  }

  void TearDown() override {
    std::vector<std::future<void>> futures;
    for (std::size_t i = 0; i < 2; ++i) {
      futures.emplace_back(
          std::async(std::launch::async, [this, i] { communication_layers_[i]->Shutdown(); }));
    }
    std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });
  }

  encrypto::motion::OtProvider& GetSenderProvider() {
    return ot_provider_wrappers_[sender_i_]->GetProvider(receiver_i_);
  }

  encrypto::motion::OtProvider& GetReceiverProvider() {
    return ot_provider_wrappers_[receiver_i_]->GetProvider(sender_i_);
  }

  void RunOtExtensionSetup() {
    for (std::size_t i = 0; i < 2; ++i) {
      ot_provider_wrappers_[i]->PreSetup();
      base_ot_providers_[i]->PreSetup();
    }

    std::vector<std::future<void>> futures;
    for (std::size_t i = 0; i < 2; ++i) {
      futures.emplace_back(std::async(std::launch::async, [this, i] {
        communication_layers_[i]->Start();
        communication_layers_[i]->Synchronize();
        motion_base_providers_[i]->Setup();
        base_ot_providers_[i]->ComputeBaseOts();
      }));
    }
    std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });

    futures.clear();
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

  std::vector<std::unique_ptr<encrypto::motion::communication::CommunicationLayer>>
      communication_layers_;
  std::vector<std::unique_ptr<encrypto::motion::BaseOtProvider>> base_ot_providers_;
  std::vector<std::unique_ptr<encrypto::motion::BaseProvider>> motion_base_providers_;
  std::vector<std::unique_ptr<encrypto::motion::OtProviderManager>> ot_provider_wrappers_;
};

TEST_F(OtFlavorTest, FixedXcOt128) {
  constexpr std::size_t kNumberOfOts = 1000;
  const auto correlation = encrypto::motion::Block128::MakeRandom();
  const auto choice_bits = encrypto::motion::BitVector<>::SecureRandom(kNumberOfOts);
  auto ot_sender = GetSenderProvider().RegisterSendFixedXcOt128(kNumberOfOts);
  auto ot_receiver = GetReceiverProvider().RegisterReceiveFixedXcOt128(kNumberOfOts);

  RunOtExtensionSetup();

  ot_sender->SetCorrelation(correlation);
  ot_sender->SendMessages();

  ot_receiver->SetChoices(choice_bits);
  ot_receiver->SendCorrections();

  ot_sender->ComputeOutputs();
  ot_receiver->ComputeOutputs();
  const auto sender_output = ot_sender->GetOutputs();
  const auto receiver_output = ot_receiver->GetOutputs();

  for (std::size_t ot_i = 0; ot_i < kNumberOfOts; ++ot_i) {
    if (choice_bits.Get(ot_i)) {
      EXPECT_TRUE(receiver_output[ot_i] == (sender_output[ot_i] ^ correlation));
    } else {
      EXPECT_TRUE(receiver_output[ot_i] == sender_output[ot_i]);
    }
  }
}

TEST_F(OtFlavorTest, XcOtBit) {
  constexpr std::size_t kNumberOfOts = 1000;
  const auto correlations = encrypto::motion::BitVector<>::SecureRandom(kNumberOfOts);
  const auto choice_bits = encrypto::motion::BitVector<>::SecureRandom(kNumberOfOts);
  auto ot_sender = GetSenderProvider().RegisterSendXcOtBit(kNumberOfOts);
  auto ot_receiver = GetReceiverProvider().RegisterReceiveXcOtBit(kNumberOfOts);

  RunOtExtensionSetup();

  ot_sender->SetCorrelations(correlations);
  ot_sender->SendMessages();

  ot_receiver->SetChoices(choice_bits);
  ot_receiver->SendCorrections();

  ot_sender->ComputeOutputs();
  ot_receiver->ComputeOutputs();
  const auto sender_output = ot_sender->GetOutputs();
  const auto receiver_output = ot_receiver->GetOutputs();

  ASSERT_EQ(receiver_output, sender_output ^ (choice_bits & correlations));
}

template <typename T>
class AcOtTest : public OtFlavorTest {
  using is_enabled_t_ = encrypto::motion::IsUnsignedInt<T>;
};

using integer_types =
    ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t, __uint128_t>;
TYPED_TEST_SUITE(AcOtTest, integer_types);

TYPED_TEST(AcOtTest, AcOt) {
  constexpr std::size_t kNumberOfOts = 1000;
  const auto correlations = encrypto::motion::RandomVector<TypeParam>(kNumberOfOts);
  const auto choice_bits = encrypto::motion::BitVector<>::SecureRandom(kNumberOfOts);
  auto ot_sender = this->GetSenderProvider().RegisterSendAcOt(kNumberOfOts, sizeof(TypeParam) * 8);
  auto ot_receiver =
      this->GetReceiverProvider().RegisterReceiveAcOt(kNumberOfOts, sizeof(TypeParam) * 8);

  auto casted_ot_sender{dynamic_cast<encrypto::motion::AcOtSender<TypeParam>*>(ot_sender.get())};
  auto casted_ot_receiver{
      dynamic_cast<encrypto::motion::AcOtReceiver<TypeParam>*>(ot_receiver.get())};

  this->RunOtExtensionSetup();

  casted_ot_sender->SetCorrelations(correlations);
  casted_ot_sender->SendMessages();

  casted_ot_receiver->SetChoices(choice_bits);
  casted_ot_receiver->SendCorrections();

  casted_ot_sender->ComputeOutputs();
  casted_ot_receiver->ComputeOutputs();
  const auto sender_output = casted_ot_sender->GetOutputs();
  const auto receiver_output = casted_ot_receiver->GetOutputs();

  EXPECT_EQ(sender_output.size(), kNumberOfOts);
  EXPECT_EQ(receiver_output.size(), kNumberOfOts);

  for (std::size_t ot_i = 0; ot_i < kNumberOfOts; ++ot_i) {
    if (choice_bits.Get(ot_i)) {
      EXPECT_EQ(receiver_output[ot_i], TypeParam(sender_output[ot_i] + correlations[ot_i]));
    } else {
      EXPECT_EQ(receiver_output[ot_i], sender_output[ot_i]);
    }
  }
}

TYPED_TEST(AcOtTest, VectorAcOt) {
  constexpr std::size_t kNumberOfOts = 100;
  constexpr std::size_t kVectorSize = 100;
  const auto correlations = encrypto::motion::RandomVector<TypeParam>(kNumberOfOts * kVectorSize);
  const auto choice_bits = encrypto::motion::BitVector<>::SecureRandom(kNumberOfOts);
  auto ot_sender =
      this->GetSenderProvider().RegisterSendAcOt(kNumberOfOts, sizeof(TypeParam) * 8, kVectorSize);
  auto ot_receiver = this->GetReceiverProvider().RegisterReceiveAcOt(
      kNumberOfOts, sizeof(TypeParam) * 8, kVectorSize);

  auto casted_ot_sender{dynamic_cast<encrypto::motion::AcOtSender<TypeParam>*>(ot_sender.get())};
  auto casted_ot_receiver{
      dynamic_cast<encrypto::motion::AcOtReceiver<TypeParam>*>(ot_receiver.get())};

  this->RunOtExtensionSetup();

  casted_ot_sender->SetCorrelations(correlations);
  casted_ot_sender->SendMessages();

  casted_ot_receiver->SetChoices(choice_bits);
  casted_ot_receiver->SendCorrections();

  casted_ot_sender->ComputeOutputs();
  casted_ot_receiver->ComputeOutputs();
  const auto sender_output = casted_ot_sender->GetOutputs();
  const auto receiver_output = casted_ot_receiver->GetOutputs();

  EXPECT_EQ(sender_output.size(), kNumberOfOts * kVectorSize);
  EXPECT_EQ(receiver_output.size(), kNumberOfOts * kVectorSize);

  for (std::size_t ot_i = 0; ot_i < kNumberOfOts; ++ot_i) {
    if (choice_bits.Get(ot_i)) {
      for (std::size_t j = 0; j < kVectorSize; ++j) {
        EXPECT_EQ(receiver_output[ot_i * kVectorSize + j],
                  TypeParam(sender_output[ot_i * kVectorSize + j] +
                            correlations[ot_i * kVectorSize + j]));
      }
    } else {
      for (std::size_t j = 0; j < kVectorSize; ++j) {
        EXPECT_EQ(receiver_output[ot_i * kVectorSize + j], sender_output[ot_i * kVectorSize + j]);
      }
    }
  }
}

TEST_F(OtFlavorTest, GOt128) {
  constexpr std::size_t kNumberOfOts = 1000;
  const auto sender_input = encrypto::motion::Block128Vector::MakeRandom(2 * kNumberOfOts);
  const auto choice_bits = encrypto::motion::BitVector<>::SecureRandom(kNumberOfOts);
  auto ot_sender = GetSenderProvider().RegisterSendGOt128(kNumberOfOts);
  auto ot_receiver = GetReceiverProvider().RegisterReceiveGOt128(kNumberOfOts);

  RunOtExtensionSetup();

  ot_receiver->SetChoices(choice_bits);
  ot_receiver->SendCorrections();

  ot_sender->SetInputs(sender_input);
  ot_sender->SendMessages();

  ot_receiver->ComputeOutputs();
  const auto receiver_output = ot_receiver->GetOutputs();

  for (std::size_t ot_i = 0; ot_i < kNumberOfOts; ++ot_i) {
    if (choice_bits.Get(ot_i)) {
      EXPECT_TRUE(receiver_output[ot_i] == sender_input[2 * ot_i + 1]);
    } else {
      EXPECT_TRUE(receiver_output[ot_i] == sender_input[2 * ot_i]);
    }
  }
}

TEST_F(OtFlavorTest, GOtBit) {
  constexpr std::size_t kNumberOfOts = 1000;
  const auto sender_input = encrypto::motion::BitVector<>::SecureRandom(2 * kNumberOfOts);
  const auto choice_bits = encrypto::motion::BitVector<>::SecureRandom(kNumberOfOts);
  auto ot_sender = GetSenderProvider().RegisterSendGOtBit(kNumberOfOts);
  auto ot_receiver = GetReceiverProvider().RegisterReceiveGOtBit(kNumberOfOts);

  RunOtExtensionSetup();

  ot_receiver->SetChoices(choice_bits);
  ot_receiver->SendCorrections();

  ot_sender->SetInputs(sender_input);
  ot_sender->SendMessages();

  ot_receiver->ComputeOutputs();
  const auto receiver_output = ot_receiver->GetOutputs();

  for (std::size_t ot_i = 0; ot_i < kNumberOfOts; ++ot_i) {
    if (choice_bits.Get(ot_i)) {
      ASSERT_EQ(receiver_output.Get(ot_i), sender_input.Get(2 * ot_i + 1));
    } else {
      ASSERT_EQ(receiver_output.Get(ot_i), sender_input.Get(2 * ot_i));
    }
  }
}
