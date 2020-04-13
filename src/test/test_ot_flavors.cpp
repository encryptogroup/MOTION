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

#include "communication/communication_layer.h"
#include "crypto/base_ots/base_ot_provider.h"
#include "crypto/motion_base_provider.h"
#include "crypto/oblivious_transfer/ot_flavors.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "utility/block.h"

class OTFlavorTest : public ::testing::Test {
 protected:
  void SetUp() override {
    comm_layers_ = MOTION::Communication::make_dummy_communication_layers(2);
    base_ot_providers_.resize(2);
    motion_base_providers_.resize(2);
    ot_provider_wrappers_.resize(2);
    for (std::size_t i = 0; i < 2; ++i) {
      base_ot_providers_[i] = std::make_unique<MOTION::BaseOTProvider>(*comm_layers_[i], nullptr);
      motion_base_providers_[i] =
          std::make_unique<MOTION::Crypto::MotionBaseProvider>(*comm_layers_[i], nullptr);
      ot_provider_wrappers_[i] = std::make_unique<ENCRYPTO::ObliviousTransfer::OTProviderManager>(
          *comm_layers_[i], *base_ot_providers_[i], *motion_base_providers_[i], nullptr);
    }

    std::vector<std::future<void>> futs;
    for (std::size_t i = 0; i < 2; ++i) {
      futs.emplace_back(std::async(std::launch::async, [this, i] {
        comm_layers_[i]->start();
        motion_base_providers_[i]->setup();
        base_ot_providers_[i]->ComputeBaseOTs();
      }));
    }
    std::for_each(std::begin(futs), std::end(futs), [](auto& f) { f.get(); });
  }

  void TearDown() override {
    std::vector<std::future<void>> futs;
    for (std::size_t i = 0; i < 2; ++i) {
      futs.emplace_back(std::async(std::launch::async, [this, i] { comm_layers_[i]->shutdown(); }));
    }
    std::for_each(std::begin(futs), std::end(futs), [](auto& f) { f.get(); });
  }

  const std::size_t sender_i_ = 0;
  const std::size_t receiver_i_ = 1;
  ENCRYPTO::ObliviousTransfer::OTProvider& get_sender_provider() {
    return ot_provider_wrappers_[sender_i_]->get_provider(receiver_i_);
  }
  ENCRYPTO::ObliviousTransfer::OTProvider& get_receiver_provider() {
    return ot_provider_wrappers_[receiver_i_]->get_provider(sender_i_);
  }

  void run_ot_extension_setup() {
    std::vector<std::future<void>> futs;
    for (std::size_t i = 0; i < 2; ++i) {
      futs.emplace_back(std::async(std::launch::async, [this, i] {
        ot_provider_wrappers_[i]->get_provider(1 - i).SendSetup();
      }));
      futs.emplace_back(std::async(std::launch::async, [this, i] {
        ot_provider_wrappers_[i]->get_provider(1 - i).ReceiveSetup();
      }));
    }
    std::for_each(std::begin(futs), std::end(futs), [](auto& f) { f.get(); });
  }

  std::vector<std::unique_ptr<MOTION::Communication::CommunicationLayer>> comm_layers_;
  std::vector<std::unique_ptr<MOTION::BaseOTProvider>> base_ot_providers_;
  std::vector<std::unique_ptr<MOTION::Crypto::MotionBaseProvider>> motion_base_providers_;
  std::vector<std::unique_ptr<ENCRYPTO::ObliviousTransfer::OTProviderManager>>
      ot_provider_wrappers_;
};

TEST_F(OTFlavorTest, FixedXCOT128) {
  const std::size_t num_ots = 1000;
  const auto correlation = ENCRYPTO::block128_t::make_random();
  const auto choice_bits = ENCRYPTO::BitVector<>::Random(num_ots);
  auto ot_sender = get_sender_provider().RegisterSendFixedXCOT128(num_ots);
  auto ot_receiver = get_receiver_provider().RegisterReceiveFixedXCOT128(num_ots);

  run_ot_extension_setup();

  ot_sender->SetCorrelation(correlation);
  ot_sender->SendMessages();

  ot_receiver->SetChoices(choice_bits);
  ot_receiver->SendCorrections();

  ot_sender->ComputeOutputs();
  ot_receiver->ComputeOutputs();
  const auto sender_output = ot_sender->GetOutputs();
  const auto receiver_output = ot_receiver->GetOutputs();

  for (std::size_t ot_i = 0; ot_i < num_ots; ++ot_i) {
    if (choice_bits.Get(ot_i)) {
      ASSERT_EQ(receiver_output[ot_i], sender_output[ot_i] ^ correlation);
    } else {
      ASSERT_EQ(receiver_output[ot_i], sender_output[ot_i]);
    }
  }
}

TEST_F(OTFlavorTest, XCOTBit) {
  const std::size_t num_ots = 1000;
  const auto correlations = ENCRYPTO::BitVector<>::Random(num_ots);
  const auto choice_bits = ENCRYPTO::BitVector<>::Random(num_ots);
  auto ot_sender = get_sender_provider().RegisterSendXCOTBit(num_ots);
  auto ot_receiver = get_receiver_provider().RegisterReceiveXCOTBit(num_ots);

  run_ot_extension_setup();

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
class ACOTTest : public OTFlavorTest {
  using is_enabled_t_ = ENCRYPTO::is_unsigned_int_t<T>;
};

using integer_types =
    ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t, __uint128_t>;
TYPED_TEST_SUITE(ACOTTest, integer_types);

TYPED_TEST(ACOTTest, ACOT) {
  const std::size_t num_ots = 1000;
  const auto correlations = MOTION::Helpers::RandomVector<TypeParam>(num_ots);
  const auto choice_bits = ENCRYPTO::BitVector<>::Random(num_ots);
  auto ot_sender = this->get_sender_provider().template RegisterSendACOT<TypeParam>(num_ots);
  auto ot_receiver = this->get_receiver_provider().template RegisterReceiveACOT<TypeParam>(num_ots);

  this->run_ot_extension_setup();

  ot_sender->SetCorrelations(correlations);
  ot_sender->SendMessages();

  ot_receiver->SetChoices(choice_bits);
  ot_receiver->SendCorrections();

  ot_sender->ComputeOutputs();
  ot_receiver->ComputeOutputs();
  const auto sender_output = ot_sender->GetOutputs();
  const auto receiver_output = ot_receiver->GetOutputs();

  EXPECT_EQ(sender_output.size(), num_ots);
  EXPECT_EQ(receiver_output.size(), num_ots);

  for (std::size_t ot_i = 0; ot_i < num_ots; ++ot_i) {
    if (choice_bits.Get(ot_i)) {
      EXPECT_EQ(receiver_output[ot_i], TypeParam(sender_output[ot_i] + correlations[ot_i]));
    } else {
      EXPECT_EQ(receiver_output[ot_i], sender_output[ot_i]);
    }
  }
}

TYPED_TEST(ACOTTest, VectorACOT) {
  const std::size_t num_ots = 100;
  const std::size_t vector_size = 100;
  const auto correlations = MOTION::Helpers::RandomVector<TypeParam>(num_ots * vector_size);
  const auto choice_bits = ENCRYPTO::BitVector<>::Random(num_ots);
  auto ot_sender =
      this->get_sender_provider().template RegisterSendACOT<TypeParam>(num_ots, vector_size);
  auto ot_receiver =
      this->get_receiver_provider().template RegisterReceiveACOT<TypeParam>(num_ots, vector_size);

  this->run_ot_extension_setup();

  ot_sender->SetCorrelations(correlations);
  ot_sender->SendMessages();

  ot_receiver->SetChoices(choice_bits);
  ot_receiver->SendCorrections();

  ot_sender->ComputeOutputs();
  ot_receiver->ComputeOutputs();
  const auto sender_output = ot_sender->GetOutputs();
  const auto receiver_output = ot_receiver->GetOutputs();

  EXPECT_EQ(sender_output.size(), num_ots * vector_size);
  EXPECT_EQ(receiver_output.size(), num_ots * vector_size);

  for (std::size_t ot_i = 0; ot_i < num_ots; ++ot_i) {
    if (choice_bits.Get(ot_i)) {
      for (std::size_t j = 0; j < vector_size; ++j) {
        EXPECT_EQ(receiver_output[ot_i * vector_size + j],
                  TypeParam(sender_output[ot_i * vector_size + j] +
                            correlations[ot_i * vector_size + j]));
      }
    } else {
      for (std::size_t j = 0; j < vector_size; ++j) {
        EXPECT_EQ(receiver_output[ot_i * vector_size + j], sender_output[ot_i * vector_size + j]);
      }
    }
  }
}

TEST_F(OTFlavorTest, GOT128) {
  const std::size_t num_ots = 1000;
  const auto sender_input = ENCRYPTO::block128_vector::make_random(2 * num_ots);
  const auto choice_bits = ENCRYPTO::BitVector<>::Random(num_ots);
  auto ot_sender = get_sender_provider().RegisterSendGOT128(num_ots);
  auto ot_receiver = get_receiver_provider().RegisterReceiveGOT128(num_ots);

  run_ot_extension_setup();

  ot_receiver->SetChoices(choice_bits);
  ot_receiver->SendCorrections();

  ot_sender->SetInputs(sender_input);
  ot_sender->SendMessages();

  ot_receiver->ComputeOutputs();
  const auto receiver_output = ot_receiver->GetOutputs();

  for (std::size_t ot_i = 0; ot_i < num_ots; ++ot_i) {
    if (choice_bits.Get(ot_i)) {
      ASSERT_EQ(receiver_output[ot_i], sender_input[2 * ot_i + 1]);
    } else {
      ASSERT_EQ(receiver_output[ot_i], sender_input[2 * ot_i]);
    }
  }
}

TEST_F(OTFlavorTest, GOTBit) {
  const std::size_t num_ots = 1000;
  const auto sender_input = ENCRYPTO::BitVector<>::Random(2 * num_ots);
  const auto choice_bits = ENCRYPTO::BitVector<>::Random(num_ots);
  auto ot_sender = get_sender_provider().RegisterSendGOTBit(num_ots);
  auto ot_receiver = get_receiver_provider().RegisterReceiveGOTBit(num_ots);

  run_ot_extension_setup();

  ot_receiver->SetChoices(choice_bits);
  ot_receiver->SendCorrections();

  ot_sender->SetInputs(sender_input);
  ot_sender->SendMessages();

  ot_receiver->ComputeOutputs();
  const auto receiver_output = ot_receiver->GetOutputs();

  for (std::size_t ot_i = 0; ot_i < num_ots; ++ot_i) {
    if (choice_bits.Get(ot_i)) {
      ASSERT_EQ(receiver_output.Get(ot_i), sender_input.Get(2 * ot_i + 1));
    } else {
      ASSERT_EQ(receiver_output.Get(ot_i), sender_input.Get(2 * ot_i));
    }
  }
}
