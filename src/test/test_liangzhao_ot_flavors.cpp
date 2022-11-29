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
#include "oblivious_transfer/ot_provider.h"
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

// template <typename T>
// class AcOtTest : public OtFlavorTest {
//   // using is_enabled_t_ = encrypto::motion::IsUnsignedInt<T>;
// };

// // using integer_types =
// //     ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t, __uint128_t>;

// using integer_types =
//     ::testing::Types<std::uint64_t>;

// TYPED_TEST_SUITE(AcOtTest, integer_types);

// TYPED_TEST(AcOtTest, AcOt) {
//   constexpr std::size_t kNumberOfOts = 1;

//   const auto correlations = encrypto::motion::RandomVector<TypeParam>(kNumberOfOts);
//   // const auto correlations = encrypto::motion::RandomVectorBoostUint<TypeParam>(kNumberOfOts);

//   const auto choice_bits = encrypto::motion::BitVector<>::SecureRandom(kNumberOfOts);

//   auto ot_sender = this->GetSenderProvider().template RegisterSendAcOt<TypeParam>(kNumberOfOts);
//   // auto ot_sender = this->GetSenderProvider().template
//   RegisterSendAcOtBoostUint<TypeParam>(kNumberOfOts);

//   auto ot_receiver =
//       this->GetReceiverProvider().template RegisterReceiveAcOt<TypeParam>(kNumberOfOts);
//   // auto ot_receiver =
//       // this->GetReceiverProvider().template
//       RegisterReceiveAcOtBoostUint<TypeParam>(kNumberOfOts);

//  this->RunOtExtensionSetup();

//   ot_sender->SetCorrelations(correlations);
//   ot_sender->SendMessages();

//       std::cout<<"ot_sender->SendMessages finish"<<std::endl;

//   ot_receiver->SetChoices(choice_bits);
//   ot_receiver->SendCorrections();

//     std::cout<<"ot_receiver->SendCorrections finish"<<std::endl;

//   ot_sender->ComputeOutputs();
//   ot_receiver->ComputeOutputs();

//   std::cout<<"ot_receiver->ComputeOutputs finish"<<std::endl;

//   const auto sender_output = ot_sender->GetOutputs();
//   const auto receiver_output = ot_receiver->GetOutputs();

//     std::cout<<"ot_receiver->GetOutputs finish"<<std::endl;

//   EXPECT_EQ(sender_output.size(), kNumberOfOts);
//   EXPECT_EQ(receiver_output.size(), kNumberOfOts);

//     std::cout<<"kNumberOfOts: "<<kNumberOfOts<<std::endl;
//     std::cout<<"sender_output.size: "<<sender_output.size()<<std::endl;
//     std::cout<<"receiver_output.size: "<<receiver_output.size()<<std::endl;

//     std::cout<<"EXPECT_EQ(receiver_output.size(), kNumberOfOts) finish"<<std::endl;

//   for (std::size_t ot_i = 0; ot_i < kNumberOfOts; ++ot_i) {

//     std::cout<<"receiver_output[ot_i]:  "<<receiver_output[ot_i]<<std::endl;
//     std::cout<<"sender_output[ot_i]:  "<<sender_output[ot_i]<<std::endl;
//     std::cout<<"correlations[ot_i]:  "<<correlations[ot_i]<<std::endl;

//     std::cout<<"choice_bits.Get(ot_i):  "<<choice_bits.Get(ot_i)<<std::endl;

//     if (choice_bits.Get(ot_i)) {

//     std::cout<<"if (choice_bits.Get(ot_i))"<<std::endl;

// std::cout<<"sender_output[ot_i] + correlations[ot_i]):  "<<sender_output[ot_i] +
// correlations[ot_i]<<std::endl;

//       EXPECT_EQ(receiver_output[ot_i], TypeParam(sender_output[ot_i] + correlations[ot_i]));
//     std::cout<<"EXPECT_EQ(receiver_output[ot_i], TypeParam(sender_output[ot_i] +
//     correlations[ot_i])) finish"<<std::endl; } else {
//  std::cout<<"else ~(choice_bits.Get(ot_i))"<<std::endl;

//       EXPECT_EQ(receiver_output[ot_i], sender_output[ot_i]);
//     std::cout<<"EXPECT_EQ(receiver_output[ot_i], sender_output[ot_i]) finish"<<std::endl;
//     }
//   }
// }

// TYPED_TEST(AcOtTest, VectorAcOt) {
//   constexpr std::size_t kNumberOfOts = 100;
//   constexpr std::size_t kVectorSize = 100;
//   const auto correlations = encrypto::motion::RandomVector<TypeParam>(kNumberOfOts *
//   kVectorSize); const auto choice_bits =
//   encrypto::motion::BitVector<>::SecureRandom(kNumberOfOts); auto ot_sender =
//       this->GetSenderProvider().template RegisterSendAcOt<TypeParam>(kNumberOfOts, kVectorSize);
//   auto ot_receiver = this->GetReceiverProvider().template RegisterReceiveAcOt<TypeParam>(
//       kNumberOfOts, kVectorSize);

//   this->RunOtExtensionSetup();

//   ot_sender->SetCorrelations(correlations);
//   ot_sender->SendMessages();

//   ot_receiver->SetChoices(choice_bits);
//   ot_receiver->SendCorrections();

//   ot_sender->ComputeOutputs();
//   ot_receiver->ComputeOutputs();
//   const auto sender_output = ot_sender->GetOutputs();
//   const auto receiver_output = ot_receiver->GetOutputs();

//   EXPECT_EQ(sender_output.size(), kNumberOfOts * kVectorSize);
//   EXPECT_EQ(receiver_output.size(), kNumberOfOts * kVectorSize);

//   for (std::size_t ot_i = 0; ot_i < kNumberOfOts; ++ot_i) {
//     if (choice_bits.Get(ot_i)) {
//       for (std::size_t j = 0; j < kVectorSize; ++j) {
//         EXPECT_EQ(receiver_output[ot_i * kVectorSize + j],
//                   TypeParam(sender_output[ot_i * kVectorSize + j] +
//                             correlations[ot_i * kVectorSize + j]));
//       }
//     } else {
//       for (std::size_t j = 0; j < kVectorSize; ++j) {
//         EXPECT_EQ(receiver_output[ot_i * kVectorSize + j], sender_output[ot_i * kVectorSize +
//         j]);
//       }
//     }
//   }
// }

// ============================================================

template <typename T>
class AcOtBoostUintTest : public OtFlavorTest {
  // using is_enabled_t_ = encrypto::motion::IsUnsignedInt<T>;
};

// using integer_types =
//     ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t, __uint128_t>;

using boost_integer_types = ::testing::Types<bm::uint256_t>;

TYPED_TEST_SUITE(AcOtBoostUintTest, boost_integer_types);

TYPED_TEST(AcOtBoostUintTest, AcOtBoostUint) {
  // TODO: increate this value
  constexpr std::size_t kNumberOfOts = 100;

  // const auto correlations = encrypto::motion::RandomVector<TypeParam>(kNumberOfOts);
  const auto correlations = encrypto::motion::RandomVectorBoostUint<TypeParam>(kNumberOfOts);

  // std::cout << "correlations.size: " << correlations.size() << std::endl;

  // for (std::size_t i = 0; i < correlations.size(); i++) {
  //   std::cout << "correlations[i]: " << correlations[i] << std::endl;
  // }

  const auto choice_bits = encrypto::motion::BitVector<>::SecureRandom(kNumberOfOts);

  // auto ot_sender = this->GetSenderProvider().template RegisterSendAcOt<TypeParam>(kNumberOfOts);
  auto ot_sender = this->GetSenderProvider().RegisterSendAcOtBoostUint(
      kNumberOfOts, std::numeric_limits<TypeParam>::digits);

  // auto ot_receiver =
  //     this->GetReceiverProvider().template RegisterReceiveAcOt<TypeParam>(kNumberOfOts);
  auto ot_receiver = this->GetReceiverProvider().RegisterReceiveAcOtBoostUint(
      kNumberOfOts, std::numeric_limits<TypeParam>::digits);

  auto casted_ot_sender{
      dynamic_cast<encrypto::motion::AcOtSenderBoostUint<TypeParam>*>(ot_sender.get())};
  auto casted_ot_receiver{
      dynamic_cast<encrypto::motion::AcOtReceiverBoostUint<TypeParam>*>(ot_receiver.get())};

  this->RunOtExtensionSetup();

  casted_ot_sender->SetCorrelations(correlations);
  casted_ot_sender->SendMessages();

  // std::cout << "casted_ot_sender->SendMessages finish" << std::endl;

  casted_ot_receiver->SetChoices(choice_bits);
  casted_ot_receiver->SendCorrections();

  // std::cout << "ot_receiver->SendCorrections finish" << std::endl;

  casted_ot_sender->ComputeOutputs();
  casted_ot_receiver->ComputeOutputs();

  // std::cout << "ot_receiver->ComputeOutputs finish" << std::endl;

  const auto sender_output = casted_ot_sender->GetOutputs();
  const auto receiver_output = casted_ot_receiver->GetOutputs();

  // std::cout << "ot_receiver->GetOutputs finish" << std::endl;

  EXPECT_EQ(sender_output.size(), kNumberOfOts);
  EXPECT_EQ(receiver_output.size(), kNumberOfOts);

  // std::cout<<"kNumberOfOts: "<<kNumberOfOts<<std::endl;
  // std::cout<<"sender_output.size: "<<sender_output.size()<<std::endl;
  // std::cout<<"receiver_output.size: "<<receiver_output.size()<<std::endl;

  // std::cout<<"EXPECT_EQ(receiver_output.size(), kNumberOfOts) finish"<<std::endl;

  for (std::size_t ot_i = 0; ot_i < kNumberOfOts; ++ot_i) {
    // std::cout << "receiver_output[ot_i]:  " << receiver_output[ot_i] << std::endl;
    // std::cout << "sender_output[ot_i]:  " << sender_output[ot_i] << std::endl;
    // std::cout << "correlations[ot_i]:  " << correlations[ot_i] << std::endl;

    // std::cout << "choice_bits.Get(ot_i):  " << choice_bits.Get(ot_i) << std::endl;

    if (choice_bits.Get(ot_i)) {
      // std::cout << "if (choice_bits.Get(ot_i))" << std::endl;

      // std::cout << "sender_output[ot_i] + correlations[ot_i]):  "
      //           << sender_output[ot_i] + correlations[ot_i] << std::endl;

      EXPECT_EQ(receiver_output[ot_i], TypeParam(sender_output[ot_i] + correlations[ot_i]));
      // std::cout << "EXPECT_EQ(receiver_output[ot_i], TypeParam(sender_output[ot_i] + "
      //              "correlations[ot_i])) finish"
      //           << std::endl;
    } else {
      // std::cout << "else ~(choice_bits.Get(ot_i))" << std::endl;

      EXPECT_EQ(receiver_output[ot_i], sender_output[ot_i]);
      // std::cout << "EXPECT_EQ(receiver_output[ot_i], sender_output[ot_i]) finish" << std::endl;
    }
  }
}

TYPED_TEST(AcOtBoostUintTest, VectorAcOtBoostUint) {
  constexpr std::size_t kNumberOfOts = 100;
  constexpr std::size_t kVectorSize = 100;
  const auto correlations = encrypto::motion::RandomVectorBoostUint<TypeParam>(kNumberOfOts * kVectorSize);
  const auto choice_bits = encrypto::motion::BitVector<>::SecureRandom(kNumberOfOts);
  auto ot_sender =
      this->GetSenderProvider().RegisterSendAcOtBoostUint(kNumberOfOts, std::numeric_limits<TypeParam>::digits, kVectorSize);
  auto ot_receiver = this->GetReceiverProvider().RegisterReceiveAcOtBoostUint(
      kNumberOfOts, std::numeric_limits<TypeParam>::digits, kVectorSize);

  auto casted_ot_sender{dynamic_cast<encrypto::motion::AcOtSenderBoostUint<TypeParam>*>(ot_sender.get())};
  auto casted_ot_receiver{
      dynamic_cast<encrypto::motion::AcOtReceiverBoostUint<TypeParam>*>(ot_receiver.get())};

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