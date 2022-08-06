// MIT License
//
// Copyright (c) 2021 Arianne Roselina Prananto
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

#include "gtest/gtest.h"

#include "test_constants.h"

#include "base/backend.h"
#include "base/motion_base_provider.h"
#include "base/party.h"
#include "data_storage/base_ot_data.h"
#include "oblivious_transfer/1_out_of_n/kk13_ot_flavors.h"

namespace {
using namespace encrypto::motion;

template <typename T>
using vvv = std::vector<std::vector<std::vector<T>>>;

using Kk13ObliviousTransferParametersType =
    std::tuple<std::size_t, std::size_t, std::size_t, std::size_t, std::size_t>;

class Kk13ObliviousTransferTest
    : public testing::TestWithParam<Kk13ObliviousTransferParametersType> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(number_of_parties_, number_of_parallel_ots_, number_of_ots_, number_of_messages_,
             bitlength_) = parameters;
  }
  void TearDown() override {
    number_of_parties_ = number_of_parallel_ots_ = number_of_ots_ = number_of_messages_ =
        bitlength_ = 0;
  }

 protected:
  std::size_t number_of_parties_ = 0, number_of_parallel_ots_ = 0, number_of_ots_ = 0,
              number_of_messages_ = 0, bitlength_ = 0;
};

TEST_P(Kk13ObliviousTransferTest, Random1ooNKk13OtsFromKk13OtExtension) {
  try {
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties_, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    }
    std::vector<std::thread> threads(number_of_parties_);

    // my id, other id, data
    vvv<std::unique_ptr<encrypto::motion::RKk13OtSender>> sender_ot(number_of_parties_);
    vvv<std::unique_ptr<encrypto::motion::RKk13OtReceiver>> receiver_ot(number_of_parties_);
    vvv<std::span<const encrypto::motion::BitVector<>>> sender_messages(number_of_parties_),
        receiver_messages(number_of_parties_);
    vvv<std::vector<std::uint8_t>> choices(number_of_parties_);

    for (auto i = 0ull; i < number_of_parties_; ++i) {
      sender_ot[i].resize(number_of_parties_);
      receiver_ot[i].resize(number_of_parties_);
      sender_messages[i].resize(number_of_parties_);
      receiver_messages[i].resize(number_of_parties_);
      choices[i].resize(number_of_parties_);
    }

    for (auto i = 0ull; i < number_of_parties_; ++i) {
      for (auto j = 0ull; j < number_of_parties_; ++j) {
        sender_ot[i][j].resize(number_of_parallel_ots_);
        receiver_ot[i][j].resize(number_of_parallel_ots_);
        sender_messages[i][j].resize(number_of_parallel_ots_);
        receiver_messages[i][j].resize(number_of_parallel_ots_);
        choices[i][j].resize(number_of_parallel_ots_);
      }
    }

    for (auto i = 0u; i < number_of_parties_; ++i) {
      threads.at(i) = std::thread([&sender_ot, &receiver_ot, &motion_parties, i, this]() {
        for (auto j = 0u; j < number_of_parties_; ++j) {
          if (i != j) {
            for (auto k = 0ull; k < number_of_parallel_ots_; ++k) {
              auto& ot_provider = motion_parties[i]->GetBackend()->GetKk13OtProvider(j);
              sender_ot[i][j][k] =
                  ot_provider.RegisterSendROt(number_of_ots_, bitlength_, number_of_messages_);
              receiver_ot[i][j][k] =
                  ot_provider.RegisterReceiveROt(number_of_ots_, bitlength_, number_of_messages_);
            }
          }
        }
        motion_parties[i]->Run();
        motion_parties[i]->Finish();
      });
    }

    for (auto& t : threads) {
      t.join();
    }

    for (auto i = 0u; i < number_of_parties_; ++i) {
      for (auto j = 0u; j < number_of_parties_; ++j) {
        if (i != j) {
          for (auto k = 0ull; k < number_of_parallel_ots_; ++k) {
            sender_ot[i][j][k]->ComputeOutputs();
            sender_messages[i][j][k] = sender_ot[i][j][k]->GetOutputs();
            receiver_ot[j][i][k]->ComputeOutputs();
            choices[j][i][k] = receiver_ot[j][i][k]->GetChoices();
            receiver_messages[j][i][k] = receiver_ot[j][i][k]->GetOutputs();
            for (auto l = 0ull; l < number_of_ots_; ++l) {
              auto c = choices[j][i][k][l];
              ASSERT_EQ(receiver_messages[j][i][k][l],
                        sender_messages[i][j][k][l].Subset(c * bitlength_, (c + 1) * bitlength_));
            }
          }
        }
      }
    }
  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(Kk13ObliviousTransferTest, General1ooNKk13OtsFromKk13OtExtension) {
    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties_, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    }
    std::vector<std::thread> threads(number_of_parties_);

    // my id, other id, data
    vvv<std::unique_ptr<GKk13OtSender>> sender_ot(number_of_parties_);
    vvv<std::unique_ptr<GKk13OtReceiver>> receiver_ot(number_of_parties_);
    vvv<std::vector<BitVector<>>> sender_messages(number_of_parties_);
    vvv<std::span<const BitVector<>>> receiver_messages(number_of_parties_);
    vvv<std::vector<std::uint8_t>> choices(number_of_parties_);

    for (auto i = 0ull; i < number_of_parties_; ++i) {
      sender_ot[i].resize(number_of_parties_);
      receiver_ot[i].resize(number_of_parties_);
      sender_messages[i].resize(number_of_parties_);
      receiver_messages[i].resize(number_of_parties_);
      choices[i].resize(number_of_parties_);
    }

    for (auto i = 0ull; i < number_of_parties_; ++i) {
      for (auto j = 0ull; j < number_of_parties_; ++j) {
        sender_ot[i][j].resize(number_of_parallel_ots_);
        receiver_ot[i][j].resize(number_of_parallel_ots_);
        sender_messages[i][j].resize(number_of_parallel_ots_);
        receiver_messages[i][j].resize(number_of_parallel_ots_);
        choices[i][j].resize(number_of_parallel_ots_);
      }
    }

    for (auto i = 0ull; i < number_of_parties_; ++i) {
      for (auto j = 0ull; j < number_of_parties_; ++j) {
        if (i != j) {
          for (auto k = 0ull; k < number_of_parallel_ots_; ++k) {
            for (auto l = 0ull; l < number_of_ots_; ++l) {
              sender_messages[i][j][k].push_back(
                  BitVector<>::SecureRandom(bitlength_ * number_of_messages_));
              std::mt19937 gen(std::random_device{}());
              std::uniform_int_distribution<std::uint32_t> dist(0, number_of_messages_ - 1);
              choices[i][j][k].push_back(dist(gen));
            }
          }
        }
      }
    }

    for (auto i = 0u; i < number_of_parties_; ++i) {
      threads.at(i) = std::thread([&sender_messages, &choices, &sender_ot, &receiver_ot,
                                   &motion_parties, i, this]() {
        for (auto j = 0u; j < number_of_parties_; ++j) {
          if (i != j) {
            for (auto k = 0ull; k < number_of_parallel_ots_; ++k) {
              auto& ot_provider = motion_parties[i]->GetBackend()->GetKk13OtProvider(j);
              sender_ot[i][j][k] =
                  ot_provider.RegisterSendGOt(number_of_ots_, bitlength_, number_of_messages_);
              receiver_ot[i][j][k] =
                  ot_provider.RegisterReceiveGOt(number_of_ots_, bitlength_, number_of_messages_);
            }
          }
        }
        motion_parties[i]->GetBackend()->RunPreprocessing();

        for (auto j = 0u; j < number_of_parties_; ++j) {
          if (i != j) {
            for (auto k = 0ull; k < number_of_parallel_ots_; ++k) {
              receiver_ot[i][j][k]->SetChoices(choices[i][j][k]);
              receiver_ot[i][j][k]->SendCorrections();
              sender_ot[i][j][k]->SetInputs(sender_messages[i][j][k]);
              sender_ot[i][j][k]->SendMessages();
              receiver_ot[i][j][k]->ComputeOutputs();
            }
          }
        }
        motion_parties[i]->Finish();
      });
    }

    for (auto& t : threads) {
      t.join();
    }

    for (auto i = 0u; i < number_of_parties_; ++i) {
      for (auto j = 0u; j < number_of_parties_; ++j) {
        if (i != j) {
          for (auto k = 0ull; k < number_of_parallel_ots_; ++k) {
            receiver_messages[j][i][k] = receiver_ot[j][i][k]->GetOutputs();
            for (auto l = 0ull; l < number_of_ots_; ++l) {
              auto c = choices[j][i][k][l];
              ASSERT_EQ(receiver_messages[j][i][k][l],
                        sender_messages[i][j][k][l].Subset(c * bitlength_, (c + 1) * bitlength_));
            }
          }
        }
      }
    }
}

using Kk13OtParallelParametersType = std::tuple<std::size_t, std::size_t>;

class Kk13OtParallelTest : public testing::TestWithParam<Kk13OtParallelParametersType> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(number_of_parallel_ots_, number_of_ots_) = parameters;
  }
  void TearDown() override { number_of_parallel_ots_ = number_of_ots_ = 0; }

 protected:
  std::size_t number_of_parallel_ots_ = 0, number_of_ots_ = 0;
};

TEST_P(Kk13OtParallelTest, GKk13OtParallel) {
  try {
    auto number_of_parties = 2u;
    std::vector<std::thread> threads(number_of_parties);

    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    }

    // my id, other id, data
    std::vector<std::unique_ptr<GKk13OtSender>> sender_ot(number_of_parallel_ots_);
    std::vector<std::unique_ptr<GKk13OtReceiver>> receiver_ot(number_of_parallel_ots_);
    std::vector<std::vector<BitVector<>>> sender_messages(number_of_parallel_ots_);
    std::vector<std::span<const BitVector<>>> receiver_messages(number_of_parallel_ots_);
    std::vector<std::vector<std::uint8_t>> choices(number_of_parallel_ots_);
    std::vector<std::size_t> number_of_messages(number_of_parallel_ots_),
        bitlengths(number_of_parallel_ots_);

    // set number of messages to {2,4,8,...} and bitlengths to {1,2,3,...}
    for (auto i = 0u; i < number_of_parallel_ots_; i++) {
      number_of_messages.at(i) = pow(2, i + 1);
      bitlengths.at(i) = i + 1;
    }

    for (auto i = 0u; i < number_of_parallel_ots_; ++i) {
      for (auto j = 0u; j < number_of_ots_; ++j) {
        sender_messages[i].push_back(
            BitVector<>::SecureRandom(bitlengths[i] * number_of_messages[i]));
        std::mt19937 gen(std::random_device{}());
        std::uniform_int_distribution<std::uint32_t> dist(0, number_of_messages[i] - 1);
        choices[i].push_back(dist(gen));
      }
    }

    for (auto i = 0u; i < number_of_parties; ++i) {
      threads.at(i) = std::thread([&motion_parties, &number_of_messages, &bitlengths, &sender_ot,
                                   &receiver_ot, i, this]() {
        auto& ot_provider = motion_parties[i]->GetBackend()->GetKk13OtProvider(1 - i);

        for (auto j = 0u; j < number_of_parallel_ots_; ++j) {
          if (i == 0) {
            sender_ot[j] =
                ot_provider.RegisterSendGOt(number_of_ots_, bitlengths[j], number_of_messages[j]);
          } else {
            receiver_ot[j] = ot_provider.RegisterReceiveGOt(number_of_ots_, bitlengths[j],
                                                            number_of_messages[j]);
          }
        }
        motion_parties[i]->GetBackend()->RunPreprocessing();
      });
    }

    for (auto& t : threads) {
      t.join();
    }

    for (auto i = 0u; i < number_of_parallel_ots_; ++i) {
      receiver_ot[i]->WaitSetup();
      receiver_ot[i]->SetChoices(choices[i]);
      receiver_ot[i]->SendCorrections();

      sender_ot[i]->WaitSetup();
      sender_ot[i]->SetInputs(sender_messages[i]);
      sender_ot[i]->SendMessages();

      receiver_ot[i]->ComputeOutputs();
      receiver_messages[i] = receiver_ot[i]->GetOutputs();

      for (auto j = 0u; j < number_of_ots_; ++j) {
        auto c = choices[i][j];
        ASSERT_EQ(receiver_messages[i][j],
                  sender_messages[i][j].Subset(c * bitlengths[i], (c + 1) * bitlengths[i]));
      }
    }

    for (auto i = 0u; i < number_of_parties; ++i) {
      threads.at(i) = std::thread([&motion_parties, i]() { motion_parties.at(i)->Finish(); });
    }
    for (auto& t : threads) {
      t.join();
    }

  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

TEST_P(Kk13OtParallelTest, RKk13OtParallel) {
  try {
    auto number_of_parties = 2u;
    std::vector<std::thread> threads(number_of_parties);

    std::vector<PartyPointer> motion_parties(
        std::move(MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    }

    // my id, other id, data
    std::vector<std::unique_ptr<RKk13OtSender>> sender_ot(number_of_parallel_ots_);
    std::vector<std::unique_ptr<RKk13OtReceiver>> receiver_ot(number_of_parallel_ots_);
    std::vector<std::span<const BitVector<>>> sender_messages(number_of_parallel_ots_);
    std::vector<std::span<const BitVector<>>> receiver_messages(number_of_parallel_ots_);
    std::vector<std::vector<std::uint8_t>> choices(number_of_parallel_ots_);
    std::vector<std::size_t> number_of_messages(number_of_parallel_ots_),
        bitlengths(number_of_parallel_ots_);

    // set number of messages to {2,4,8,...} and bitlengths to {1,2,3,...}
    for (auto i = 0u; i < number_of_parallel_ots_; i++) {
      number_of_messages.at(i) = pow(2, i + 1);
      bitlengths.at(i) = i + 1;
    }

    for (auto i = 0u; i < number_of_parties; ++i) {
      threads.at(i) = std::thread([&motion_parties, &number_of_messages, &bitlengths, &sender_ot,
                                   &receiver_ot, i, this]() {
        auto& ot_provider = motion_parties[i]->GetBackend()->GetKk13OtProvider(1 - i);

        for (auto j = 0u; j < number_of_parallel_ots_; ++j) {
          if (i == 0) {
            sender_ot[j] =
                ot_provider.RegisterSendROt(number_of_ots_, bitlengths[j], number_of_messages[j]);
          } else {
            receiver_ot[j] = ot_provider.RegisterReceiveROt(number_of_ots_, bitlengths[j],
                                                            number_of_messages[j]);
          }
        }
        motion_parties[i]->GetBackend()->RunPreprocessing();
      });
    }

    for (auto& t : threads) {
      t.join();
    }

    for (auto i = 0u; i < number_of_parallel_ots_; ++i) {
      sender_ot[i]->ComputeOutputs();
      sender_messages[i] = sender_ot[i]->GetOutputs();
      receiver_ot[i]->ComputeOutputs();
      choices[i] = receiver_ot[i]->GetChoices();
      receiver_messages[i] = receiver_ot[i]->GetOutputs();

      for (auto j = 0u; j < number_of_ots_; ++j) {
        auto c = choices[i][j];
        ASSERT_EQ(receiver_messages[i][j],
                  sender_messages[i][j].Subset(c * bitlengths[i], (c + 1) * bitlengths[i]));
      }
    }

    for (auto i = 0u; i < number_of_parties; ++i) {
      threads.at(i) = std::thread([&motion_parties, i]() { motion_parties.at(i)->Finish(); });
    }
    for (auto& t : threads) {
      t.join();
    }

  } catch (std::exception& e) {
    std::cerr << e.what() << std::endl;
  }
}

constexpr std::array<std::size_t, 2> kKK13ObliviousTransferNumberOfParties{2, 3};
constexpr std::array<std::size_t, 2> kKK13ObliviousTransferNumberOfParallelOts{5, 8};
constexpr std::array<std::size_t, 2> kKK13ObliviousTransferNumberOfOts{5, 10};
constexpr std::array<std::size_t, 2> kKK13ObliviousTransferNumberOfMessages{2, 10};
constexpr std::array<std::size_t, 2> kKK13ObliviousTransferBitlength{10, 50};

INSTANTIATE_TEST_SUITE_P(
    Kk13ObliviousTransferTestSuite, Kk13ObliviousTransferTest,
    testing::Combine(testing::ValuesIn(kKK13ObliviousTransferNumberOfParties),
                     testing::ValuesIn(kKK13ObliviousTransferNumberOfParallelOts),
                     testing::ValuesIn(kKK13ObliviousTransferNumberOfOts),
                     testing::ValuesIn(kKK13ObliviousTransferNumberOfMessages),
                     testing::ValuesIn(kKK13ObliviousTransferBitlength)),
    [](const testing::TestParamInfo<Kk13ObliviousTransferTest::ParamType>& info) {
      std::string name =
          fmt::format("{}_Parties_{}_Parallel_{}_Ots_with_{}_Messages_{}_Bitlength",
                      std::get<0>(info.param), std::get<1>(info.param), std::get<2>(info.param),
                      std::get<3>(info.param), std::get<4>(info.param));
      return name;
    });

INSTANTIATE_TEST_SUITE_P(
    Kk13ObliviousTransferTestSuite, Kk13OtParallelTest,
    testing::Combine(testing::ValuesIn(kKK13ObliviousTransferNumberOfParallelOts),
                     testing::ValuesIn(kKK13ObliviousTransferNumberOfOts)),
    [](const testing::TestParamInfo<Kk13OtParallelTest::ParamType>& info) {
      std::string name =
          fmt::format("{}_Parallel_{}_Ots_with_varying_Messages_and_Bitlength",
                      std::get<0>(info.param), std::get<1>(info.param));
      return name;
    });

}  // namespace