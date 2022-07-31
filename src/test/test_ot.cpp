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

#include "gtest/gtest.h"

#include "test_constants.h"

#include "base/backend.h"
#include "base/motion_base_provider.h"
#include "base/party.h"
#include "data_storage/base_ot_data.h"
#include "oblivious_transfer/base_ots/base_ot_provider.h"
#include "oblivious_transfer/ot_flavors.h"

namespace {

constexpr auto kNumberOfPartiesList = {2u, 3u};

template <typename T>
using vvv = std::vector<std::vector<std::vector<T>>>;

TEST(ObliviousTransfer, Random1oo2OtsFromOtExtension) {
  constexpr std::size_t kNumberOfOts{10};
  for (auto number_of_parties : kNumberOfPartiesList) {
    std::mt19937_64 random(0);
    std::uniform_int_distribution<std::size_t> distribution_bitlength(1, 1000);
    std::uniform_int_distribution<std::size_t> distribution_batch_size(1, 10);
    std::array<std::size_t, kNumberOfOts> bitlength, ots_in_batch;
    for (auto i = 0ull; i < bitlength.size(); ++i) {
      bitlength.at(i) = distribution_bitlength(random);
      ots_in_batch.at(i) = distribution_batch_size(random);
    }

    bitlength.at(bitlength.size() - 1) = 1;

    std::vector<encrypto::motion::PartyPointer> motion_parties(
        std::move(encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    }
    std::vector<std::thread> threads(number_of_parties);

    // my id, other id, data
    vvv<std::unique_ptr<encrypto::motion::ROtSender>> sender_ot(number_of_parties);
    vvv<std::unique_ptr<encrypto::motion::ROtReceiver>> receiver_ot(number_of_parties);
    vvv<std::span<const encrypto::motion::BitVector<>>> sender_messages(number_of_parties),
        receiver_messages(number_of_parties);
    vvv<encrypto::motion::BitVector<>> choices(number_of_parties);

    for (auto i = 0ull; i < number_of_parties; ++i) {
      sender_ot.at(i).resize(number_of_parties);
      receiver_ot.at(i).resize(number_of_parties);
      sender_messages.at(i).resize(number_of_parties);
      receiver_messages.at(i).resize(number_of_parties);
      choices.at(i).resize(number_of_parties);
    }

    for (auto i = 0u; i < motion_parties.size(); ++i) {
      threads.at(i) =
          std::thread([&bitlength, &ots_in_batch, &sender_ot, &receiver_ot, &motion_parties, i]() {
            motion_parties.at(i)->GetBackend()->GetBaseProvider().Setup();
            for (auto j = 0u; j < motion_parties.size(); ++j) {
              if (i != j) {
                auto& ot_provider = motion_parties.at(i)->GetBackend()->GetOtProvider(j);
                for (auto k = 0ull; k < kNumberOfOts; ++k) {
                  sender_ot.at(i).at(j).push_back(
                      ot_provider.RegisterSendROt(ots_in_batch.at(k), bitlength.at(k)));
                  receiver_ot.at(i).at(j).push_back(
                      ot_provider.RegisterReceiveROt(ots_in_batch.at(k), bitlength.at(k)));
                }
              }
            }
            for (std::size_t party_id = 0; party_id < motion_parties.size(); ++party_id) {
              if (party_id != i) {
                motion_parties.at(i)->GetBackend()->GetOtProvider(party_id).PreSetup();
              }
            }
            motion_parties.at(i)->GetBackend()->GetBaseOtProvider().PreSetup();
            motion_parties.at(i)->GetBackend()->Synchronize();
            motion_parties.at(i)->GetBackend()->GetBaseOtProvider().ComputeBaseOts();
            motion_parties.at(i)->GetBackend()->OtExtensionSetup();
            motion_parties.at(i)->Finish();
          });
    }

    for (auto& t : threads) {
      t.join();
    }

    for (auto i = 0u; i < motion_parties.size(); ++i) {
      for (auto j = 0u; j < motion_parties.size(); ++j) {
        if (i != j) {
          for (auto k = 0ull; k < kNumberOfOts; ++k) {
            sender_ot.at(i).at(j).at(k)->ComputeOutputs();
            sender_messages.at(i).at(j).push_back(sender_ot.at(i).at(j).at(k)->GetOutputs());
            receiver_ot.at(j).at(i).at(k)->ComputeOutputs();
            choices.at(j).at(i).push_back(receiver_ot.at(j).at(i).at(k)->GetChoices());
            receiver_messages.at(j).at(i).push_back(receiver_ot.at(j).at(i).at(k)->GetOutputs());

            for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
              if (!choices.at(j).at(i).at(k)[l]) {
                ASSERT_EQ(receiver_messages.at(j).at(i).at(k)[l],
                          sender_messages.at(i).at(j).at(k)[l].Subset(0, bitlength.at(k)));
              } else {
                ASSERT_EQ(receiver_messages.at(j).at(i).at(k)[l],
                          sender_messages.at(i).at(j).at(k)[l].Subset(bitlength.at(k),
                                                                      2 * bitlength.at(k)));
              }
            }
          }
        }
      }
    }
  }
}

TEST(ObliviousTransfer, General1oo2OtsFromOtExtension) {
  constexpr std::size_t kNumberOfOts{10};
  for (auto number_of_parties : kNumberOfPartiesList) {
    std::mt19937_64 random(0);
    std::uniform_int_distribution<std::size_t> distribution_bitlength(1, 1000);
    std::uniform_int_distribution<std::size_t> distribution_batch_size(1, 10);
    std::array<std::size_t, kNumberOfOts> bitlength, ots_in_batch;
    for (auto i = 0ull; i < bitlength.size(); ++i) {
      bitlength.at(i) = distribution_bitlength(random);
      ots_in_batch.at(i) = distribution_batch_size(random);
    }

    bitlength.at(bitlength.size() - 1) = 1;

    std::vector<encrypto::motion::PartyPointer> motion_parties(
        std::move(encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    }
    std::vector<std::thread> threads(number_of_parties);

    // my id, other id, data
    vvv<std::unique_ptr<encrypto::motion::GOtSender>> sender_ot(number_of_parties);
    vvv<std::unique_ptr<encrypto::motion::GOtReceiver>> receiver_ot(number_of_parties);
    vvv<std::vector<encrypto::motion::BitVector<>>> sender_messages(number_of_parties);
    vvv<std::span<const encrypto::motion::BitVector<>>> receiver_messages(number_of_parties);
    vvv<encrypto::motion::BitVector<>> choices(number_of_parties);

    for (auto i = 0ull; i < number_of_parties; ++i) {
      sender_ot.at(i).resize(number_of_parties);
      receiver_ot.at(i).resize(number_of_parties);
      sender_messages.at(i).resize(number_of_parties);
      receiver_messages.at(i).resize(number_of_parties);
      choices.at(i).resize(number_of_parties);
    }

    for (auto i = 0ull; i < number_of_parties; ++i) {
      for (auto j = 0ull; j < number_of_parties; ++j) {
        if (i != j) {
          for (auto k = 0ull; k < kNumberOfOts; ++k) {
            sender_messages.at(i).at(j).resize(kNumberOfOts);
            receiver_messages.at(i).at(j).resize(kNumberOfOts);
            choices.at(i).at(j).resize(kNumberOfOts);
            for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
              sender_messages.at(i).at(j).at(k).push_back(
                  encrypto::motion::BitVector<>::SecureRandom(bitlength.at(k) * 2));
            }
            choices.at(i).at(j).at(k) =
                encrypto::motion::BitVector<>::SecureRandom(ots_in_batch.at(k));
          }
        }
      }
    }

    for (auto i = 0u; i < motion_parties.size(); ++i) {
      threads.at(i) =
          std::thread([&sender_messages, &receiver_messages, &choices, &bitlength, &ots_in_batch,
                       &sender_ot, &receiver_ot, &motion_parties, i, number_of_parties]() {
            motion_parties.at(i)->GetBackend()->GetBaseProvider().Setup();
            for (auto j = 0u; j < motion_parties.size(); ++j) {
              if (i != j) {
                auto& ot_provider = motion_parties.at(i)->GetBackend()->GetOtProvider(j);
                for (auto k = 0ull; k < kNumberOfOts; ++k) {
                  sender_ot.at(i).at(j).push_back(
                      ot_provider.RegisterSendGOt(ots_in_batch.at(k), bitlength.at(k)));
                  receiver_ot.at(i).at(j).push_back(
                      ot_provider.RegisterReceiveGOt(ots_in_batch.at(k), bitlength.at(k)));
                }
              }
            }
            for (std::size_t party_id = 0; party_id < motion_parties.size(); ++party_id) {
              if (party_id != i) {
                motion_parties.at(i)->GetBackend()->GetOtProvider(party_id).PreSetup();
              }
            }
            motion_parties.at(i)->GetBackend()->GetBaseOtProvider().PreSetup();
            motion_parties.at(i)->GetBackend()->Synchronize();
            motion_parties.at(i)->GetBackend()->GetBaseOtProvider().ComputeBaseOts();
            motion_parties.at(i)->GetBackend()->OtExtensionSetup();

            for (auto j = 0u; j < motion_parties.size(); ++j) {
              if (i != j) {
                for (auto k = 0ull; k < kNumberOfOts; ++k) {
                  receiver_ot.at(i).at(j).at(k)->SetChoices(choices.at(i).at(j).at(k));
                  receiver_ot.at(i).at(j).at(k)->SendCorrections();
                  sender_ot.at(i).at(j).at(k)->SetInputs(sender_messages.at(i).at(j).at(k));
                  sender_ot.at(i).at(j).at(k)->SendMessages();
                }
              }
            }
            motion_parties.at(i)->Finish();
          });
    }

    for (auto& t : threads) {
      t.join();
    }

    for (auto i = 0u; i < motion_parties.size(); ++i) {
      for (auto j = 0u; j < motion_parties.size(); ++j) {
        if (i != j) {
          for (auto k = 0ull; k < kNumberOfOts; ++k) {
            receiver_ot.at(j).at(i).at(k)->WaitSetup();
            receiver_ot.at(j).at(i).at(k)->ComputeOutputs();
            receiver_messages.at(j).at(i).at(k) = receiver_ot.at(j).at(i).at(k)->GetOutputs();
            for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
              if (!choices.at(j).at(i).at(k)[l]) {
                ASSERT_EQ(receiver_messages.at(j).at(i).at(k)[l],
                          sender_messages.at(i).at(j).at(k).at(l).Subset(0, bitlength.at(k)));
              } else {
                ASSERT_EQ(receiver_messages.at(j).at(i).at(k)[l],
                          sender_messages.at(i).at(j).at(k).at(l).Subset(bitlength.at(k),
                                                                         2 * bitlength.at(k)));
              }
            }
          }
        }
      }
    }
  }
}

TEST(ObliviousTransfer, XorCorrelated1oo2OtsFromOtExtension) {
  constexpr std::size_t kNumberOfOts{10};
  for (auto number_of_parties : kNumberOfPartiesList) {
    std::mt19937_64 random(0);
    std::uniform_int_distribution<std::size_t> distribution_bitlength(1, 1000);
    std::uniform_int_distribution<std::size_t> distribution_batch_size(1, 10);
    std::array<std::size_t, kNumberOfOts> bitlength, ots_in_batch;
    for (auto i = 0ull; i < bitlength.size(); ++i) {
      bitlength.at(i) = distribution_bitlength(random);
      ots_in_batch.at(i) = distribution_batch_size(random);
    }

    bitlength.at(bitlength.size() - 1) = 1;

    std::vector<encrypto::motion::PartyPointer> motion_parties(
        std::move(encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset)));
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    }
    std::vector<std::thread> threads(number_of_parties);
    // my id, other id, data
    vvv<std::unique_ptr<encrypto::motion::XcOtSender>> sender_ot(number_of_parties);
    vvv<std::unique_ptr<encrypto::motion::XcOtReceiver>> receiver_ot(number_of_parties);
    vvv<std::vector<encrypto::motion::BitVector<>>> sender_messages(number_of_parties),
        sender_out(number_of_parties), receiver_messages(number_of_parties);
    vvv<encrypto::motion::BitVector<>> choices(number_of_parties);

    for (auto i = 0ull; i < number_of_parties; ++i) {
      sender_ot.at(i).resize(number_of_parties);
      receiver_ot.at(i).resize(number_of_parties);
      sender_messages.at(i).resize(number_of_parties);
      sender_out.at(i).resize(number_of_parties);
      receiver_messages.at(i).resize(number_of_parties);
      choices.at(i).resize(number_of_parties);
    }

    for (auto i = 0ull; i < number_of_parties; ++i) {
      for (auto j = 0ull; j < number_of_parties; ++j) {
        if (i != j) {
          for (auto k = 0ull; k < kNumberOfOts; ++k) {
            sender_messages.at(i).at(j).resize(kNumberOfOts);
            sender_out.at(i).at(j).resize(kNumberOfOts);
            receiver_messages.at(i).at(j).resize(kNumberOfOts);
            choices.at(i).at(j).resize(kNumberOfOts);
            for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
              sender_messages.at(i).at(j).at(k).push_back(
                  encrypto::motion::BitVector<>::SecureRandom(bitlength.at(k)));
            }
            choices.at(i).at(j).at(k) =
                encrypto::motion::BitVector<>::SecureRandom(ots_in_batch.at(k));
          }
        }
      }
    }

    for (auto i = 0u; i < motion_parties.size(); ++i) {
      threads.at(i) = std::thread([&sender_messages, &receiver_messages, &choices, &bitlength,
                                   &ots_in_batch, &sender_ot, &sender_out, &receiver_ot,
                                   &motion_parties, i, number_of_parties]() {
        motion_parties.at(i)->GetBackend()->GetBaseProvider().Setup();
        for (auto j = 0u; j < motion_parties.size(); ++j) {
          if (i != j) {
            auto& ot_provider = motion_parties.at(i)->GetBackend()->GetOtProvider(j);
            for (auto k = 0ull; k < kNumberOfOts; ++k) {
              sender_ot.at(i).at(j).push_back(
                  ot_provider.RegisterSendXcOt(ots_in_batch.at(k), bitlength.at(k)));
              receiver_ot.at(i).at(j).push_back(
                  ot_provider.RegisterReceiveXcOt(ots_in_batch.at(k), bitlength.at(k)));
            }
          }
        }
        for (std::size_t party_id = 0; party_id < motion_parties.size(); ++party_id) {
          if (party_id != i) {
            motion_parties.at(i)->GetBackend()->GetOtProvider(party_id).PreSetup();
          }
        }
        motion_parties.at(i)->GetBackend()->GetBaseOtProvider().PreSetup();
        motion_parties.at(i)->GetBackend()->Synchronize();
        motion_parties.at(i)->GetBackend()->GetBaseOtProvider().ComputeBaseOts();
        motion_parties.at(i)->GetBackend()->OtExtensionSetup();
        for (auto j = 0u; j < motion_parties.size(); ++j) {
          if (i != j) {
            for (auto k = 0ull; k < kNumberOfOts; ++k) {
              receiver_ot.at(i).at(j).at(k)->SetChoices(choices.at(i).at(j).at(k));
              receiver_ot.at(i).at(j).at(k)->SendCorrections();
            }
            for (auto k = 0ull; k < kNumberOfOts; ++k) {
              sender_ot.at(i).at(j).at(k)->SetCorrelations(sender_messages.at(i).at(j).at(k));
              sender_ot.at(i).at(j).at(k)->SendMessages();
            }
          }
        }
        motion_parties.at(i)->Finish();
      });
    }

    for (auto& t : threads) {
      if (t.joinable()) t.join();
    }

    for (auto i = 0u; i < motion_parties.size(); ++i) {
      for (auto j = 0u; j < motion_parties.size(); ++j) {
        if (i == j) continue;
        for (auto k = 0ull; k < kNumberOfOts; ++k) {
          receiver_ot.at(i).at(j).at(k)->ComputeOutputs();
          receiver_messages.at(i).at(j).at(k).assign(
              receiver_ot.at(i).at(j).at(k)->GetOutputs().begin(),
              receiver_ot.at(i).at(j).at(k)->GetOutputs().end());
          sender_ot.at(i).at(j).at(k)->ComputeOutputs();
          sender_out.at(i).at(j).at(k).assign(sender_ot.at(i).at(j).at(k)->GetOutputs().begin(),
                                              sender_ot.at(i).at(j).at(k)->GetOutputs().end());
        }
      }
    }

    for (auto i = 0u; i < motion_parties.size(); ++i) {
      for (auto j = 0u; j < motion_parties.size(); ++j) {
        if (i != j) {
          for (auto k = 0ull; k < kNumberOfOts; ++k) {
            for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
              if (!choices.at(j).at(i).at(k)[l]) {
                ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l),
                          sender_out.at(i).at(j).at(k).at(l).Subset(0, bitlength.at(k)));
              } else {
                ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l),
                          sender_out.at(i).at(j).at(k).at(l).Subset(bitlength.at(k),
                                                                    2 * bitlength.at(k)));
                ASSERT_EQ(receiver_messages.at(j).at(i).at(k).at(l) ^
                              sender_out.at(i).at(j).at(k).at(l).Subset(0, bitlength.at(k)),
                          sender_messages.at(i).at(j).at(k).at(l));
              }
            }
          }
        }
      }
    }
  }
}

}  // namespace