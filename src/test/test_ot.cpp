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

#include "base/party.h"
#include "crypto/oblivious_transfer/ot_provider.h"

namespace {

constexpr auto num_parties_list = {2u, 3u};
constexpr auto PORT_OFFSET = 7777u;

template <typename T>
using vvv = std::vector<std::vector<std::vector<T>>>;

TEST(ObliviousTransfer, BaseOT) {
  for (auto num_parties : num_parties_list) {
    try {
      std::vector<ABYN::PartyPtr> abyn_parties(
          std::move(ABYN::Party::GetNLocalParties(num_parties, PORT_OFFSET)));
      for (auto &p : abyn_parties) {
        p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      }
      std::vector<std::thread> t(num_parties);

      struct base_ots_t {
        std::array<std::array<std::byte, 16>, 128> messages_c_, messages0_, messages1_;
        ENCRYPTO::BitVector<> c;
      };
      std::vector<std::vector<base_ots_t>> base_ots(num_parties);
      for (auto &v : base_ots) {
        v.resize(num_parties);
      }

      for (auto i = 0u; i < abyn_parties.size(); ++i) {
        t.at(i) = std::thread([&abyn_parties, i, num_parties, &base_ots]() {
          abyn_parties.at(i)->GetBackend()->ComputeBaseOTs();
          abyn_parties.at(i)->Finish();

          for (auto other_id = 0u; other_id < num_parties; ++other_id) {
            if (i == other_id) {
              continue;
            }
            auto &ds = abyn_parties.at(i)
                           ->GetConfiguration()
                           ->GetContexts()
                           .at(other_id)
                           ->GetDataStorage();

            auto &base_ots_recv = ds->GetBaseOTsReceiverData();
            auto &bo = base_ots.at(i).at(other_id);
            assert((*base_ots_recv->is_ready_condition_)());
            for (auto j = 0ull; j < bo.messages_c_.size(); ++j) {
              std::copy(base_ots_recv->messages_c_.at(j).begin(),
                        base_ots_recv->messages_c_.at(j).end(), bo.messages_c_.at(j).begin());
            }
            base_ots.at(i).at(other_id).c = base_ots_recv->c_;

            auto &base_ots_snd = ds->GetBaseOTsSenderData();
            assert((*base_ots_snd->is_ready_condition_)());

            for (auto k = 0ull; k < bo.messages0_.size(); ++k) {
              std::copy(base_ots_snd->messages_0_.at(k).begin(),
                        base_ots_snd->messages_0_.at(k).end(), bo.messages0_.at(k).begin());
            }
            for (auto k = 0ull; k < bo.messages1_.size(); ++k) {
              std::copy(base_ots_snd->messages_1_.at(k).begin(),
                        base_ots_snd->messages_1_.at(k).end(), bo.messages1_.at(k).begin());
            }
          }
        });
      }

      for (auto &tt : t) {
        tt.join();
      }

      for (auto i = 0u; i < num_parties; ++i) {
        for (auto j = 0u; j < num_parties; ++j) {
          if (i == j) {
            continue;
          }
          auto &base_ots_a = base_ots.at(i).at(j);
          auto &base_ots_b = base_ots.at(j).at(i);

          for (auto k = 0u; k < base_ots_a.messages_c_.size(); ++k) {
            if (base_ots_a.c.Get(k)) {
              ASSERT_EQ(base_ots_a.messages_c_.at(k), base_ots_b.messages1_.at(k));
            } else {
              ASSERT_EQ(base_ots_a.messages_c_.at(k), base_ots_b.messages0_.at(k));
            }

            if (base_ots_b.c.Get(k)) {
              ASSERT_EQ(base_ots_b.messages_c_.at(k), base_ots_a.messages1_.at(k));
            } else {
              ASSERT_EQ(base_ots_b.messages_c_.at(k), base_ots_a.messages0_.at(k));
            }
          }
        }
      }
    } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
    }
  }
}

TEST(ObliviousTransfer, Random1oo2OTsFromOTExtension) {
  constexpr std::size_t num_ots = 10;
  for (auto num_parties : num_parties_list) {
    try {
      std::random_device rd("/dev/urandom");
      std::uniform_int_distribution<std::size_t> dist_bitlen(1, 1000);
      std::uniform_int_distribution<std::size_t> dist_batch_size(1, 10);
      std::array<std::size_t, num_ots> bitlen, ots_in_batch;
      for (auto i = 0ull; i < bitlen.size(); ++i) {
        bitlen.at(i) = dist_bitlen(rd);
        ots_in_batch.at(i) = dist_batch_size(rd);
      }

      bitlen.at(bitlen.size() - 1) = 1;

      std::vector<ABYN::PartyPtr> abyn_parties(
          std::move(ABYN::Party::GetNLocalParties(num_parties, PORT_OFFSET)));
      for (auto &p : abyn_parties) {
        p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      }
      std::vector<std::thread> t(num_parties);

      // my id, other id, data
      vvv<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorSender>> sender_ot(num_parties);
      vvv<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorReceiver>> receiver_ot(num_parties);
      vvv<std::vector<ENCRYPTO::BitVector<>>> sender_msgs(num_parties), receiver_msgs(num_parties);
      vvv<ENCRYPTO::BitVector<>> choices(num_parties);

      for (auto i = 0ull; i < num_parties; ++i) {
        sender_ot.at(i).resize(num_parties);
        receiver_ot.at(i).resize(num_parties);
        sender_msgs.at(i).resize(num_parties);
        receiver_msgs.at(i).resize(num_parties);
        choices.at(i).resize(num_parties);
      }

      for (auto i = 0u; i < abyn_parties.size(); ++i) {
        t.at(i) = std::thread(
            [&bitlen, &ots_in_batch, &sender_ot, &receiver_ot, &abyn_parties, i, num_parties]() {
              for (auto j = 0u; j < abyn_parties.size(); ++j) {
                if (i != j) {
                  auto &ot_provider = abyn_parties.at(i)->GetBackend()->GetOTProvider(j);
                  for (auto k = 0ull; k < num_ots; ++k) {
                    sender_ot.at(i).at(j).push_back(
                        ot_provider->RegisterSend(bitlen.at(k), ots_in_batch.at(k), 2,
                                                  ENCRYPTO::ObliviousTransfer::OTProtocol::ROT));
                    receiver_ot.at(i).at(j).push_back(
                        ot_provider->RegisterReceive(bitlen.at(k), ots_in_batch.at(k), 2,
                                                     ENCRYPTO::ObliviousTransfer::OTProtocol::ROT));
                  }
                }
              }
              abyn_parties.at(i)->GetBackend()->ComputeOTExtension();
              abyn_parties.at(i)->Finish();
            });
      }

      for (auto &tt : t) {
        tt.join();
      }

      for (auto i = 0u; i < abyn_parties.size(); ++i) {
        for (auto j = 0u; j < abyn_parties.size(); ++j) {
          if (i != j) {
            for (auto k = 0ull; k < num_ots; ++k) {
              sender_msgs.at(i).at(j).push_back(sender_ot.at(i).at(j).at(k)->GetOutputs());
              choices.at(j).at(i).push_back(receiver_ot.at(j).at(i).at(k)->GetChoices());
              receiver_msgs.at(j).at(i).push_back(receiver_ot.at(j).at(i).at(k)->GetOutputs());

              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                if (!choices.at(j).at(i).at(k)[l]) {
                  ASSERT_EQ(receiver_msgs.at(j).at(i).at(k).at(l),
                            sender_msgs.at(i).at(j).at(k).at(l).Subset(0, bitlen.at(k)));
                } else {
                  ASSERT_EQ(
                      receiver_msgs.at(j).at(i).at(k).at(l),
                      sender_msgs.at(i).at(j).at(k).at(l).Subset(bitlen.at(k), 2 * bitlen.at(k)));
                }
              }
            }
          }
        }
      }
    } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
    }
  }
}

TEST(ObliviousTransfer, General1oo2OTsFromOTExtension) {
  constexpr std::size_t num_ots = 10;
  for (auto num_parties : num_parties_list) {
    try {
      std::random_device rd("/dev/urandom");
      std::uniform_int_distribution<std::size_t> dist_bitlen(1, 1000);
      std::uniform_int_distribution<std::size_t> dist_batch_size(1, 10);
      std::array<std::size_t, num_ots> bitlen, ots_in_batch;
      for (auto i = 0ull; i < bitlen.size(); ++i) {
        bitlen.at(i) = dist_bitlen(rd);
        ots_in_batch.at(i) = dist_batch_size(rd);
      }

      bitlen.at(bitlen.size() - 1) = 1;

      std::vector<ABYN::PartyPtr> abyn_parties(
          std::move(ABYN::Party::GetNLocalParties(num_parties, PORT_OFFSET)));
      for (auto &p : abyn_parties) {
        p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      }
      std::vector<std::thread> t(num_parties);

      // my id, other id, data
      vvv<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorSender>> sender_ot(num_parties);
      vvv<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorReceiver>> receiver_ot(num_parties);
      vvv<std::vector<ENCRYPTO::BitVector<>>> sender_msgs(num_parties), receiver_msgs(num_parties);
      vvv<ENCRYPTO::BitVector<>> choices(num_parties);

      for (auto i = 0ull; i < num_parties; ++i) {
        sender_ot.at(i).resize(num_parties);
        receiver_ot.at(i).resize(num_parties);
        sender_msgs.at(i).resize(num_parties);
        receiver_msgs.at(i).resize(num_parties);
        choices.at(i).resize(num_parties);
      }

      for (auto i = 0ull; i < num_parties; ++i) {
        for (auto j = 0ull; j < num_parties; ++j) {
          if (i != j) {
            for (auto k = 0ull; k < num_ots; ++k) {
              sender_msgs.at(i).at(j).resize(num_ots);
              receiver_msgs.at(i).at(j).resize(num_ots);
              choices.at(i).at(j).resize(num_ots);
              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                sender_msgs.at(i).at(j).at(k).push_back(
                    ENCRYPTO::BitVector<>::Random(bitlen.at(k) * 2));
              }
              choices.at(i).at(j).at(k) = ENCRYPTO::BitVector<>::Random(ots_in_batch.at(k));
            }
          }
        }
      }

      for (auto i = 0u; i < abyn_parties.size(); ++i) {
        t.at(i) = std::thread([&sender_msgs, &receiver_msgs, &choices, &bitlen, &ots_in_batch,
                               &sender_ot, &receiver_ot, &abyn_parties, i, num_parties]() {
          for (auto j = 0u; j < abyn_parties.size(); ++j) {
            if (i != j) {
              auto &ot_provider = abyn_parties.at(i)->GetBackend()->GetOTProvider(j);
              for (auto k = 0ull; k < num_ots; ++k) {
                sender_ot.at(i).at(j).push_back(
                    ot_provider->RegisterSend(bitlen.at(k), ots_in_batch.at(k), 2,
                                              ENCRYPTO::ObliviousTransfer::OTProtocol::GOT));
                receiver_ot.at(i).at(j).push_back(
                    ot_provider->RegisterReceive(bitlen.at(k), ots_in_batch.at(k), 2,
                                                 ENCRYPTO::ObliviousTransfer::OTProtocol::GOT));
              }
            }
          }
          abyn_parties.at(i)->GetBackend()->ComputeOTExtension();

          for (auto j = 0u; j < abyn_parties.size(); ++j) {
            if (i != j) {
              for (auto k = 0ull; k < num_ots; ++k) {
                receiver_ot.at(i).at(j).at(k)->SetChoices(choices.at(i).at(j).at(k));
                receiver_ot.at(i).at(j).at(k)->SendCorrections();
                sender_ot.at(i).at(j).at(k)->SetInputs(sender_msgs.at(i).at(j).at(k));
                sender_ot.at(i).at(j).at(k)->SendMessages();
              }
            }
          }
          abyn_parties.at(i)->Finish();
        });
      }

      for (auto &tt : t) {
        tt.join();
      }

      for (auto i = 0u; i < abyn_parties.size(); ++i) {
        for (auto j = 0u; j < abyn_parties.size(); ++j) {
          if (i != j) {
            for (auto k = 0ull; k < num_ots; ++k) {
              receiver_msgs.at(j).at(i).at(k) = receiver_ot.at(j).at(i).at(k)->GetOutputs();
              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                if (!choices.at(j).at(i).at(k)[l]) {
                  ASSERT_EQ(receiver_msgs.at(j).at(i).at(k).at(l),
                            sender_msgs.at(i).at(j).at(k).at(l).Subset(0, bitlen.at(k)));
                } else {
                  ASSERT_EQ(
                      receiver_msgs.at(j).at(i).at(k).at(l),
                      sender_msgs.at(i).at(j).at(k).at(l).Subset(bitlen.at(k), 2 * bitlen.at(k)));
                }
              }
            }
          }
        }
      }
    } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
    }
  }
}

TEST(ObliviousTransfer, XORCorrelated1oo2OTsFromOTExtension) {
  constexpr std::size_t num_ots = 10;
  for (auto num_parties : num_parties_list) {
    try {
      std::random_device rd("/dev/urandom");
      std::uniform_int_distribution<std::size_t> dist_bitlen(1, 32);
      std::uniform_int_distribution<std::size_t> dist_batch_size(1, 10);
      std::array<std::size_t, num_ots> bitlen, ots_in_batch;
      for (auto i = 0ull; i < bitlen.size(); ++i) {
        bitlen.at(i) = dist_bitlen(rd);
        ots_in_batch.at(i) = dist_batch_size(rd);
      }

      bitlen.at(bitlen.size() - 1) = 1;

      std::vector<ABYN::PartyPtr> abyn_parties(
          std::move(ABYN::Party::GetNLocalParties(num_parties, PORT_OFFSET)));
      for (auto &p : abyn_parties) {
        p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      }
      std::vector<std::thread> t(num_parties);

      // my id, other id, data
      vvv<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorSender>> sender_ot(num_parties);
      vvv<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorReceiver>> receiver_ot(num_parties);
      vvv<std::vector<ENCRYPTO::BitVector<>>> sender_msgs(num_parties), sender_out(num_parties),
          receiver_msgs(num_parties);
      vvv<ENCRYPTO::BitVector<>> choices(num_parties);

      for (auto i = 0ull; i < num_parties; ++i) {
        sender_ot.at(i).resize(num_parties);
        receiver_ot.at(i).resize(num_parties);
        sender_msgs.at(i).resize(num_parties);
        sender_out.at(i).resize(num_parties);
        receiver_msgs.at(i).resize(num_parties);
        choices.at(i).resize(num_parties);
      }

      for (auto i = 0ull; i < num_parties; ++i) {
        for (auto j = 0ull; j < num_parties; ++j) {
          if (i != j) {
            for (auto k = 0ull; k < num_ots; ++k) {
              sender_msgs.at(i).at(j).resize(num_ots);
              sender_out.at(i).at(j).resize(num_ots);
              receiver_msgs.at(i).at(j).resize(num_ots);
              choices.at(i).at(j).resize(num_ots);
              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                sender_msgs.at(i).at(j).at(k).push_back(
                    ENCRYPTO::BitVector<>::Random(bitlen.at(k)));
              }
              choices.at(i).at(j).at(k) = ENCRYPTO::BitVector<>::Random(ots_in_batch.at(k));
            }
          }
        }
      }

      for (auto i = 0u; i < abyn_parties.size(); ++i) {
        t.at(i) =
            std::thread([&sender_msgs, &receiver_msgs, &choices, &bitlen, &ots_in_batch, &sender_ot,
                         &sender_out, &receiver_ot, &abyn_parties, i, num_parties]() {
              for (auto j = 0u; j < abyn_parties.size(); ++j) {
                if (i != j) {
                  auto &ot_provider = abyn_parties.at(i)->GetBackend()->GetOTProvider(j);
                  for (auto k = 0ull; k < num_ots; ++k) {
                    sender_ot.at(i).at(j).push_back(
                        ot_provider->RegisterSend(bitlen.at(k), ots_in_batch.at(k), 2,
                                                  ENCRYPTO::ObliviousTransfer::OTProtocol::XCOT));
                    receiver_ot.at(i).at(j).push_back(ot_provider->RegisterReceive(
                        bitlen.at(k), ots_in_batch.at(k), 2,
                        ENCRYPTO::ObliviousTransfer::OTProtocol::XCOT));
                  }
                }
              }
              abyn_parties.at(i)->GetBackend()->ComputeOTExtension();

              for (auto j = 0u; j < abyn_parties.size(); ++j) {
                if (i != j) {
                  for (auto k = 0ull; k < num_ots; ++k) {
                    receiver_ot.at(i).at(j).at(k)->SetChoices(choices.at(i).at(j).at(k));
                    receiver_ot.at(i).at(j).at(k)->SendCorrections();
                    sender_ot.at(i).at(j).at(k)->SetInputs(sender_msgs.at(i).at(j).at(k));
                    sender_ot.at(i).at(j).at(k)->SendMessages();
                    sender_out.at(i).at(j).at(k) = sender_ot.at(i).at(j).at(k)->GetOutputs();
                    receiver_msgs.at(j).at(i).at(k) = receiver_ot.at(j).at(i).at(k)->GetOutputs();
                  }
                }
              }
              abyn_parties.at(i)->Finish();
            });
      }

      for (auto &tt : t) {
        tt.join();
      }

      for (auto i = 0u; i < abyn_parties.size(); ++i) {
        for (auto j = 0u; j < abyn_parties.size(); ++j) {
          if (i != j) {
            for (auto k = 0ull; k < num_ots; ++k) {
              for (auto l = 0ull; l < ots_in_batch.at(k); ++l) {
                if (!choices.at(j).at(i).at(k)[l]) {
                  ASSERT_EQ(receiver_msgs.at(j).at(i).at(k).at(l),
                            sender_out.at(i).at(j).at(k).at(l).Subset(0, bitlen.at(k)));
                } else {
                  ASSERT_EQ(
                      receiver_msgs.at(j).at(i).at(k).at(l),
                      sender_out.at(i).at(j).at(k).at(l).Subset(bitlen.at(k), 2 * bitlen.at(k)));
                }
              }
            }
          }
        }
      }
    } catch (std::exception &e) {
      std::cerr << e.what() << std::endl;
    }
  }
}
}