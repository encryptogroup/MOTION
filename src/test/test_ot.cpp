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
#include "base/party.h"
#include "crypto/motion_base_provider.h"
#include "crypto/oblivious_transfer/ot_provider.h"
#include "data_storage/base_ot_data.h"

namespace {

constexpr auto num_parties_list = {2u, 3u};

template <typename T>
using vvv = std::vector<std::vector<std::vector<T>>>;

TEST(ObliviousTransfer, Random1oo2OTsFromOTExtension) {
  constexpr std::size_t num_ots{10};
  for (auto num_parties : num_parties_list) {
    try {
      std::mt19937_64 r(0);
      std::uniform_int_distribution<std::size_t> dist_bitlen(1, 1000);
      std::uniform_int_distribution<std::size_t> dist_batch_size(1, 10);
      std::array<std::size_t, num_ots> bitlen, ots_in_batch;
      for (auto i = 0ull; i < bitlen.size(); ++i) {
        bitlen.at(i) = dist_bitlen(r);
        ots_in_batch.at(i) = dist_batch_size(r);
      }

      bitlen.at(bitlen.size() - 1) = 1;

      std::vector<MOTION::PartyPtr> motion_parties(
          std::move(MOTION::GetNLocalParties(num_parties, PORT_OFFSET)));
      for (auto &p : motion_parties) {
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

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        t.at(i) = std::thread(
            [&bitlen, &ots_in_batch, &sender_ot, &receiver_ot, &motion_parties, i, num_parties]() {
              motion_parties.at(i)->GetBackend()->get_motion_base_provider().setup();
              for (auto j = 0u; j < motion_parties.size(); ++j) {
                if (i != j) {
                  auto &ot_provider = motion_parties.at(i)->GetBackend()->GetOTProvider(j);
                  for (auto k = 0ull; k < num_ots; ++k) {
                    sender_ot.at(i).at(j).push_back(
                        ot_provider.RegisterSend(bitlen.at(k), ots_in_batch.at(k),
                                                 ENCRYPTO::ObliviousTransfer::OTProtocol::ROT));
                    receiver_ot.at(i).at(j).push_back(
                        ot_provider.RegisterReceive(bitlen.at(k), ots_in_batch.at(k),
                                                    ENCRYPTO::ObliviousTransfer::OTProtocol::ROT));
                  }
                }
              }
              motion_parties.at(i)->GetBackend()->OTExtensionSetup();
              motion_parties.at(i)->Finish();
            });
      }

      for (auto &tt : t) {
        tt.join();
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
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
  constexpr std::size_t num_ots{10};
  for (auto num_parties : num_parties_list) {
    try {
      std::mt19937_64 r(0);
      std::uniform_int_distribution<std::size_t> dist_bitlen(1, 1000);
      std::uniform_int_distribution<std::size_t> dist_batch_size(1, 10);
      std::array<std::size_t, num_ots> bitlen, ots_in_batch;
      for (auto i = 0ull; i < bitlen.size(); ++i) {
        bitlen.at(i) = dist_bitlen(r);
        ots_in_batch.at(i) = dist_batch_size(r);
      }

      bitlen.at(bitlen.size() - 1) = 1;

      std::vector<MOTION::PartyPtr> motion_parties(
          std::move(MOTION::GetNLocalParties(num_parties, PORT_OFFSET)));
      for (auto &p : motion_parties) {
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

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        t.at(i) = std::thread([&sender_msgs, &receiver_msgs, &choices, &bitlen, &ots_in_batch,
                               &sender_ot, &receiver_ot, &motion_parties, i, num_parties]() {
          motion_parties.at(i)->GetBackend()->get_motion_base_provider().setup();
          for (auto j = 0u; j < motion_parties.size(); ++j) {
            if (i != j) {
              auto &ot_provider = motion_parties.at(i)->GetBackend()->GetOTProvider(j);
              for (auto k = 0ull; k < num_ots; ++k) {
                sender_ot.at(i).at(j).push_back(
                    ot_provider.RegisterSend(bitlen.at(k), ots_in_batch.at(k)));
                receiver_ot.at(i).at(j).push_back(
                    ot_provider.RegisterReceive(bitlen.at(k), ots_in_batch.at(k)));
              }
            }
          }
          motion_parties.at(i)->GetBackend()->OTExtensionSetup();

          for (auto j = 0u; j < motion_parties.size(); ++j) {
            if (i != j) {
              for (auto k = 0ull; k < num_ots; ++k) {
                receiver_ot.at(i).at(j).at(k)->SetChoices(choices.at(i).at(j).at(k));
                receiver_ot.at(i).at(j).at(k)->SendCorrections();
                sender_ot.at(i).at(j).at(k)->SetInputs(sender_msgs.at(i).at(j).at(k));
                sender_ot.at(i).at(j).at(k)->SendMessages();
              }
            }
          }
          motion_parties.at(i)->Finish();
        });
      }

      for (auto &tt : t) {
        tt.join();
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
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
  constexpr std::size_t num_ots{10};
  for (auto num_parties : num_parties_list) {
    try {
      std::mt19937_64 r(0);
      std::uniform_int_distribution<std::size_t> dist_bitlen(1, 1000);
      std::uniform_int_distribution<std::size_t> dist_batch_size(1, 10);
      std::array<std::size_t, num_ots> bitlen, ots_in_batch;
      for (auto i = 0ull; i < bitlen.size(); ++i) {
        bitlen.at(i) = dist_bitlen(r);
        ots_in_batch.at(i) = dist_batch_size(r);
      }

      bitlen.at(bitlen.size() - 1) = 1;

      std::vector<MOTION::PartyPtr> motion_parties(
          std::move(MOTION::GetNLocalParties(num_parties, PORT_OFFSET)));
      for (auto &p : motion_parties) {
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

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        t.at(i) =
            std::thread([&sender_msgs, &receiver_msgs, &choices, &bitlen, &ots_in_batch, &sender_ot,
                         &sender_out, &receiver_ot, &motion_parties, i, num_parties]() {
              motion_parties.at(i)->GetBackend()->get_motion_base_provider().setup();
              for (auto j = 0u; j < motion_parties.size(); ++j) {
                if (i != j) {
                  auto &ot_provider = motion_parties.at(i)->GetBackend()->GetOTProvider(j);
                  for (auto k = 0ull; k < num_ots; ++k) {
                    sender_ot.at(i).at(j).push_back(
                        ot_provider.RegisterSend(bitlen.at(k), ots_in_batch.at(k),
                                                 ENCRYPTO::ObliviousTransfer::OTProtocol::XCOT));
                    receiver_ot.at(i).at(j).push_back(
                        ot_provider.RegisterReceive(bitlen.at(k), ots_in_batch.at(k),
                                                    ENCRYPTO::ObliviousTransfer::OTProtocol::XCOT));
                  }
                }
              }
              motion_parties.at(i)->GetBackend()->OTExtensionSetup();
              for (auto j = 0u; j < motion_parties.size(); ++j) {
                if (i != j) {
                  for (auto k = 0ull; k < num_ots; ++k) {
                    receiver_ot.at(i).at(j).at(k)->SetChoices(choices.at(i).at(j).at(k));
                    receiver_ot.at(i).at(j).at(k)->SendCorrections();
                  }
                  for (auto k = 0ull; k < num_ots; ++k) {
                    sender_ot.at(i).at(j).at(k)->SetInputs(sender_msgs.at(i).at(j).at(k));
                    sender_ot.at(i).at(j).at(k)->SendMessages();
                  }
                }
              }
              motion_parties.at(i)->Finish();
            });
      }

      for (auto &tt : t) {
        if (tt.joinable()) tt.join();
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
          if (i == j) continue;
          for (auto k = 0ull; k < num_ots; ++k) {
            receiver_msgs.at(i).at(j).at(k) = receiver_ot.at(i).at(j).at(k)->GetOutputs();
            sender_out.at(i).at(j).at(k) = sender_ot.at(i).at(j).at(k)->GetOutputs();
          }
        }
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
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
                  ASSERT_EQ(receiver_msgs.at(j).at(i).at(k).at(l) ^
                                sender_out.at(i).at(j).at(k).at(l).Subset(0, bitlen.at(k)),
                            sender_msgs.at(i).at(j).at(k).at(l));
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
}  // namespace

TEST(ObliviousTransfer, AdditivelyCorrelated1oo2OTsFromOTExtension) {
  constexpr std::size_t num_ots{10};
  constexpr std::array<std::size_t, 5> bitlens{8, 16, 32, 64, 128};
  for (auto num_parties : num_parties_list) {
    try {
      std::mt19937_64 r(0);
      std::uniform_int_distribution<std::size_t> dist_bitlen(0, bitlens.size() - 1);
      std::uniform_int_distribution<std::size_t> dist_batch_size(1, 10);
      std::array<std::size_t, num_ots> bitlen, ots_in_batch;
      for (auto i = 0ull; i < bitlen.size(); ++i) {
        bitlen.at(i) = bitlens.at(dist_bitlen(r));
        ots_in_batch.at(i) = dist_batch_size(r);
      }

      std::vector<MOTION::PartyPtr> motion_parties(
          std::move(MOTION::GetNLocalParties(num_parties, PORT_OFFSET)));
      for (auto &p : motion_parties) {
        p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
      }
      std::vector<std::thread> t(num_parties);

      // my id, other id, data
      vvv<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorSender>> sender_ot(num_parties);
      vvv<std::shared_ptr<ENCRYPTO::ObliviousTransfer::OTVectorReceiver>> receiver_ot(num_parties);
      vvv<std::vector<ENCRYPTO::BitVector<>>> sender_msgs(num_parties), sender_out(num_parties),
          receiver_msgs(num_parties);
      vvv<ENCRYPTO::BitVector<>> choices(num_parties);

      for (auto i{0ull}; i < num_parties; ++i) {
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

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        t.at(i) =
            std::thread([&sender_msgs, &receiver_msgs, &choices, &bitlen, &ots_in_batch, &sender_ot,
                         &sender_out, &receiver_ot, &motion_parties, i, num_parties]() {
              motion_parties.at(i)->GetBackend()->get_motion_base_provider().setup();
              for (auto j = 0u; j < motion_parties.size(); ++j) {
                if (i != j) {
                  auto &ot_provider = motion_parties.at(i)->GetBackend()->GetOTProvider(j);
                  for (auto k = 0ull; k < num_ots; ++k) {
                    sender_ot.at(i).at(j).push_back(
                        ot_provider.RegisterSend(bitlen.at(k), ots_in_batch.at(k),
                                                 ENCRYPTO::ObliviousTransfer::OTProtocol::ACOT));
                    receiver_ot.at(i).at(j).push_back(
                        ot_provider.RegisterReceive(bitlen.at(k), ots_in_batch.at(k),
                                                    ENCRYPTO::ObliviousTransfer::OTProtocol::ACOT));
                  }
                }
              }
              motion_parties.at(i)->GetBackend()->OTExtensionSetup();

              for (auto j = 0u; j < motion_parties.size(); ++j) {
                if (i != j) {
// #pragma omp parallel sections
                  {
// #pragma omp section
                    {
                      for (auto k = 0ull; k < num_ots; ++k) {
                        receiver_ot.at(i).at(j).at(k)->SetChoices(choices.at(i).at(j).at(k));
                        receiver_ot.at(i).at(j).at(k)->SendCorrections();
                      }
                    }
// #pragma omp section
                    {
                      for (auto k = 0ull; k < num_ots; ++k) {
                        sender_ot.at(i).at(j).at(k)->SetInputs(sender_msgs.at(i).at(j).at(k));
                        sender_ot.at(i).at(j).at(k)->SendMessages();
                      }
                    }
                  }
                }
              }
              motion_parties.at(i)->Finish();
            });
      }

      for (auto &tt : t) {
        tt.join();
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
          if (i != j) {
            for (auto k = 0ull; k < num_ots; ++k) {
              receiver_msgs.at(i).at(j).at(k) = receiver_ot.at(i).at(j).at(k)->GetOutputs();
              sender_out.at(i).at(j).at(k) = sender_ot.at(i).at(j).at(k)->GetOutputs();
            }
          }
        }
      }

      for (auto i = 0u; i < motion_parties.size(); ++i) {
        for (auto j = 0u; j < motion_parties.size(); ++j) {
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
                  auto x = receiver_msgs.at(j).at(i).at(k).at(l);
                  const auto mask = sender_out.at(i).at(j).at(k).at(l).Subset(0, bitlen.at(k));
                  if (bitlen.at(k) == 8u) {
                    *reinterpret_cast<std::uint8_t *>(x.GetMutableData().data()) -=
                        *reinterpret_cast<const std::uint8_t *>(mask.GetData().data());
                  } else if (bitlen.at(k) == 16u) {
                    *reinterpret_cast<std::uint16_t *>(x.GetMutableData().data()) -=
                        *reinterpret_cast<const std::uint16_t *>(mask.GetData().data());
                  } else if (bitlen.at(k) == 32u) {
                    *reinterpret_cast<std::uint32_t *>(x.GetMutableData().data()) -=
                        *reinterpret_cast<const std::uint32_t *>(mask.GetData().data());
                  } else if (bitlen.at(k) == 64u) {
                    *reinterpret_cast<std::uint64_t *>(x.GetMutableData().data()) -=
                        *reinterpret_cast<const std::uint64_t *>(mask.GetData().data());
                  } else if (bitlen.at(k) == 128u) {
                    *reinterpret_cast<__uint128_t *>(x.GetMutableData().data()) -=
                        *reinterpret_cast<const __uint128_t *>(mask.GetData().data());
                  }
                  ASSERT_EQ(x, sender_msgs.at(i).at(j).at(k).at(l));
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
}  // namespace
}  // namespace
