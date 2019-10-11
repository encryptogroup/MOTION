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
#include "crypto/multiplication_triple/mt_provider.h"
#include "share/share_wrapper.h"
#include "wire/boolean_gmw_wire.h"
namespace {

constexpr auto num_parties_list = {2u, 3u};

template <typename T>
using vvv = std::vector<std::vector<std::vector<T>>>;

TEST(MultiplicationTriples, Binary) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = MOTION::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : {2u, 3u}) {
      std::vector<bool> global_input_1(num_parties);
      for (auto j = 0ull; j < global_input_1.size(); ++j) {
        global_input_1.at(j) = (std::rand() % 2) == 1;
      }
      std::vector<ENCRYPTO::BitVector<>> global_input_20(num_parties);

      for (auto j = 0ull; j < global_input_20.size(); ++j) {
        global_input_20.at(j) = ENCRYPTO::BitVector<>::Random(20);
      }
      bool dummy_input_1 = false;
      ENCRYPTO::BitVector<> dummy_input_20(20, false);
      try {
        std::vector<MOTION::PartyPtr> motion_parties(
            std::move(MOTION::GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }

        auto f = [&](std::size_t party_id) {
          std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_1K;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              s_in_1.emplace_back(
                  motion_parties.at(party_id)->IN<BGMW>(static_cast<bool>(global_input_1.at(j)), j));
              s_in_1K.emplace_back(motion_parties.at(party_id)->IN<BGMW>(global_input_20.at(j), j));
            } else {
              s_in_1.emplace_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_1, j));
              s_in_1K.emplace_back(motion_parties.at(party_id)->IN<BGMW>(dummy_input_20, j));
            }
          }

          auto s_and_1 = s_in_1.at(0) & s_in_1.at(1);
          auto s_and_1K = s_in_1K.at(0) & s_in_1K.at(1);

          for (auto j = 2ull; j < num_parties; ++j) {
            s_and_1 = s_and_1 & s_in_1.at(j);
            s_and_1K = s_and_1K & s_in_1K.at(j);
          }

          motion_parties.at(party_id)->Run();
        };
        std::vector<std::thread> t;
        //#pragma omp parallel for num_threads(motion_parties.size() + 1)
        for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
          t.emplace_back([party_id, &motion_parties, &f]() {
            f(party_id);
            // check multiplication triples
            if (party_id == 0) {
              ENCRYPTO::BitVector<> a, b, c;
              a = motion_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().a;
              b = motion_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().b;
              c = motion_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().c;

              for (auto j = 1ull; j < motion_parties.size(); ++j) {
                a ^= motion_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().a;
                b ^= motion_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().b;
                c ^= motion_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().c;
              }
              EXPECT_EQ(c, a & b);
            }
            motion_parties.at(party_id)->Finish();
          });
        }
        for (auto &&tt : t)
          if (tt.joinable()) tt.join();
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(MultiplicationTriples, Integer) {
  auto template_test = [](auto t) {
    using T = decltype(t);
    for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
      constexpr auto AGMW = MOTION::MPCProtocol::ArithmeticGMW;
      std::srand(std::time(nullptr));
      for (auto num_parties : {2u, 3u}) {
        std::vector<T> global_input_1(num_parties);
        for (auto j = 0ull; j < global_input_1.size(); ++j) {
          global_input_1.at(j) = (std::rand() % 2) == 1;
        }
        std::vector<std::vector<T>> global_input_100(num_parties);
        std::random_device r;
        std::uniform_int_distribution<T> d(0, std::numeric_limits<T>::max());
        for (auto j = 0ull; j < global_input_100.size(); ++j) {
          for (auto k = 0; k < 100; ++k) {
            global_input_100.at(j).emplace_back(d(r));
          }
        }
        T dummy_input_1 = 0;
        std::vector<T> dummy_input_100(100);
        try {
          std::vector<MOTION::PartyPtr> motion_parties(
              std::move(MOTION::GetNLocalParties(num_parties, PORT_OFFSET)));
          for (auto &p : motion_parties) {
            p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
            p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
          }

          auto f = [&](std::size_t party_id) {
            std::vector<MOTION::Shares::ShareWrapper> s_in_1, s_in_1K;

            for (auto j = 0ull; j < num_parties; ++j) {
              if (j == motion_parties.at(party_id)->GetConfiguration()->GetMyId()) {
                s_in_1.emplace_back(motion_parties.at(party_id)->IN<AGMW>(global_input_1.at(j), j));
                s_in_1K.emplace_back(
                    motion_parties.at(party_id)->IN<AGMW>(global_input_100.at(j), j));
              } else {
                s_in_1.emplace_back(motion_parties.at(party_id)->IN<AGMW>(dummy_input_1, j));
                s_in_1K.emplace_back(motion_parties.at(party_id)->IN<AGMW>(dummy_input_100, j));
              }
            }

            auto s_and_1 = s_in_1.at(0) * s_in_1.at(1);
            auto s_and_1K = s_in_1K.at(0) * s_in_1K.at(1);

            for (auto j = 2ull; j < num_parties; ++j) {
              s_and_1 = s_and_1 * s_in_1.at(j);
              s_and_1K = s_and_1K * s_in_1K.at(j);
            }

            motion_parties.at(party_id)->Run();
          };
          std::vector<std::thread> t;
          //#pragma omp parallel for num_threads(motion_parties.size() + 1)
          for (auto party_id = 0u; party_id < motion_parties.size(); ++party_id) {
            t.emplace_back([party_id, &motion_parties, &f]() {
              f(party_id);
              // check multiplication triples
              if (party_id == 0) {
                std::vector<T> a, b, c;
                const auto &mtp = motion_parties.at(0)->GetBackend()->GetMTProvider();
                a = mtp->template GetIntegerAll<T>().a;
                b = mtp->template GetIntegerAll<T>().b;
                c = mtp->template GetIntegerAll<T>().c;

                for (auto j = 1ull; j < motion_parties.size(); ++j) {
                  const auto &mtp_j = motion_parties.at(j)->GetBackend()->GetMTProvider();
                  for (auto k = 0ull; k < a.size(); ++k) {
                    a.at(k) += mtp_j->template GetIntegerAll<T>().a.at(k);
                    b.at(k) += mtp_j->template GetIntegerAll<T>().b.at(k);
                    c.at(k) += mtp_j->template GetIntegerAll<T>().c.at(k);
                  }
                }
                for (auto k = 0ull; k < a.size(); ++k) {
                  EXPECT_EQ(c.at(k), static_cast<T>(a.at(k) * b.at(k)));
                }
              }
              motion_parties.at(party_id)->Finish();
            });
          }
          for (auto &&tt : t)
            if (tt.joinable()) tt.join();
        } catch (std::exception &e) {
          std::cerr << e.what() << std::endl;
        }
      }
    }
  };

  template_test(static_cast<std::uint8_t>(0));
  template_test(static_cast<std::uint16_t>(0));
  template_test(static_cast<std::uint32_t>(0));
  template_test(static_cast<std::uint64_t>(0));
}
}  // namespace
