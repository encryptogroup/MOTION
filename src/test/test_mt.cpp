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
constexpr auto PORT_OFFSET = 7777u;

template <typename T>
using vvv = std::vector<std::vector<std::vector<T>>>;

TEST(MultiplicationTriples, Binary) {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    constexpr auto BGMW = ABYN::MPCProtocol::BooleanGMW;
    std::srand(std::time(nullptr));
    for (auto num_parties : {2u, 3u}) {
      std::vector<bool> global_input_1(num_parties);
      for (auto j = 0ull; j < global_input_1.size(); ++j) {
        global_input_1.at(j) = (std::rand() % 2) == 1;
      }
      std::vector<ENCRYPTO::BitVector<>> global_input_1K(num_parties);

      for (auto j = 0ull; j < global_input_1K.size(); ++j) {
        global_input_1K.at(j) = ENCRYPTO::BitVector<>::Random(20);
      }
      bool dummy_input_1 = false;
      ENCRYPTO::BitVector<> dummy_input_20(20, false);
      try {
        std::vector<ABYN::PartyPtr> abyn_parties(
            std::move(ABYN::Party::GetNLocalParties(num_parties, PORT_OFFSET)));
        for (auto &p : abyn_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetConfiguration()->SetOnlineAfterSetup(i % 2 == 1);
        }

        auto f = [&](std::size_t party_id) {
          std::vector<ABYN::Shares::ShareWrapper> s_in_1, s_in_1K;

          for (auto j = 0ull; j < num_parties; ++j) {
            if (j == abyn_parties.at(party_id)->GetConfiguration()->GetMyId()) {
              s_in_1.push_back(
                  abyn_parties.at(party_id)->IN<BGMW>(static_cast<bool>(global_input_1.at(j)), j));
              s_in_1K.push_back(abyn_parties.at(party_id)->IN<BGMW>(global_input_1K.at(j), j));
            } else {
              s_in_1.push_back(abyn_parties.at(party_id)->IN<BGMW>(dummy_input_1, j));
              s_in_1K.push_back(abyn_parties.at(party_id)->IN<BGMW>(dummy_input_20, j));
            }
          }

          auto s_and_1 = s_in_1.at(0) & s_in_1.at(1);
          auto s_and_1K = s_in_1K.at(0) & s_in_1K.at(1);

          for (auto j = 2ull; j < num_parties; ++j) {
            s_and_1 = s_and_1 & s_in_1.at(j);
            s_and_1K = s_and_1K & s_in_1K.at(j);
          }

          abyn_parties.at(party_id)->Run();
        };

#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(abyn_parties.size())
        for (auto party_id = 0u; party_id < abyn_parties.size(); ++party_id) {
          f(party_id);
          // check multiplication triples
          if (party_id == 0) {
            ENCRYPTO::BitVector<> a, b, c;
            a = abyn_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().a;
            b = abyn_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().b;
            c = abyn_parties.at(0)->GetBackend()->GetMTProvider()->GetBinaryAll().c;

            for (auto j = 1ull; j < abyn_parties.size(); ++j) {
              a ^= abyn_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().a;
              b ^= abyn_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().b;
              c ^= abyn_parties.at(j)->GetBackend()->GetMTProvider()->GetBinaryAll().c;
            }
            EXPECT_EQ(c, a & b);
          }
          abyn_parties.at(party_id)->Finish();
        }
      } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}
}