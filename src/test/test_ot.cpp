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

namespace {

constexpr auto num_parties_list = {2u, 3u};
constexpr auto PORT_OFFSET = 7777u;

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

            for (auto i = 0ull; i < bo.messages0_.size(); ++i) {
              std::copy(base_ots_snd->messages_0_.at(i).begin(),
                        base_ots_snd->messages_0_.at(i).end(), bo.messages0_.at(i).begin());
            }
            for (auto i = 0ull; i < bo.messages1_.size(); ++i) {
              std::copy(base_ots_snd->messages_1_.at(i).begin(),
                        base_ots_snd->messages_1_.at(i).end(), bo.messages1_.at(i).begin());
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
}