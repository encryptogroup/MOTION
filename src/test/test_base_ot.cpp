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

#include "gtest/gtest.h"

#include "test_constants.h"

#include "base/backend.h"
#include "base/party.h"
#include "crypto/base_ots/base_ot_provider.h"
#include "data_storage/base_ot_data.h"

using namespace MOTION;

TEST(ObliviousTransfer, BaseOT) {
  const std::size_t num_parties = 2;
  auto motion_parties = GetNLocalParties(num_parties, 0);
  for (auto &p : motion_parties) {
    p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
  }

  struct base_ots_t {
    std::array<std::array<std::byte, 16>, 128> messages_c_, messages_0_, messages_1_;
    ENCRYPTO::BitVector<> c;
  };
  std::vector<std::vector<base_ots_t>> base_ots(num_parties);
  for (auto &v : base_ots) {
    v.resize(num_parties);
  }

  std::vector<std::future<void>> futs;
  futs.reserve(num_parties);

  for (auto i = 0u; i < num_parties; ++i) {
    futs.emplace_back(
        std::async(std::launch::async, [&motion_parties, i, num_parties, &base_ots]() {
          motion_parties.at(i)->GetBackend()->ComputeBaseOTs();
          motion_parties.at(i)->Finish();
        }));
  }
  std::for_each(std::begin(futs), std::end(futs), [](auto &fut) { fut.get(); });

  for (std::size_t party_id = 0; party_id < num_parties; ++party_id) {
    for (auto other_id = 0u; other_id < num_parties; ++other_id) {
      if (party_id == other_id) {
        continue;
      }
      auto &base_ots_data =
          motion_parties.at(party_id)->GetBackend()->GetBaseOTProvider()->get_base_ots_data(
              other_id);

      const auto &base_ots_recv = base_ots_data.GetReceiverData();
      // base_ots_recv.is_ready_condition_->Wait();
      auto &bo = base_ots.at(party_id).at(other_id);
      for (auto j = 0ull; j < bo.messages_c_.size(); ++j) {
        std::copy(base_ots_recv.messages_c_.at(j).begin(), base_ots_recv.messages_c_.at(j).end(),
                  bo.messages_c_.at(j).begin());
      }
      base_ots.at(party_id).at(other_id).c = base_ots_recv.c_;

      const auto &base_ots_snd = base_ots_data.GetSenderData();
      // base_ots_snd.is_ready_condition_->Wait();

      for (auto k = 0ull; k < bo.messages_0_.size(); ++k) {
        std::copy(base_ots_snd.messages_0_.at(k).begin(), base_ots_snd.messages_0_.at(k).end(),
                  bo.messages_0_.at(k).begin());
      }
      for (auto k = 0ull; k < bo.messages_1_.size(); ++k) {
        std::copy(base_ots_snd.messages_1_.at(k).begin(), base_ots_snd.messages_1_.at(k).end(),
                  bo.messages_1_.at(k).begin());
      }
    }
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
          ASSERT_EQ(base_ots_a.messages_c_.at(k), base_ots_b.messages_1_.at(k));
        } else {
          ASSERT_EQ(base_ots_a.messages_c_.at(k), base_ots_b.messages_0_.at(k));
        }

        if (base_ots_b.c.Get(k)) {
          ASSERT_EQ(base_ots_b.messages_c_.at(k), base_ots_a.messages_1_.at(k));
        } else {
          ASSERT_EQ(base_ots_b.messages_c_.at(k), base_ots_a.messages_0_.at(k));
        }
      }
    }
  }
}
