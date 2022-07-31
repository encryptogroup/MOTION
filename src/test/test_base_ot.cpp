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
#include "data_storage/base_ot_data.h"
#include "oblivious_transfer/base_ots/base_ot_provider.h"

using namespace encrypto::motion;

TEST(ObliviousTransfer, BaseOt) {
  const std::size_t number_of_parties = 2;
  const std::array<std::size_t, 4> number_of_base_ots = {128, 256, 512, 1024};

  struct base_ots_t {
    base_ots_t(std::size_t num_base_ots)
        : messages_c(num_base_ots),
          messages_0(num_base_ots),
          messages_1(num_base_ots),
          c(BitVector(num_base_ots)) {}
    std::vector<std::array<std::byte, 16>> messages_c, messages_0, messages_1;
    encrypto::motion::BitVector<> c;
  };

  for (auto& num_base_ots : number_of_base_ots) {
    auto motion_parties = MakeLocallyConnectedParties(number_of_parties, 0);
    for (auto& party : motion_parties) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
    }

    std::vector<std::vector<base_ots_t>> base_ots(number_of_parties);
    for (auto& v : base_ots) {
      v.resize(number_of_parties, num_base_ots);
    }

    for (std::size_t i = 0; i < number_of_parties; ++i) {
      motion_parties.at(i)->GetBackend()->GetBaseOtProvider().Request(num_base_ots);
      motion_parties.at(i)->GetBackend()->GetBaseOtProvider().PreSetup();
    }

    std::vector<std::future<void>> futures;
    futures.reserve(number_of_parties);

    for (std::size_t i = 0; i < number_of_parties; ++i) {
      futures.emplace_back(std::async(std::launch::async, [&motion_parties, i]() {
        motion_parties.at(i)->GetBackend()->Synchronize();
        motion_parties.at(i)->GetBackend()->ComputeBaseOts();
        motion_parties.at(i)->Finish();
      }));
    }
    std::for_each(std::begin(futures), std::end(futures), [](auto& fut) { fut.get(); });

    for (std::size_t party_id = 0; party_id < number_of_parties; ++party_id) {
      for (auto other_id = 0u; other_id < number_of_parties; ++other_id) {
        if (party_id == other_id) {
          continue;
        }
        auto& base_ots_data =
            motion_parties.at(party_id)->GetBackend()->GetBaseOtProvider().GetBaseOtsData(
                other_id);

        const auto& base_ots_receiver = base_ots_data.GetReceiverData();
        // base_ots_receiver.is_ready_condition_->Wait();

        // check if number of computed base ots is correct
        ASSERT_EQ(base_ots_receiver.c.GetSize(), num_base_ots);
        ASSERT_EQ(base_ots_receiver.messages_c.size(), num_base_ots);

        auto& base_ot = base_ots.at(party_id).at(other_id);
        for (auto j = 0ull; j < base_ot.messages_c.size(); ++j) {
          std::copy(base_ots_receiver.messages_c.at(j).begin(),
                    base_ots_receiver.messages_c.at(j).end(), base_ot.messages_c.at(j).begin());
        }
        base_ots.at(party_id).at(other_id).c = base_ots_receiver.c;

        const auto& base_ots_sender = base_ots_data.GetSenderData();
        // base_ots_sender.is_ready_condition_->Wait();

        // check if number of computed base ots is correct
        ASSERT_EQ(base_ots_sender.messages_0.size(), num_base_ots);
        ASSERT_EQ(base_ots_sender.messages_1.size(), num_base_ots);

        for (auto k = 0ull; k < base_ot.messages_0.size(); ++k) {
          std::copy(base_ots_sender.messages_0.at(k).begin(),
                    base_ots_sender.messages_0.at(k).end(), base_ot.messages_0.at(k).begin());
        }
        for (auto k = 0ull; k < base_ot.messages_1.size(); ++k) {
          std::copy(base_ots_sender.messages_1.at(k).begin(),
                    base_ots_sender.messages_1.at(k).end(), base_ot.messages_1.at(k).begin());
        }
      }
    }

    for (auto i = 0u; i < number_of_parties; ++i) {
      for (auto j = 0u; j < number_of_parties; ++j) {
        if (i == j) {
          continue;
        }
        auto& base_ots_a = base_ots.at(i).at(j);
        auto& base_ots_b = base_ots.at(j).at(i);

        for (auto k = 0u; k < base_ots_a.messages_c.size(); ++k) {
          if (base_ots_a.c.Get(k)) {
            ASSERT_EQ(base_ots_a.messages_c.at(k), base_ots_b.messages_1.at(k));
          } else {
            ASSERT_EQ(base_ots_a.messages_c.at(k), base_ots_b.messages_0.at(k));
          }

          if (base_ots_b.c.Get(k)) {
            ASSERT_EQ(base_ots_b.messages_c.at(k), base_ots_a.messages_1.at(k));
          } else {
            ASSERT_EQ(base_ots_b.messages_c.at(k), base_ots_a.messages_0.at(k));
          }
        }
      }
    }
  }
}
