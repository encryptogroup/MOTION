// MIT License
//
// Copyright (c) 2019 Lennart Braun
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
#include "crypto/multiplication_triple/sp_provider.h"

namespace {

constexpr auto num_parties_list = {2u, 3u};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
void template_test() {
  for (auto i = 0ull; i < TEST_ITERATIONS; ++i) {
    for (auto num_parties : {2u, 3u}) {
      std::size_t num_sps = 100;

      try {
        auto motion_parties = MOTION::GetNLocalParties(num_parties, PORT_OFFSET);
        for (auto& p : motion_parties) {
          p->GetLogger()->SetEnabled(DETAILED_LOGGING_ENABLED);
          p->GetBackend()->GetSPProvider()->template RequestSPs<T>(num_sps);
        }

        std::vector<std::future<void>> futs;
        futs.reserve(num_parties);
        for (auto& p : motion_parties) {
          futs.emplace_back(std::async(std::launch::async, [&p] {
            auto& backend = p->GetBackend();
            auto& sp_provider = backend->GetSPProvider();
            sp_provider->PreSetup();
            backend->OTExtensionSetup();
            sp_provider->Setup();
          }));
        }
        std::for_each(futs.begin(), futs.end(), [](auto& f) { f.get(); });

        const auto& spp_0 = motion_parties.at(0)->GetBackend()->GetSPProvider();
        std::vector<T> a = spp_0->template GetSPsAll<T>().a;
        std::vector<T> c = spp_0->template GetSPsAll<T>().c;
        EXPECT_EQ(a.size(), num_sps);
        EXPECT_EQ(c.size(), num_sps);
        for (std::size_t j = 1; j < motion_parties.size(); ++j) {
          const auto& spp_j = motion_parties.at(j)->GetBackend()->GetSPProvider();
          for (std::size_t k = 0; k < a.size(); ++k) {
            a.at(k) += spp_j->template GetSPsAll<T>().a.at(k);
            c.at(k) += spp_j->template GetSPsAll<T>().c.at(k);
          }
        }
        for (std::size_t k = 0; k < a.size(); ++k) {
          EXPECT_EQ(c.at(k), static_cast<T>(a.at(k) * a.at(k)));
        }

        futs.clear();

        for (auto& p : motion_parties) {
          futs.emplace_back(std::async(std::launch::async, [&p] { p->Finish(); }));
        }
        std::for_each(futs.begin(), futs.end(), [](auto& f) { f.get(); });

      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(SquarePairs, Integer) {
  template_test<std::uint8_t>();
  template_test<std::uint16_t>();
  template_test<std::uint32_t>();
  template_test<std::uint64_t>();
  template_test<__uint128_t>();
}

}  // namespace
