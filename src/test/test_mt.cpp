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
#include "multiplication_triple/mt_provider.h"
#include "oblivious_transfer/base_ots/base_ot_provider.h"

namespace {

constexpr auto kNumberOfPartiesList = {2u, 3u};

TEST(MultiplicationTriples, Binary) {
  constexpr std::size_t kNumberOfMts = 100;
  for (auto i = 0ull; i < kTestIterations; ++i) {
    for (auto number_of_parties : {2u, 3u}) {
      try {
        auto motion_parties =
            encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);

        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetBackend()->GetMtProvider().RequestBinaryMts(kNumberOfMts);
        }

        std::vector<std::future<void>> futures;
        futures.reserve(number_of_parties);
        for (std::size_t j = 0; j < number_of_parties; ++j) {
          futures.emplace_back(std::async(std::launch::async, [&motion_parties, j] {
            auto& backend = motion_parties.at(j)->GetBackend();
            backend->GetBaseProvider().Setup();
            auto& mt_provider = backend->GetMtProvider();
            mt_provider.PreSetup();
            backend->GetOtProviderManager().PreSetup();
            backend->GetBaseOtProvider().PreSetup();
            backend->Synchronize();
            backend->GetBaseOtProvider().ComputeBaseOts();
            backend->OtExtensionSetup();
            mt_provider.Setup();
            motion_parties.at(j)->Finish();
          }));
        }

        std::for_each(futures.begin(), futures.end(), [](auto& f) { f.get(); });

        // check multiplication triples
        encrypto::motion::BitVector<> a, b, c;
        a = motion_parties.at(0)->GetBackend()->GetMtProvider().GetBinaryAll().a;
        b = motion_parties.at(0)->GetBackend()->GetMtProvider().GetBinaryAll().b;
        c = motion_parties.at(0)->GetBackend()->GetMtProvider().GetBinaryAll().c;

        for (auto j = 1ull; j < motion_parties.size(); ++j) {
          a ^= motion_parties.at(j)->GetBackend()->GetMtProvider().GetBinaryAll().a;
          b ^= motion_parties.at(j)->GetBackend()->GetMtProvider().GetBinaryAll().b;
          c ^= motion_parties.at(j)->GetBackend()->GetMtProvider().GetBinaryAll().c;
        }
        EXPECT_EQ(c, a & b);

        futures.clear();

        for (auto& party : motion_parties) {
          futures.emplace_back(std::async(std::launch::async, [&party] { party->Finish(); }));
        }
        std::for_each(futures.begin(), futures.end(), [](auto& f) { f.get(); });

      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
void TemplateTestInteger() {
  constexpr std::size_t kNumberOfMts = 100;
  for (auto i = 0ull; i < kTestIterations; ++i) {
    for (auto number_of_parties : {2u, 3u}) {
      try {
        auto motion_parties =
            encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetBackend()->GetMtProvider().template RequestArithmeticMts<T>(kNumberOfMts);
        }

        std::vector<std::future<void>> futures;
        futures.reserve(number_of_parties);
        for (std::size_t j = 0; j < number_of_parties; ++j) {
          futures.emplace_back(std::async(std::launch::async, [&motion_parties, j] {
            auto& backend = motion_parties.at(j)->GetBackend();
            backend->GetBaseProvider().Setup();
            auto& mt_provider = backend->GetMtProvider();
            mt_provider.PreSetup();
            backend->GetOtProviderManager().PreSetup();
            backend->GetBaseOtProvider().PreSetup();
            backend->Synchronize();
            backend->GetBaseOtProvider().ComputeBaseOts();
            backend->OtExtensionSetup();
            mt_provider.Setup();
            motion_parties.at(j)->Finish();
          }));
        }
        std::for_each(futures.begin(), futures.end(), [](auto& f) { f.get(); });

        const auto& mt_provider_0 = motion_parties.at(0)->GetBackend()->GetMtProvider();
        auto a = mt_provider_0.template GetIntegerAll<T>().a;
        auto b = mt_provider_0.template GetIntegerAll<T>().b;
        auto c = mt_provider_0.template GetIntegerAll<T>().c;
        EXPECT_EQ(a.size(), kNumberOfMts);
        EXPECT_EQ(b.size(), kNumberOfMts);
        EXPECT_EQ(c.size(), kNumberOfMts);
        for (std::size_t j = 1; j < motion_parties.size(); ++j) {
          const auto& mt_provider_j = motion_parties.at(j)->GetBackend()->GetMtProvider();
          for (std::size_t k = 0; k < a.size(); ++k) {
            a.at(k) += mt_provider_j.template GetIntegerAll<T>().a.at(k);
            b.at(k) += mt_provider_j.template GetIntegerAll<T>().b.at(k);
            c.at(k) += mt_provider_j.template GetIntegerAll<T>().c.at(k);
          }
        }
        for (std::size_t k = 0; k < a.size(); ++k) {
          EXPECT_EQ(c.at(k), static_cast<T>(a.at(k) * b.at(k)));
        }

        futures.clear();

        for (auto& party : motion_parties) {
          futures.emplace_back(std::async(std::launch::async, [&party] { party->Finish(); }));
        }
        std::for_each(futures.begin(), futures.end(), [](auto& f) { f.get(); });

      } catch (std::exception& e) {
        std::cerr << e.what() << std::endl;
      }
    }
  }
}

TEST(MultiplicationTriples, Integer) {
  TemplateTestInteger<std::uint8_t>();
  TemplateTestInteger<std::uint16_t>();
  TemplateTestInteger<std::uint32_t>();
  TemplateTestInteger<std::uint64_t>();
}

}  // namespace
