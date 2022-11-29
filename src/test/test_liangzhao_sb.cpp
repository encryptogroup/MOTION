// MIT License
//
// Copyright (c) 2022 Liang Zhao
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

#include <gtest/gtest.h>

#include "test_constants.h"

#include "base/party.h"
#include "multiplication_triple/sb_impl.h"
#include "multiplication_triple/sb_provider.h"
#include "multiplication_triple/sp_provider.h"
#include "oblivious_transfer/base_ots/base_ot_provider.h"

namespace {

constexpr auto kNumberOfPartiesList = {2u, 3u};

// test not passed, runtime error
template <typename T>
void TemplateBoostUintTest() {
  // this value must be greater than 1, otherwise the test will fail
  constexpr std::size_t kNumberOfSbs = 100;

  for (auto i = 0ull; i < kTestIterations; ++i) {
    for (auto number_of_parties : {2u, 3u}) {
      try {
        auto motion_parties =
            encrypto::motion::MakeLocallyConnectedParties(number_of_parties, kPortOffset);
        for (auto& party : motion_parties) {
          party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
          party->GetBackend()->GetSbProvider().template RequestSbs<T>(kNumberOfSbs);
        }

        // std::cout<<"template RequestSbs<T>(kNumberOfSbs)"<<std::endl;

        std::vector<std::future<void>> futures;
        futures.reserve(number_of_parties);
        for (std::size_t j = 0; j < number_of_parties; ++j) {
          futures.emplace_back(std::async(std::launch::async, [&motion_parties, j] {
            auto& backend = motion_parties.at(j)->GetBackend();
            backend->GetBaseProvider().Setup();
            auto& sp_provider = backend->GetSpProvider();
            auto& sb_provider = backend->GetSbProvider();
            sb_provider.PreSetup();
            sp_provider.PreSetup();
            backend->GetOtProviderManager().PreSetup();
            backend->GetBaseOtProvider().PreSetup();
            backend->Synchronize();
            backend->GetBaseOtProvider().ComputeBaseOts();
            backend->OtExtensionSetup();
            sp_provider.Setup();
            sb_provider.Setup();  // // ! runtime error since this line
            motion_parties.at(j)->Finish();
          }));
        }
        std::for_each(futures.begin(), futures.end(), [](auto& f) { f.get(); });

        // std::cout << "for_each(futures.begin(), futures.end" << std::endl;

        auto& sb_provider_0 = motion_parties.at(0)->GetBackend()->GetSbProvider();
        std::vector<T> a = sb_provider_0.template GetSbsAll<T>();

        // std::cout << "sb_provider_0->template GetSbsAll" << std::endl;

        EXPECT_EQ(a.size(), kNumberOfSbs);
        for (std::size_t j = 1; j < motion_parties.size(); ++j) {
          auto& sb_provider_j = motion_parties.at(j)->GetBackend()->GetSbProvider();
          for (std::size_t k = 0; k < a.size(); ++k) {
            a.at(k) += sb_provider_j.template GetSbsAll<T>().at(k);
          }
        }
        for (std::size_t k = 0; k < a.size(); ++k) {
          EXPECT_TRUE(a.at(k) == T(0) || a.at(k) == T(1));
        }

        // with kNumberOfSbs bits generated there should be at least a 0 and a 1 whp
        EXPECT_TRUE(std::any_of(a.cbegin(), a.cend(), [](auto& b) { return b == 0; }));
        EXPECT_TRUE(std::any_of(a.cbegin(), a.cend(), [](auto& b) { return b == 1; }));

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

TEST(SharedBitsBoostUint, IntegerBoostUint) {
  // TemplateBoostUintTest<std::uint64_t>();
  TemplateBoostUintTest<__uint128_t>();  // // ! runtime error
}

// test passed
TEST(SharedBitsImplementationBoostUint, InvertBoostUint) {
  constexpr std::size_t kK = 6;
  constexpr bm::uint256_t kA = 47;
  bm::uint256_t x = encrypto::motion::detail::invert(kK, kA);
  EXPECT_EQ(x, 15);
}

// test passed
TEST(SharedBitsImplementationBoostUint, SqrtBoostUint) {
  constexpr std::size_t kK = 6;
  constexpr bm::uint256_t KA = 49;
  bm::uint256_t x = encrypto::motion::detail::sqrt(kK, KA);
  EXPECT_EQ(x, 7);
}

template <typename T>
std::pair<encrypto::motion::SpVector<T>, std::vector<encrypto::motion::SpVector<T>>>
GenerateSpVectorsBoostUint(std::size_t number_of_parties, std::size_t size) {
  encrypto::motion::SpVector<T> plain;
  plain.a = encrypto::motion::RandomVectorBoostUint<T>(size);
  std::transform(plain.a.cbegin(), plain.a.cend(), std::back_inserter(plain.c),
                 [](auto a) { return a * a; });
  std::vector<encrypto::motion::SpVector<T>> shares(number_of_parties);
  std::copy(plain.a.cbegin(), plain.a.cend(), std::back_inserter(shares.at(0).a));
  std::copy(plain.c.cbegin(), plain.c.cend(), std::back_inserter(shares.at(0).c));
  for (std::size_t i = 1; i < number_of_parties; ++i) {
    shares.at(i).a = encrypto::motion::RandomVectorBoostUint<T>(size);
    shares.at(i).c = encrypto::motion::RandomVectorBoostUint<T>(size);
  }
  for (std::size_t j = 0; j < size; ++j) {
    for (std::size_t i = 1; i < number_of_parties; ++i) {
      shares.at(0).a.at(j) -= shares.at(i).a.at(j);
      shares.at(0).c.at(j) -= shares.at(i).c.at(j);
    }
  }
  return {plain, shares};
}

// test passed
TEST(SharedBitsImplementationBoostUint, HelperBoostUint) {
  constexpr std::size_t kNumberOfParties = 3;
  constexpr std::size_t kNumberOfSbs = 100;
  auto [plain_sps, shared_sps] =
      GenerateSpVectorsBoostUint<bm::uint256_t>(kNumberOfParties, kNumberOfSbs);
  std::vector<std::vector<bm::uint256_t>> shares_a;
  std::vector<std::vector<bm::uint256_t>> shares_c;
  shares_a.reserve(shared_sps.size());
  shares_c.reserve(shared_sps.size());
  for (auto& sp_vector : shared_sps) {
    shares_a.push_back(std::move(sp_vector.a));
    shares_c.push_back(std::move(sp_vector.c));
  }
  auto reconstructed_a = encrypto::motion::AddVectors<bm::uint256_t>(shares_a);
  auto reconstructed_c = encrypto::motion::AddVectors<bm::uint256_t>(shares_c);
  EXPECT_EQ(plain_sps.a, reconstructed_a);
  EXPECT_EQ(plain_sps.c, reconstructed_c);
}

// test passed
TEST(SharedBitsImplementationBoostUint, Phase1BoostUint) {
  std::size_t kNumberOfParties = 3;
  std::size_t kNumberOfSbs = 100;
  auto reduce_mod = [](auto& v, auto k) {
    bm::uint256_t mod_mask = (bm::uint256_t(1) << k) - 1;
    std::transform(v.cbegin(), v.cend(), v.begin(), [mod_mask](auto a) { return a & mod_mask; });
  };

  auto [plain_sps, shared_sps] =
      GenerateSpVectorsBoostUint<bm::uint256_t>(kNumberOfParties, kNumberOfSbs);
  std::vector<std::vector<bm::uint256_t>> wb1s;
  std::vector<std::vector<bm::uint256_t>> wb2s;
  for (std::size_t i = 0; i < kNumberOfParties; ++i) {
    auto [wb1, wb2] =
        encrypto::motion::detail::compute_sbs_phase_1_BoostUint<__uint128_t, bm::uint256_t>(
            kNumberOfSbs, i, shared_sps.at(i));
    wb1s.emplace_back(std::move(wb1));
    wb2s.emplace_back(std::move(wb2));
  }

  // party 1 has the odd share of a
  EXPECT_TRUE(
      std::all_of(wb1s.at(0).cbegin(), wb1s.at(0).cend(), [](auto a) { return (a & 1) == 1; }));
  // all other parties have even shares of a
  for (std::size_t i = 1; i < kNumberOfParties; ++i) {
    EXPECT_TRUE(
        std::all_of(wb1s.at(i).cbegin(), wb1s.at(i).cend(), [](auto a) { return (a & 1) == 0; }));
  }

  auto a = encrypto::motion::AddVectors<bm::uint256_t>(wb1s);
  reduce_mod(a, 34);
  // a is odd
  EXPECT_TRUE(std::all_of(a.cbegin(), a.cend(), [](auto a) { return (a & 1) == 1; }));

  auto masked_a = encrypto::motion::AddVectors<bm::uint256_t>(wb2s);
  reduce_mod(masked_a, 34);
  auto unmasked_masked_a = encrypto::motion::AddVectors<bm::uint256_t>(masked_a, plain_sps.a);
  reduce_mod(unmasked_masked_a, 34);
  // check that a was masked correctly
  EXPECT_EQ(unmasked_masked_a, a);
}

// test passed
TEST(SharedBitsImplBoostUint, Phase2BoostUint) {
  std::size_t kNumberOfParties = 3;
  std::size_t kNumberOfSbs = 100;
  auto reduce_mod = [](auto& v, auto k) {
    bm::uint256_t mod_mask = (bm::uint256_t(1) << k) - 1;
    std::transform(v.cbegin(), v.cend(), v.begin(), [mod_mask](auto a) { return a & mod_mask; });
  };

  auto [plain_sps, shared_sps] =
      GenerateSpVectorsBoostUint<bm::uint256_t>(kNumberOfParties, kNumberOfSbs);
  std::vector<std::vector<bm::uint256_t>> wb1s;
  std::vector<std::vector<bm::uint256_t>> wb2s;
  for (std::size_t i = 0; i < kNumberOfParties; ++i) {
    auto [wb1, wb2] =
        encrypto::motion::detail::compute_sbs_phase_1_BoostUint<__uint128_t, bm::uint256_t>(
            kNumberOfSbs, i, shared_sps.at(i));
    wb1s.emplace_back(std::move(wb1));
    wb2s.emplace_back(std::move(wb2));
  }

  auto masked_a = encrypto::motion::AddVectors<bm::uint256_t>(wb2s);
  std::fill(wb2s.begin(), wb2s.end(), masked_a);

  for (std::size_t i = 0; i < kNumberOfParties; ++i) {
    encrypto::motion::detail::compute_sbs_phase_2_BoostUint<__uint128_t, bm::uint256_t>(
        wb1s.at(i), wb2s.at(i), i, shared_sps.at(i));
  }

  auto a = encrypto::motion::AddVectors<bm::uint256_t>(wb1s);
  reduce_mod(a, 34);
  std::vector<bm::uint256_t> a_squared_plain;
  std::transform(a.cbegin(), a.cend(), std::back_inserter(a_squared_plain),
                 [](auto a) { return a * a; });
  reduce_mod(a_squared_plain, 34);

  // check that wb2 contains shares of a^2
  auto a_squared = encrypto::motion::AddVectors<bm::uint256_t>(wb2s);
  reduce_mod(a_squared, 34);
  EXPECT_EQ(a_squared, a_squared_plain);
}

// test passed
TEST(SharedBitsImplementationBoostUint, Phase3BoostUint) {
  constexpr std::size_t kNumberOfParties = 3;
  constexpr std::size_t kNumberOfSbs = 100;
  auto reduce_mod = [](auto& v, auto k) {
    bm::uint256_t mod_mask = (bm::uint256_t(1) << k) - 1;
    std::transform(v.cbegin(), v.cend(), v.begin(), [mod_mask](auto a) {
      __uint128_t result = a & mod_mask;
      return result;
    });
  };

  auto [plain_sps, shared_sps] =
      GenerateSpVectorsBoostUint<bm::uint256_t>(kNumberOfParties, kNumberOfSbs);
  std::vector<std::vector<bm::uint256_t>> wb1s;
  std::vector<std::vector<bm::uint256_t>> wb2s;
  for (std::size_t i = 0; i < kNumberOfParties; ++i) {
    auto [wb1, wb2] =
        encrypto::motion::detail::compute_sbs_phase_1_BoostUint<__uint128_t, bm::uint256_t>(
            kNumberOfSbs, i, shared_sps.at(i));
    wb1s.emplace_back(std::move(wb1));
    wb2s.emplace_back(std::move(wb2));
  }

  auto masked_a = encrypto::motion::AddVectors<bm::uint256_t>(wb2s);
  std::fill(wb2s.begin(), wb2s.end(), masked_a);

  for (std::size_t i = 0; i < kNumberOfParties; ++i) {
    encrypto::motion::detail::compute_sbs_phase_2_BoostUint<__uint128_t, bm::uint256_t>(
        wb1s.at(i), wb2s.at(i), i, shared_sps.at(i));
  }

  auto a_squared = encrypto::motion::AddVectors<bm::uint256_t>(wb2s);
  reduce_mod(a_squared, 34);
  std::fill(wb2s.begin(), wb2s.end(), a_squared);

  std::vector<std::vector<__uint128_t>> sbs_128(kNumberOfParties);
  for (std::size_t i = 0; i < kNumberOfParties; ++i) {
    encrypto::motion::detail::compute_sbs_phase_3_BoostUint<__uint128_t, bm::uint256_t>(
        wb1s.at(i), wb2s.at(i), sbs_128.at(i), i);
  }

  auto bits = encrypto::motion::AddVectors<__uint128_t>(sbs_128);
  reduce_mod(bits, 32);
  EXPECT_TRUE(std::all_of(bits.cbegin(), bits.cend(), [](auto b) { return b == 0 || b == 1; }));
}

}  // namespace
