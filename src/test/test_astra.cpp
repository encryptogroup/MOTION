// MIT License
//
// Copyright (c) 2019 Oliver Schick
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

#include <gtest/gtest.h>
#include <algorithm>

#include "base/party.h"
#include "protocols/share_wrapper.h"
#include "test_constants.h"
#include "test_helpers.h"

constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max();
constexpr auto kAstra = encrypto::motion::MpcProtocol::kAstra;

namespace mo = encrypto::motion;

template <typename T>
class AstraTest : public ::testing::Test {
 protected:
  void SetUp() override { InstantiateParties(); }

  void InstantiateParties() {
    parties_ = std::move(mo::MakeLocallyConnectedParties(number_of_parties_, kPortOffset));
    for (auto& party : parties_) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(false);
    }
  }

  void GenerateDiverseInputs() {
    zeros_single_.emplace_back(0);
    zeros_simd_.resize(number_of_simd_, 0);

    std::mt19937_64 mt(seed_);
    std::uniform_int_distribution<T> dist;

    for (T& t : inputs_single_) t = dist(mt);

    for (auto& v : inputs_simd_) {
      v.resize(number_of_simd_);
      for (T& t : v) t = dist(mt);
    }
  }

  void ShareDiverseInputs() {
    for (std::size_t input_owner : {0, 1, 2}) {
      for (std::size_t party_id : {0, 1, 2}) {
        if (party_id == input_owner) {
          shared_inputs_single_[party_id][input_owner] =
              parties_.at(party_id)->template In<kAstra>(inputs_single_[input_owner], input_owner);
          shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kAstra>(inputs_simd_[input_owner], input_owner);
        } else {
          shared_inputs_single_[party_id][input_owner] =
              parties_.at(party_id)->template In<kAstra>(zeros_single_, input_owner);
          shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kAstra>(zeros_simd_, input_owner);
        }
      }
    }
  }

  void GenerateDotProductInputs() {
    zeros_single_.emplace_back(0);
    zeros_simd_.resize(number_of_simd_, 0);

    std::mt19937_64 mt(seed_);
    std::uniform_int_distribution<T> dist;

    for (auto& v : inputs_dot_product_single_) {
      v.resize(dot_product_vector_size_);
      for (T& t : v) t = dist(mt);
    }

    for (auto& vv : inputs_dot_product_simd_) {
      vv.resize(dot_product_vector_size_);
      for (auto& v : vv) {
        v.resize(number_of_simd_);
        for (T& t : v) t = dist(mt);
      }
    }
  }

  void ShareDotProductInputs() {
    constexpr std::size_t input_owner = 0;
    for (std::size_t party_id : {0, 1, 2}) {
      for (std::size_t vector_i : {0, 1}) {
        shared_dot_product_inputs_single_[party_id][vector_i].resize(dot_product_vector_size_);
        shared_dot_product_inputs_simd_[party_id][vector_i].resize(dot_product_vector_size_);
        for (std::size_t element_j = 0; element_j < dot_product_vector_size_; ++element_j) {
          shared_dot_product_inputs_single_[party_id][vector_i][element_j] =
              parties_.at(party_id)->template In<kAstra>(
                  inputs_dot_product_single_[vector_i][element_j], input_owner);
          shared_dot_product_inputs_simd_[party_id][vector_i][element_j] =
              parties_.at(party_id)->template In<kAstra>(
                  inputs_dot_product_simd_[vector_i][element_j], input_owner);
        }
      }
    }
  }

  static constexpr T seed_{0};
  static constexpr std::size_t number_of_simd_{1000};
  static constexpr std::size_t dot_product_vector_size_{100};

  std::array<T, 3> inputs_single_;
  std::array<std::vector<T>, 3> inputs_simd_;
  std::array<std::vector<T>, 2> inputs_dot_product_single_;
  std::array<std::vector<std::vector<T>>, 2> inputs_dot_product_simd_;

  std::vector<T> zeros_single_;
  std::vector<T> zeros_simd_;

  static constexpr std::size_t number_of_parties_{3};
  std::vector<mo::PartyPointer> parties_;

  std::array<std::array<mo::ShareWrapper, 3>, 3> shared_inputs_single_;
  std::array<std::array<mo::ShareWrapper, 3>, 3> shared_inputs_simd_;

  std::array<std::array<std::vector<mo::ShareWrapper>, 2>, 3> shared_dot_product_inputs_single_;
  std::array<std::array<std::vector<mo::ShareWrapper>, 2>, 3> shared_dot_product_inputs_simd_;
};

using UintTypes = ::testing::Types<std::uint8_t, std::uint16_t, std::uint32_t, std::uint64_t>;
TYPED_TEST_SUITE(AstraTest, UintTypes);

TYPED_TEST(AstraTest, InputOutput) {
  this->GenerateDiverseInputs();
  this->ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      std::array<mo::ShareWrapper, 3> share_output_single, share_output_simd;
      for (std::size_t other_party_id = 0; other_party_id < this->number_of_parties_;
           ++other_party_id) {
        share_output_single[other_party_id] =
            this->shared_inputs_single_[party_id][other_party_id].Out(kAll);
        share_output_simd[other_party_id] =
            this->shared_inputs_simd_[party_id][other_party_id].Out(kAll);
      }

      this->parties_[party_id]->Run();

      for (std::size_t input_owner = 0; input_owner < this->number_of_parties_; ++input_owner) {
        EXPECT_EQ(share_output_single[input_owner].template As<TypeParam>(),
                  this->inputs_single_[input_owner]);
        EXPECT_EQ(share_output_simd[input_owner].template As<std::vector<TypeParam>>(),
                  this->inputs_simd_[input_owner]);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TYPED_TEST(AstraTest, Addition) {
  this->GenerateDiverseInputs();
  this->ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_add_single = this->shared_inputs_single_[party_id][0] +
                              this->shared_inputs_single_[party_id][1] +
                              this->shared_inputs_single_[party_id][2];
      auto share_add_simd = this->shared_inputs_simd_[party_id][0] +
                            this->shared_inputs_simd_[party_id][1] +
                            this->shared_inputs_simd_[party_id][2];

      auto share_output_single_all = share_add_single.Out();
      auto share_output_simd_all = share_add_simd.Out();

      this->parties_[party_id]->Run();

      {
        TypeParam circuit_result_single = share_output_single_all.template As<TypeParam>();
        TypeParam expected_result_single = mo::SumReduction<TypeParam>(this->inputs_single_);
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<TypeParam> circuit_result_simd =
            share_output_simd_all.template As<std::vector<TypeParam>>();
        const std::vector<TypeParam> expected_result_simd =
            std::move(mo::RowSumReduction<TypeParam>(this->inputs_simd_));
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TYPED_TEST(AstraTest, Subtraction) {
  this->GenerateDiverseInputs();
  this->ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_sub_single = this->shared_inputs_single_[party_id][0] -
                              this->shared_inputs_single_[party_id][1] -
                              this->shared_inputs_single_[party_id][2];
      auto share_sub_simd = this->shared_inputs_simd_[party_id][0] -
                            this->shared_inputs_simd_[party_id][1] -
                            this->shared_inputs_simd_[party_id][2];

      auto share_output_single_all = share_sub_single.Out();
      auto share_output_simd_all = share_sub_simd.Out();

      this->parties_[party_id]->Run();

      {
        TypeParam circuit_result_single = share_output_single_all.template As<TypeParam>();
        TypeParam expected_result_single = mo::SubReduction<TypeParam>(this->inputs_single_);
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<TypeParam> circuit_result_simd =
            share_output_simd_all.template As<std::vector<TypeParam>>();
        const std::vector<TypeParam> expected_result_simd =
            std::move(mo::RowSubReduction<TypeParam>(this->inputs_simd_));
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TYPED_TEST(AstraTest, Multiplication) {
  this->GenerateDiverseInputs();
  this->ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_mul_single = this->shared_inputs_single_[party_id][0] *
                              this->shared_inputs_single_[party_id][1] *
                              this->shared_inputs_single_[party_id][2];
      auto share_mul_simd = this->shared_inputs_simd_[party_id][0] *
                            this->shared_inputs_simd_[party_id][1] *
                            this->shared_inputs_simd_[party_id][2];

      auto share_output_single_all = share_mul_single.Out();
      auto share_output_simd_all = share_mul_simd.Out();

      this->parties_[party_id]->Run();

      {
        TypeParam circuit_result_single = share_output_single_all.template As<TypeParam>();
        TypeParam expected_result_single = mo::MulReduction<TypeParam>(this->inputs_single_);
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<TypeParam> circuit_result_simd =
            share_output_simd_all.template As<std::vector<TypeParam>>();
        const std::vector<TypeParam> expected_result_simd =
            std::move(mo::RowMulReduction<TypeParam>(this->inputs_simd_));
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TYPED_TEST(AstraTest, DotPdoruct) {
  this->GenerateDotProductInputs();
  this->ShareDotProductInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id < this->parties_.size(); ++party_id) {
    futures[party_id] = std::async([this, party_id]() {
      auto share_dp_single = mo::DotProduct(this->shared_dot_product_inputs_single_[party_id][0],
                                            this->shared_dot_product_inputs_single_[party_id][1]);
      auto share_dp_simd = mo::DotProduct(this->shared_dot_product_inputs_simd_[party_id][0],
                                          this->shared_dot_product_inputs_simd_[party_id][1]);

      auto share_output_single_all = share_dp_single.Out();
      auto share_output_simd_all = share_dp_simd.Out();

      this->parties_[party_id]->Run();

      {
        TypeParam circuit_result_single = share_output_single_all.template As<TypeParam>();
        TypeParam expected_result_single = mo::DotProduct<TypeParam>(
            this->inputs_dot_product_single_[0], this->inputs_dot_product_single_[1]);
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<TypeParam> circuit_result_simd =
            share_output_simd_all.template As<std::vector<TypeParam>>();
        const std::vector<TypeParam> expected_result_simd = std::move(mo::RowDotProduct<TypeParam>(
            this->inputs_dot_product_simd_[0], this->inputs_dot_product_simd_[1]));
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      this->parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}