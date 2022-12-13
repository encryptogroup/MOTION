// MIT License
//
// Copyright (c) 2022 Oliver Schick
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
#include "protocols/boolean_astra/boolean_astra_wire.h"
#include "test_constants.h"
#include "test_helpers.h"
#include "utility/bit_vector.h"

constexpr std::size_t kAll = std::numeric_limits<std::int64_t>::max();
constexpr auto kBooleanAstra = encrypto::motion::MpcProtocol::kBooleanAstra;

namespace mo = encrypto::motion;

class BooleanAstraTestParameters {
  static constexpr size_t kDefaultTestBitLength = 32u;
 
 public:
  BooleanAstraTestParameters() { InstantiateParties(); }

  void InstantiateParties() {
    parties_ = std::move(mo::MakeLocallyConnectedParties(number_of_parties_, kPortOffset));
    for (auto& party : parties_) {
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetConfiguration()->SetOnlineAfterSetup(false);
    }
  }

  void GenerateDiverseInputs() {
    zeros_single_.emplace_back(kDefaultTestBitLength, false);
    zeros_simd_.resize(number_of_simd_, mo::BitVector<>(kDefaultTestBitLength, false));

    for (mo::BitVector<>& t : inputs_single_) {
      t = mo::BitVector<>::SecureRandom(kDefaultTestBitLength);
    }

    for (auto& v : inputs_simd_) {
      v.resize(number_of_simd_);
      for (mo::BitVector<>& t : v) {
        t = mo::BitVector<>::SecureRandom(kDefaultTestBitLength);
      }
    }
  }

  void ShareDiverseInputs() {
    for (std::size_t input_owner : {0, 1, 2}) {
      for (std::size_t party_id : {0, 1, 2}) {
        if (party_id == input_owner) {
          shared_inputs_single_[party_id][input_owner] =
              parties_.at(party_id)->template In<kBooleanAstra>(inputs_single_[input_owner], input_owner);
          shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kBooleanAstra>(inputs_simd_[input_owner], input_owner);
        } else {
          shared_inputs_single_[party_id][input_owner] =
              parties_.at(party_id)->template In<kBooleanAstra>(zeros_single_, input_owner);
          shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kBooleanAstra>(zeros_simd_, input_owner);
        }
      }
    }
  }
  
  void GenerateAndNInputs(size_t arity) {
    zeros_single_.emplace_back(kDefaultTestBitLength, false);
    zeros_simd_.resize(number_of_simd_, mo::BitVector<>(kDefaultTestBitLength, false));

    for (auto& v : inputs_and_n_) {
      v.resize(arity);
      for (mo::BitVector<>& t : v) {
        t = mo::BitVector<>::SecureRandom(kDefaultTestBitLength);
      }
    }
    
    
    
    //TODO: SIMD here
  }
  
  void ShareAndNInputs() {
    //Input owner is always 0
    size_t input_owner = 0;
    size_t arity = inputs_and_n_[0].size();
    for (std::size_t party_id : {0, 1, 2}) {
      shared_and_n_inputs_[party_id].reserve(arity);
      for(size_t i = 0; i != arity; ++i) {
        if (party_id == input_owner) {
        shared_and_n_inputs_[party_id].emplace_back(
            parties_.at(party_id)->template In<kBooleanAstra>(inputs_and_n_[0][i], input_owner));
        /*shared_inputs_simd_[party_id][input_owner] =
            parties_.at(party_id)->template In<kBooleanAstra>(inputs_simd_[input_owner], input_owner);*/
        
        } else {
          shared_and_n_inputs_[party_id].emplace_back(
              parties_.at(party_id)->template In<kBooleanAstra>(zeros_single_, input_owner));
          /*shared_inputs_simd_[party_id][input_owner] =
              parties_.at(party_id)->template In<kBooleanAstra>(zeros_simd_, input_owner);*/
        }
      }
    }
  }

  
  void GenerateDotProductInputs() {
    zeros_single_.emplace_back(kDefaultTestBitLength, false);
    zeros_simd_.resize(number_of_simd_, mo::BitVector<>(kDefaultTestBitLength, false));

    for (auto& v : inputs_dot_product_single_) {
      v.resize(dot_product_vector_size_);
      for (mo::BitVector<>& t : v) {
        t = mo::BitVector<>::SecureRandom(kDefaultTestBitLength);
      }
    }

    for (auto& vv : inputs_dot_product_simd_) {
      vv.resize(dot_product_vector_size_);
      for (auto& v : vv) {
        v.resize(number_of_simd_);
        for (mo::BitVector<>& t : v) {
          t = mo::BitVector<>::SecureRandom(kDefaultTestBitLength);
        }
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
              parties_.at(party_id)->template In<kBooleanAstra>(
                  inputs_dot_product_single_[vector_i][element_j], input_owner);
          shared_dot_product_inputs_simd_[party_id][vector_i][element_j] =
              parties_.at(party_id)->template In<kBooleanAstra>(
                  inputs_dot_product_simd_[vector_i][element_j], input_owner);
        }
      }
    }
  }
  
  std::vector<std::byte> GetXorOfInputs() const {
    mo::BitVector<> result = inputs_single_[0];
    for(size_t party_id = 1u; party_id != parties_.size(); ++party_id) {
      result ^= inputs_single_[party_id];
    }
    return result.GetData();
  }
  
  std::vector<std::byte> GetXorOfSimdInputs() const {
    std::vector<mo::BitVector<>> xored = inputs_simd_[0];
    for(size_t party_id = 1u; party_id != parties_.size(); ++party_id) {
      for(size_t i = 0u; i != xored.size(); ++i) {
        xored[i] ^= inputs_simd_[party_id][i];
      }
    }
    std::vector<std::byte> result;
    for(auto& b : xored) {
      auto& d = b.GetData();
      std::copy(d.begin(), d.end(), std::back_inserter(result));
    }
    return result;
  }
  
  std::vector<std::byte> GetAndOfInputs() const {
    mo::BitVector<> result = inputs_single_[0];
    for(size_t party_id = 1u; party_id != parties_.size(); ++party_id) {
      result &= inputs_single_[party_id];
    }
    return result.GetData();
  }
  
  std::vector<std::byte> GetAndOfSimdInputs() const {
    std::vector<mo::BitVector<>> anded = inputs_simd_[0];
    for(size_t party_id = 1u; party_id != parties_.size(); ++party_id) {
      for(size_t i = 0u; i != anded.size(); ++i) {
        anded[i] &= inputs_simd_[party_id][i];
      }
    }
    std::vector<std::byte> result;
    for(auto& b : anded) {
      auto& d = b.GetData();
      std::copy(d.begin(), d.end(), std::back_inserter(result));
    }
    return result;
  }
  
  std::vector<std::byte> GetAndNOfInputs() const {
    mo::BitVector<> result = inputs_and_n_[0][0];
    for(size_t i = 0; i != inputs_and_n_[0].size(); ++i) {
      result &= inputs_and_n_[0][i];
    }
    
    return result.GetData();
  }
  
  mo::BitVector<> DotProduct(std::vector<mo::BitVector<>> const& x, std::vector<mo::BitVector<>> const& y) const {
    assert(x.size() == y.size());
    mo::BitVector<> result = x[0] & y[0];
    for(size_t i = 1u; i != x.size(); ++i) {
      result ^= x[i] & y[i];
    }
    return result;
  }
  
  std::vector<mo::BitVector<>> 
  SimdDotProduct(std::vector<std::vector<mo::BitVector<>>> const& x, 
                 std::vector<std::vector<mo::BitVector<>>> const& y) const {
    std::vector<mo::BitVector<>> result;
    for(size_t i = 0u; i != number_of_simd_; ++i) {
      mo::BitVector<> b = x[0][i] & y[0][i];
      for(size_t j = 1u; j != dot_product_vector_size_; ++j) {
        b ^= x[j][i] & y[j][i];
      }
      result.emplace_back(std::move(b));
    }
    return result;
  }
  
  std::vector<std::byte> GetDotProductOfInputs() const {
    return DotProduct(inputs_dot_product_single_[0], inputs_dot_product_single_[1]).GetData();
  }
  
  std::vector<std::byte> GetDotProductOfSimdInputs() const {
    std::vector<mo::BitVector<>> dot_product = 
      SimdDotProduct(inputs_dot_product_simd_[0], inputs_dot_product_simd_[1]);
    std::vector<std::byte> result;
    for(auto& b : dot_product) {
      auto& d = b.GetData();
      std::copy(d.begin(), d.end(), std::back_inserter(result));
    }
    return result;
  }
  
  static constexpr std::size_t number_of_simd_{1000};
  static constexpr std::size_t dot_product_vector_size_{100};

  std::array<mo::BitVector<>, 3> inputs_single_;
  std::array<std::vector<mo::BitVector<>>, 3> inputs_simd_;
  std::array<std::vector<mo::BitVector<>>, 2> inputs_dot_product_single_;
  std::array<std::vector<std::vector<mo::BitVector<>>>, 2> inputs_dot_product_simd_;
  
  //Dimensions: inputs_and_n_[PARTY][ARGUMENT_ID]
  std::array<std::vector<mo::BitVector<>>, 3> inputs_and_n_;
  //Dimensions: shared_and_n_inputs_[PARTY_ID][ARGUMENT_ID]
  std::array<std::vector<mo::ShareWrapper>, 3> shared_and_n_inputs_;

  std::vector<mo::BitVector<>> zeros_single_;
  std::vector<mo::BitVector<>> zeros_simd_;

  static constexpr std::size_t number_of_parties_{3};
  std::vector<mo::PartyPointer> parties_;

  std::array<std::array<mo::ShareWrapper, 3>, 3> shared_inputs_single_;
  std::array<std::array<mo::ShareWrapper, 3>, 3> shared_inputs_simd_;

  std::array<std::array<std::vector<mo::ShareWrapper>, 2>, 3> shared_dot_product_inputs_single_;
  std::array<std::array<std::vector<mo::ShareWrapper>, 2>, 3> shared_dot_product_inputs_simd_;
};

std::vector<std::byte> ToByteVector(mo::ShareWrapper output) {
  std::vector<std::byte> result;
  auto wires = output->GetWires();
  for(auto wire : wires) {
    auto w = std::dynamic_pointer_cast<mo::proto::boolean_astra::Wire>(wire);
    for(auto v : w->GetValues()) {
      auto& d = v.value.GetData();
      std::copy(d.begin(), d.end(), std::back_inserter(result));
    }
  }
  return result;
}

TEST(BooleanAstraTest, InputOutput) {
  BooleanAstraTestParameters astra_test;
  astra_test.GenerateDiverseInputs();
  astra_test.ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != astra_test.parties_.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      std::array<mo::ShareWrapper, 3> share_output_single, share_output_simd;
      for (std::size_t other_party_id = 0u; 
           other_party_id != astra_test.number_of_parties_;
           ++other_party_id) {
        share_output_single[other_party_id] =
            astra_test.shared_inputs_single_[party_id][other_party_id].Out(kAll);
        share_output_simd[other_party_id] =
            astra_test.shared_inputs_simd_[party_id][other_party_id].Out(kAll);
      }

      astra_test.parties_[party_id]->Run();

      for (std::size_t input_owner = 0; input_owner != astra_test.number_of_parties_; ++input_owner) {
        
        EXPECT_EQ(ToByteVector(share_output_single[input_owner]),
                  astra_test.inputs_single_[input_owner].GetData());
        std::vector<std::byte> circuit_result_simd = ToByteVector(share_output_simd[input_owner]);
        std::vector<std::byte> expected_result_simd;
        for(auto& s : astra_test.inputs_simd_[input_owner]) {
          auto& d = s.GetData();
          std::copy(d.begin(), d.end(), std::back_inserter(expected_result_simd));
        }
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      astra_test.parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TEST(BooleanAstraTest, Xor) {
  BooleanAstraTestParameters astra_test;
  astra_test.GenerateDiverseInputs();
  astra_test.ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != astra_test.parties_.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      auto share_xor_single = astra_test.shared_inputs_single_[party_id][0] ^
                              astra_test.shared_inputs_single_[party_id][1] ^
                              astra_test.shared_inputs_single_[party_id][2];
      auto share_xor_simd = astra_test.shared_inputs_simd_[party_id][0] ^
                            astra_test.shared_inputs_simd_[party_id][1] ^
                            astra_test.shared_inputs_simd_[party_id][2];

      auto share_output_single_all = share_xor_single.Out();
      auto share_output_simd_all = share_xor_simd.Out();

      astra_test.parties_[party_id]->Run();

      {
        std::vector<std::byte> circuit_result_single = ToByteVector(share_output_single_all);
        std::vector<std::byte> expected_result_single = astra_test.GetXorOfInputs();
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<std::byte> circuit_result_simd = ToByteVector(share_output_simd_all);
        const std::vector<std::byte> expected_result_simd = astra_test.GetXorOfSimdInputs();
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      astra_test.parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TEST(BooleanAstraTest, And) {
  BooleanAstraTestParameters astra_test;
  astra_test.GenerateDiverseInputs();
  astra_test.ShareDiverseInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != astra_test.parties_.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      auto share_and_single = astra_test.shared_inputs_single_[party_id][0] &
                              astra_test.shared_inputs_single_[party_id][1] &
                              astra_test.shared_inputs_single_[party_id][2];
      auto share_and_simd = astra_test.shared_inputs_simd_[party_id][0] &
                            astra_test.shared_inputs_simd_[party_id][1] &
                            astra_test.shared_inputs_simd_[party_id][2];

      auto share_output_single_all = share_and_single.Out();
      auto share_output_simd_all = share_and_simd.Out();

      astra_test.parties_[party_id]->Run();

      {
        std::vector<std::byte> circuit_result_single = ToByteVector(share_output_single_all);
        std::vector<std::byte> expected_result_single = astra_test.GetAndOfInputs();
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<std::byte> circuit_result_simd = ToByteVector(share_output_simd_all);
        const std::vector<std::byte> expected_result_simd = astra_test.GetAndOfSimdInputs();
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      astra_test.parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}

TEST(BooleanAstraTest, AndN_arity_2_to_8) {
  constexpr size_t lower_arity = 2, upper_arity = 8;
  assert(lower_arity < upper_arity);
  for(size_t i = lower_arity; i != upper_arity; ++i) {
    BooleanAstraTestParameters astra_test;
    astra_test.GenerateAndNInputs(i);
    astra_test.ShareAndNInputs();
    std::array<std::future<void>, 3> futures;
    for (auto party_id = 0u; party_id != astra_test.parties_.size(); ++party_id) {
      futures[party_id] = std::async([&, party_id]() {
        auto share_and_n_single = mo::AndN(astra_test.shared_and_n_inputs_[party_id]);
  
        auto share_output_and_n_all = share_and_n_single.Out();
  
        astra_test.parties_[party_id]->Run();
  
        {
          std::vector<std::byte> circuit_result_single = ToByteVector(share_output_and_n_all);
          std::vector<std::byte> expected_result_single = astra_test.GetAndNOfInputs();
          EXPECT_EQ(circuit_result_single, expected_result_single);
        }
        astra_test.parties_[party_id]->Finish();
      });
    }
    for (auto& f : futures) f.get();
  }
}

TEST(BooleanAstraTest, DotProduct) {
  BooleanAstraTestParameters astra_test;
  astra_test.GenerateDotProductInputs();
  astra_test.ShareDotProductInputs();
  std::array<std::future<void>, 3> futures;
  for (auto party_id = 0u; party_id != astra_test.parties_.size(); ++party_id) {
    futures[party_id] = std::async([&, party_id]() {
      auto share_and_single = mo::DotProduct(astra_test.shared_dot_product_inputs_single_[party_id][0],
                                             astra_test.shared_dot_product_inputs_single_[party_id][1]);
      auto share_and_simd = mo::DotProduct(astra_test.shared_dot_product_inputs_simd_[party_id][0],
                                           astra_test.shared_dot_product_inputs_simd_[party_id][1]);

      auto share_output_single_all = share_and_single.Out();
      auto share_output_simd_all = share_and_simd.Out();

      astra_test.parties_[party_id]->Run();

      {
        std::vector<std::byte> circuit_result_single = ToByteVector(share_output_single_all);
        std::vector<std::byte> expected_result_single = astra_test.GetDotProductOfInputs();
        EXPECT_EQ(circuit_result_single, expected_result_single);

        const std::vector<std::byte> circuit_result_simd = ToByteVector(share_output_simd_all);
        const std::vector<std::byte> expected_result_simd = astra_test.GetDotProductOfSimdInputs();
        EXPECT_EQ(circuit_result_simd, expected_result_simd);
      }
      astra_test.parties_[party_id]->Finish();
    });
  }
  for (auto& f : futures) f.get();
}