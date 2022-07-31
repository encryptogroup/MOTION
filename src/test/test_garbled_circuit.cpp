// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko
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

#include <chrono>
#include <iterator>

#include "base/party.h"
#include "protocols/garbled_circuit/garbled_circuit_constants.h"
#include "protocols/garbled_circuit/garbled_circuit_provider.h"
#include "protocols/share_wrapper.h"
#include "test_constants.h"
#include "utility/reusable_future.h"

namespace {

// number of wires, SIMD values, and online-after-setup flag
using ParametersType = std::tuple<std::size_t, std::size_t, bool>;

class GarbledCircuitTest : public testing::TestWithParam<ParametersType> {
 public:
  void SetUp() override {
    auto parameters = GetParam();
    std::tie(number_of_wires_, number_of_simd_, online_after_setup_) = parameters;

    parties_ = MakeParties();
    for (auto& party : parties_) {
      // XXX
      party->GetLogger()->SetEnabled(kDetailedLoggingEnabled);
      party->GetLogger()->SetEnabled(true);
      party->GetConfiguration()->SetOnlineAfterSetup(this->online_after_setup_);
    }

    global_inputs_.resize(2);
    for (auto& bv_v : global_inputs_) {
      bv_v.resize(number_of_wires_);
      for (auto& bv : bv_v) bv = GenerateRandomBitVector(number_of_simd_);
    }
  }

  void TearDown() override { number_of_wires_ = number_of_simd_ = 0; }

  std::vector<encrypto::motion::PartyPointer> MakeParties() {
    return encrypto::motion::MakeLocallyConnectedParties(2, kPortOffset);
  }

  encrypto::motion::BitVector<> GenerateRandomBitVector(std::size_t bitlength) {
    return encrypto::motion::BitVector<>::RandomSeeded(this->number_of_simd_,
                                                       this->bitvector_randomness_seed_++);
  }

 protected:
  std::size_t number_of_wires_ = 0, number_of_simd_ = 0;
  bool online_after_setup_ = false;
  std::vector<encrypto::motion::PartyPointer> parties_;
  std::size_t bitvector_randomness_seed_ = 0;
  std::vector<std::vector<encrypto::motion::BitVector<>>> global_inputs_;
  static constexpr auto garbler_id_{
      static_cast<std::size_t>(encrypto::motion::GarbledCircuitRole::kGarbler)};
  static constexpr std::size_t evaluator_id_{1 - garbler_id_};
};

TEST_P(GarbledCircuitTest, InputOutput) {
  std::vector<std::future<void>> futures;
  for (std::size_t party_id = 0; party_id < 2u; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, this]() {
      const bool is_garbler{this->garbler_id_ == party_id};

      // garbler's input
      auto [garblers_input_share, garblers_input_promise] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
              this->garbler_id_, this->number_of_wires_, this->number_of_simd_);

      EXPECT_EQ(garblers_input_share->GetBitLength(), this->number_of_wires_);

      // evaluator's input
      auto [evaluators_input_share, evaluators_input_promise] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
              this->evaluator_id_, this->number_of_wires_, this->number_of_simd_);

      EXPECT_EQ(evaluators_input_share->GetBitLength(), this->number_of_wires_);

      // Set inputs using the obtained promises
      if (is_garbler) {
        ASSERT_TRUE(garblers_input_promise);
        EXPECT_FALSE(evaluators_input_promise);
        garblers_input_promise->set_value(this->global_inputs_[this->garbler_id_]);
      } else {  // is evaluator
        ASSERT_TRUE(evaluators_input_promise);
        EXPECT_FALSE(garblers_input_promise);
        evaluators_input_promise->set_value(this->global_inputs_[this->evaluator_id_]);
      }

      // output gates for garbler's input
      auto garblers_input_output_to_all{encrypto::motion::ShareWrapper(garblers_input_share).Out()};
      auto garblers_input_output_to_garbler{
          encrypto::motion::ShareWrapper(garblers_input_share).Out(this->garbler_id_)};
      auto garblers_input_output_to_evaluator{
          encrypto::motion::ShareWrapper(garblers_input_share).Out(this->evaluator_id_)};

      // output gates for evaluator's input
      auto evaluators_input_output_to_all{
          encrypto::motion::ShareWrapper(evaluators_input_share).Out()};
      auto evaluators_input_output_to_garbler{
          encrypto::motion::ShareWrapper(evaluators_input_share).Out(this->garbler_id_)};
      auto evaluators_input_output_to_evaluator{
          encrypto::motion::ShareWrapper(evaluators_input_share).Out(this->evaluator_id_)};

      this->parties_[party_id]->Run();
      EXPECT_EQ(garblers_input_output_to_all.As<std::vector<encrypto::motion::BitVector<>>>(),
                this->global_inputs_[this->garbler_id_]);
      EXPECT_EQ(evaluators_input_output_to_all.As<std::vector<encrypto::motion::BitVector<>>>(),
                this->global_inputs_[this->evaluator_id_]);

      if (is_garbler) {
        EXPECT_EQ(garblers_input_output_to_garbler.As<std::vector<encrypto::motion::BitVector<>>>(),
                  this->global_inputs_[this->garbler_id_]);
        EXPECT_EQ(
            evaluators_input_output_to_garbler.As<std::vector<encrypto::motion::BitVector<>>>(),
            this->global_inputs_[this->evaluator_id_]);
      } else {  // is evaluator
        EXPECT_EQ(
            garblers_input_output_to_evaluator.As<std::vector<encrypto::motion::BitVector<>>>(),
            this->global_inputs_[this->garbler_id_]);
        EXPECT_EQ(
            evaluators_input_output_to_evaluator.As<std::vector<encrypto::motion::BitVector<>>>(),
            this->global_inputs_[this->evaluator_id_]);
      }
      this->parties_[party_id]->Finish();
    }));
  }
  for (auto& f : futures) f.get();
}

TEST_P(GarbledCircuitTest, DelayedInputOutput) {
  std::vector<std::future<void>> futures;
  for (std::size_t party_id = 0; party_id < 2u; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, this]() {
      const bool is_garbler{this->garbler_id_ == party_id};

      // garbler's input
      auto [garblers_input_share, garblers_input_promise] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
              this->garbler_id_, this->number_of_wires_, this->number_of_simd_);

      EXPECT_EQ(garblers_input_share->GetBitLength(), this->number_of_wires_);

      // evaluator's input
      auto [evaluators_input_share, evaluators_input_promise] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
              this->evaluator_id_, this->number_of_wires_, this->number_of_simd_);

      EXPECT_EQ(evaluators_input_share->GetBitLength(), this->number_of_wires_);

      // output gates for garbler's input
      auto garblers_input_output_to_all{encrypto::motion::ShareWrapper(garblers_input_share).Out()};
      auto garblers_input_output_to_garbler{
          encrypto::motion::ShareWrapper(garblers_input_share).Out(this->garbler_id_)};
      auto garblers_input_output_to_evaluator{
          encrypto::motion::ShareWrapper(garblers_input_share).Out(this->evaluator_id_)};

      // output gates for evaluator's input
      auto evaluators_input_output_to_all{
          encrypto::motion::ShareWrapper(evaluators_input_share).Out()};
      auto evaluators_input_output_to_garbler{
          encrypto::motion::ShareWrapper(evaluators_input_share).Out(this->garbler_id_)};
      auto evaluators_input_output_to_evaluator{
          encrypto::motion::ShareWrapper(evaluators_input_share).Out(this->evaluator_id_)};

      auto party_finished_future =
          std::async(std::launch::async, [this, party_id]() { this->parties_[party_id]->Run(); });
      // Set inputs using the obtained promises with a 10 ms delay
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
      if (is_garbler) {
        ASSERT_TRUE(garblers_input_promise);
        EXPECT_FALSE(evaluators_input_promise);
        garblers_input_promise->set_value(this->global_inputs_[this->garbler_id_]);
      } else {  // is evaluator
        ASSERT_TRUE(evaluators_input_promise);
        EXPECT_FALSE(garblers_input_promise);
        evaluators_input_promise->set_value(this->global_inputs_[this->evaluator_id_]);
      }
      party_finished_future.get();

      EXPECT_EQ(garblers_input_output_to_all.As<std::vector<encrypto::motion::BitVector<>>>(),
                this->global_inputs_[this->garbler_id_]);
      EXPECT_EQ(evaluators_input_output_to_all.As<std::vector<encrypto::motion::BitVector<>>>(),
                this->global_inputs_[this->evaluator_id_]);

      if (is_garbler) {
        EXPECT_EQ(garblers_input_output_to_garbler.As<std::vector<encrypto::motion::BitVector<>>>(),
                  this->global_inputs_[this->garbler_id_]);
        EXPECT_EQ(
            evaluators_input_output_to_garbler.As<std::vector<encrypto::motion::BitVector<>>>(),
            this->global_inputs_[this->evaluator_id_]);
      } else {  // is evaluator
        EXPECT_EQ(
            garblers_input_output_to_evaluator.As<std::vector<encrypto::motion::BitVector<>>>(),
            this->global_inputs_[this->garbler_id_]);
        EXPECT_EQ(
            evaluators_input_output_to_evaluator.As<std::vector<encrypto::motion::BitVector<>>>(),
            this->global_inputs_[this->evaluator_id_]);
      }
      this->parties_[party_id]->Finish();
    }));
  }
  for (auto& f : futures) f.get();
}

TEST_P(GarbledCircuitTest, Xor) {
  std::vector<std::future<void>> futures;
  for (std::size_t party_id = 0; party_id < 2u; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, this]() {
      auto [input_share_0, input_promise_0] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
              0, this->number_of_wires_, this->number_of_simd_);
      encrypto::motion::ShareWrapper input_0(input_share_0);

      // evaluator's input
      auto [input_share_1, input_promise_1] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
              1, this->number_of_wires_, this->number_of_simd_);
      encrypto::motion::ShareWrapper input_1(input_share_1);

      // Set inputs using the obtained promises
      if (party_id == 0) {
        input_promise_0->set_value(this->global_inputs_[0]);
      } else {  // party_id == 1
        input_promise_1->set_value(this->global_inputs_[1]);
      }

      auto result{input_0 ^ input_1};

      auto output{result.Out()};

      this->parties_[party_id]->Run();

      for (std::size_t i = 0; i < this->number_of_wires_; ++i) {
        EXPECT_EQ(output.GetWire(i).As<encrypto::motion::BitVector<>>(),
                  this->global_inputs_[0][i] ^ this->global_inputs_[1][i]);
      }
      this->parties_[party_id]->Finish();
    }));
  }
  for (auto& f : futures) f.get();
}

TEST_P(GarbledCircuitTest, Inv) {
  std::vector<std::future<void>> futures;
  for (std::size_t party_id = 0; party_id < 2u; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, this]() {
      auto [input_share, input_promise] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
              0, this->number_of_wires_, this->number_of_simd_);
      encrypto::motion::ShareWrapper input(input_share);

      // Set inputs using the obtained promises
      if (party_id == 0) input_promise->set_value(this->global_inputs_[0]);

      auto result{~input};

      auto output{result.Out()};

      this->parties_[party_id]->Run();

      for (std::size_t i = 0; i < this->number_of_wires_; ++i) {
        EXPECT_EQ(output.GetWire(i).As<encrypto::motion::BitVector<>>(),
                  ~this->global_inputs_[0][i]);
      }
      this->parties_[party_id]->Finish();
    }));
  }
  for (auto& f : futures) f.get();
}

TEST_P(GarbledCircuitTest, And) {
  std::vector<std::future<void>> futures;
  std::mutex labels_mutex;
  std::array<encrypto::motion::Block128Vector, 2> labels;
  encrypto::motion::Block128 random_offset;
  std::array<encrypto::motion::BitVector<>, 2> p0, p1;
  encrypto::motion::BitVector<> result_of_and_gate;
  for (std::size_t party_id = 0; party_id < 2u; ++party_id) {
    futures.emplace_back(std::async(std::launch::async, [party_id, this, &labels, &labels_mutex,
                                                         &p0, &p1, &random_offset,
                                                         &result_of_and_gate]() {
      auto [input_share_0, input_promise_0] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
              0, this->number_of_wires_, this->number_of_simd_);
      encrypto::motion::ShareWrapper input_0(input_share_0);

      // evaluator's input
      auto [input_share_1, input_promise_1] =
          this->parties_[party_id]->In<encrypto::motion::MpcProtocol::kGarbledCircuit>(
              1, this->number_of_wires_, this->number_of_simd_);
      encrypto::motion::ShareWrapper input_1(input_share_1);

      // Set inputs using the obtained promises
      if (party_id == 0) {
        input_promise_0->set_value(this->global_inputs_[0]);
      } else {  // party_id == 1
        input_promise_1->set_value(this->global_inputs_[1]);
      }

      auto result{input_0 & input_1};

      auto output{result.Out()};

      this->parties_[party_id]->Run();

      p0[party_id] = std::dynamic_pointer_cast<encrypto::motion::proto::garbled_circuit::Wire>(
                         input_share_0->GetWires()[0])
                         ->CopyPermutationBits();
      p1[party_id] = std::dynamic_pointer_cast<encrypto::motion::proto::garbled_circuit::Wire>(
                         input_share_1->GetWires()[0])
                         ->CopyPermutationBits();

      if (party_id == this->garbler_id_) {
        random_offset =
            dynamic_cast<encrypto::motion::proto::garbled_circuit::ThreeHalvesGarblerProvider&>(
                this->parties_[party_id]->GetBackend()->GetGarbledCircuitProvider())
                .GetOffset();
      }

      {
        auto gc_wire{std::dynamic_pointer_cast<encrypto::motion::proto::garbled_circuit::Wire>(
            result.Get()->GetWires()[0])};
        std::scoped_lock lock(labels_mutex);
        labels[party_id].resize(gc_wire->GetNumberOfSimdValues());
        std::copy(gc_wire->GetKeys().begin(), gc_wire->GetKeys().end(), labels[party_id].begin());
      }
      for (std::size_t i = 0; i < this->number_of_wires_; ++i) {
        EXPECT_EQ(output.GetWire(i).As<encrypto::motion::BitVector<>>(),
                  this->global_inputs_[0][i] & this->global_inputs_[1][i])
            << fmt::format(" inputs were {}, {}", static_cast<int>(this->global_inputs_[0][i][0]),
                           static_cast<int>(this->global_inputs_[1][i][0]));
      }
      if (party_id == this->garbler_id_) {
        result_of_and_gate = output.GetWire(0).As<encrypto::motion::BitVector<>>();
      }
      this->parties_[party_id]->Finish();
    }));
  }

  for (auto& f : futures) f.get();

  if constexpr (false) {
    for (std::size_t j = 0; j < this->number_of_simd_; ++j) {
      if ((labels[this->evaluator_id_][j] == labels[this->garbler_id_][j]) ||
          (labels[this->evaluator_id_][j] == (labels[this->garbler_id_][j] ^ random_offset)))
        std::cerr << "Wow, labels are valid!";
      else {
        auto left_bw = encrypto::motion::BitVector<>(
            (labels[this->evaluator_id_][j] ^ labels[this->garbler_id_][j]).data(), 128);
        auto left_hw = left_bw.HammingWeight();
        if (left_hw < 3) {
          for (std::size_t iii = 0; iii < left_bw.GetSize(); ++iii) {
            if (left_bw[iii]) std::cerr << "Wrong bit at position " << iii << std::endl;
          }
        }
        auto right_bw = encrypto::motion::BitVector<>(
            (labels[this->evaluator_id_][j] ^ labels[this->garbler_id_][j] ^ random_offset).data(),
            128);
        auto right_hw = right_bw.HammingWeight();
        if (right_hw < 3) {
          for (std::size_t iii = 0; iii < right_bw.GetSize(); ++iii) {
            if (right_bw[iii]) std::cerr << "Wrong bit at position " << iii << std::endl;
          }
        }

        std::cerr << fmt::format("Labels are wrong and min HW is {}! ",
                                 std::min(left_hw, right_hw));
      }
      std::cerr << fmt::format("Permutation bits G {} {} E {} {}", p0[this->garbler_id_][j],
                               p1[this->garbler_id_][j], p0[this->evaluator_id_][j],
                               p1[this->evaluator_id_][j]);
      if (result_of_and_gate[j] ==
          (this->global_inputs_[0][0][j] & this->global_inputs_[1][0][j])) {
        std::cerr << fmt::format(" and the result ({}) is correct\n", result_of_and_gate[j]);
      } else
        std::cerr << fmt::format(" and the result ({}) is *wrong*\n", result_of_and_gate[j]);

      EXPECT_TRUE(
          (labels[this->evaluator_id_][j] == labels[this->garbler_id_][j]) ||
          (labels[this->evaluator_id_][j] == (labels[this->garbler_id_][j] ^ random_offset)));
    }
  }
}
constexpr std::array<std::size_t, 3> kGarbledCircuitNumberOfWires{1, 64, 100};
constexpr std::array<std::size_t, 3> kGarbledCircuitNumberOfSimd{1, 64, 100};
constexpr std::array<bool, 2> kGarbledCircuitOnlineAfterSetup{false, true};

INSTANTIATE_TEST_SUITE_P(GarbledCircuitTestSuite, GarbledCircuitTest,
                         testing::Combine(testing::ValuesIn(kGarbledCircuitNumberOfWires),
                                          testing::ValuesIn(kGarbledCircuitNumberOfSimd),
                                          testing::ValuesIn(kGarbledCircuitOnlineAfterSetup)),
                         [](const testing::TestParamInfo<GarbledCircuitTest::ParamType>& info) {
                           const auto mode =
                               static_cast<bool>(std::get<2>(info.param)) ? "Seq" : "Par";
                           std::string name =
                               fmt::format("{}_Wires_{}_SIMD__{}", std::get<0>(info.param),
                                           std::get<1>(info.param), mode);
                           return name;
                         });

}  // namespace
