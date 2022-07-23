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

#include <benchmark/benchmark.h>

#include "communication/communication_layer.h"
#include "protocols/garbled_circuit/garbled_circuit_constants.h"
#include "protocols/garbled_circuit/garbled_circuit_provider.h"
#include "utility/block.h"

static void BM_ThreeHalvesEvaluation(benchmark::State& state) {
  auto communication_layers = encrypto::motion::communication::MakeDummyCommunicationLayers(2);
  std::for_each(std::begin(communication_layers), std::end(communication_layers),
                [](auto& cl) { cl->Start(); });
  encrypto::motion::proto::garbled_circuit::ThreeHalvesEvaluatorProvider provider(
      *communication_layers[1]);

  std::size_t number_of_simd = state.range(0);
  encrypto::motion::Block128Vector keys_a(number_of_simd), keys_b(number_of_simd),
      keys_out(number_of_simd);
  encrypto::motion::BitVector<> garbled_tables(
      number_of_simd * encrypto::motion::proto::garbled_circuit::kGarbledTableBitSize);
  encrypto::motion::BitVector<> garbled_control_bits(
      number_of_simd * encrypto::motion::proto::garbled_circuit::kGarbledControlBitsBitSize);

  std::size_t counter{0};
  for (auto _ : state) {
    provider.Evaluate(keys_a, keys_b, keys_out, garbled_tables.GetData().data(),
                      garbled_control_bits.GetData().data(), 0, 0);
    counter += number_of_simd;
  }

  // shutdown all commmunication layers
  std::vector<std::future<void>> futures;
  for (auto& cl : communication_layers) {
    futures.emplace_back(std::async(std::launch::async, [&cl] { cl->Shutdown(); }));
  }
  std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });

  state.counters["Gates"] = benchmark::Counter(counter, benchmark::Counter::kIsRate);
}
BENCHMARK(BM_ThreeHalvesEvaluation)->RangeMultiplier(2)->Range(1, 128);

static void BM_ThreeHalvesGarbling(benchmark::State& state) {
  auto communication_layers = encrypto::motion::communication::MakeDummyCommunicationLayers(2);
  std::for_each(std::begin(communication_layers), std::end(communication_layers),
                [](auto& cl) { cl->Start(); });

  encrypto::motion::proto::garbled_circuit::ThreeHalvesGarblerProvider provider(
      *communication_layers[0]);

  std::size_t number_of_simd = state.range(0);
  encrypto::motion::Block128Vector keys_a(number_of_simd), keys_b(number_of_simd),
      keys_out(number_of_simd);
  encrypto::motion::BitVector<> garbled_tables(
      number_of_simd * encrypto::motion::proto::garbled_circuit::kGarbledTableBitSize);
  encrypto::motion::BitVector<> garbled_control_bits(
      number_of_simd * encrypto::motion::proto::garbled_circuit::kGarbledControlBitsBitSize);

  std::size_t counter{0};
  for (auto _ : state) {
    provider.Garble(keys_a, keys_b, keys_out, garbled_tables.GetMutableData().data(),
                    garbled_control_bits.GetMutableData().data(), 0, 0);
    counter += number_of_simd;
  }

  // shutdown all commmunication layers
  std::vector<std::future<void>> futures;
  for (auto& cl : communication_layers) {
    futures.emplace_back(std::async(std::launch::async, [&cl] { cl->Shutdown(); }));
  }
  std::for_each(std::begin(futures), std::end(futures), [](auto& f) { f.get(); });

  state.counters["Gates"] = benchmark::Counter(counter, benchmark::Counter::kIsRate);
}
BENCHMARK(BM_ThreeHalvesGarbling)->RangeMultiplier(2)->Range(1, 128);