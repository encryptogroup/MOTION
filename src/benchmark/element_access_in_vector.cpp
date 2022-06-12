// MIT License
//
// Copyright (c) 2022 Oleksandr Tkachenko
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

#include <benchmark/benchmark.h>
#include <vector>

/**
 * Benchmark for element access in a vector, where elements are stored in a struct.
 */
static void BM_StructInVector(benchmark::State& state) {
  struct Data {
    std::uint64_t x;
    std::uint64_t y;
  };
  std::vector<Data> v(100'000);

  for (auto _ : state) {
    std::uint64_t dummy_counter_x;
    std::uint64_t dummy_counter_y;
    for (auto& data : v) {
      benchmark::DoNotOptimize(dummy_counter_x += data.x);
      benchmark::DoNotOptimize(dummy_counter_y += data.y);
    }
  }
}
BENCHMARK(BM_StructInVector);

/**
 * Benchmark for element access in a vector, where elements are stored directly in the vector.
 */
static void BM_InlinedStructInVector(benchmark::State& state) {
  std::vector<std::uint64_t> v(2 * 100'000);

  for (auto _ : state) {
    std::uint64_t dummy_counter_x;
    std::uint64_t dummy_counter_y;
    for (std::size_t i = 0; i < v.size(); i += 2) {
      benchmark::DoNotOptimize(dummy_counter_x += v[i]);
      benchmark::DoNotOptimize(dummy_counter_y += v[i + 1]);
    }
  }
}
BENCHMARK(BM_InlinedStructInVector);

/**
 * Benchmark for element access in a vector, where elements are stored directly in the vector.
 */
static void BM_InlinedStructInVectorFunctionAt(benchmark::State& state) {
  volatile std::int64_t vector_size{100'000};
  std::vector<std::uint64_t> v(2 * vector_size);

  for (auto _ : state) {
    std::uint64_t dummy_counter_x;
    std::uint64_t dummy_counter_y;
    for (std::size_t i = 0; i < v.size(); i += 2) {
      benchmark::DoNotOptimize(dummy_counter_x += v.at(i));
      benchmark::DoNotOptimize(dummy_counter_y += v.at(i));
    }
  }
}
BENCHMARK(BM_InlinedStructInVectorFunctionAt);