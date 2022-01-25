// MIT License
//
// Copyright (c) 2022 Arianne Roselina Prananto
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
#include <math.h>
#include <random>

#include "utility/fiber_thread_pool/fiber_thread_pool.hpp"

class DummyGate {
 public:
  virtual ~DummyGate() {}

  virtual void operator()() const = 0;

  virtual bool HasWork() = 0;

 protected:
  DummyGate() {}
};

class MuchComputationGate final : public DummyGate {
 public:
  MuchComputationGate() : DummyGate() {}

  ~MuchComputationGate() final = default;

  void operator()() const {
    // random calculation
    std::vector<std::size_t> vector;
    for (std::size_t i = 1; i <= 10; ++i) {
      auto element = static_cast<std::size_t>(std::ceil(std::log(i) * 12.34f));
      vector.push_back(element);
    }
  }

  bool HasWork() { return true; }
};

class NoComputationGate final : public DummyGate {
 public:
  NoComputationGate() : DummyGate() {}

  ~NoComputationGate() final = default;

  void operator()() const { return; }

  bool HasWork() { return false; }
};

/**
 * Benchmark for Fiber using MuchComputationGate and NoComputationGate without HasWork() check.
 * The percentage is set to 0%, 20%, 40%, 60%, 80%, and 100% of NoComputationGate and the rest of
 * MuchComputationGate. Both Gates are subclasses of DummyGate that don't do actual computations.
 *
 * @param state the benchmark state
 */
static void BM_FiberMixComputationNoCheck(benchmark::State& state) {
  std::size_t number_of_gates = state.range(0);
  std::size_t threshold = number_of_gates * state.range(1) / 100;

  // initialize the gates
  std::vector<std::shared_ptr<DummyGate>> gates;
  for (std::size_t i = 0; i < number_of_gates; i++) {
    if (i < threshold) {
      gates.emplace_back(std::make_shared<NoComputationGate>());
    } else {
      gates.emplace_back(std::make_shared<MuchComputationGate>());
    }
  }

  // shuffle the gates so that the compiler won't know where each gate is
  std::random_device rd;
  std::mt19937 g(rd());
  std::shuffle(gates.begin(), gates.end(), g);

  // --------------------------- computation phase ---------------------------

  // evaluates the operator()
  std::size_t counter = 0;
  for (auto _ : state) {
    encrypto::motion::FiberThreadPool fiber_pool(0, 2 * number_of_gates);
    for (auto& gate : gates) {
      fiber_pool.post([gate] { gate->operator()(); });
    }
    counter += number_of_gates;
    fiber_pool.join();
  }

  state.counters["Gates"] = benchmark::Counter(counter, benchmark::Counter::kIsRate);

  // -------------------------------------------------------------------------
}
BENCHMARK(BM_FiberMixComputationNoCheck)
    ->ArgsProduct({benchmark::CreateRange(1, 1 << 20, 8), {0, 20, 40, 60, 80, 100}});

/**
 * Benchmark for Fiber using MuchComputationGate and NoComputationGate with a HasWork() check. Fiber
 * is used only when HasWork() returns true. The percentage is set to 0%, 20%, 40%, 60%, 80%, and
 * 100% of NoComputationGate and the rest of MuchComputationGate. Both Gates are subclasses of
 * DummyGate that don't do actual computations.
 *
 * @param state the benchmark state
 */
static void BM_FiberMixComputationWithCheck(benchmark::State& state) {
  std::size_t number_of_gates = state.range(0);
  std::size_t threshold = number_of_gates * state.range(1) / 100;

  // initialize the gates
  std::vector<std::shared_ptr<DummyGate>> gates;
  for (std::size_t i = 0; i < number_of_gates; i++) {
    if (i < threshold) {
      gates.emplace_back(std::make_shared<NoComputationGate>());
    } else {
      gates.emplace_back(std::make_shared<MuchComputationGate>());
    }
  }

  // shuffle the gates so that the compiler won't know where each gate is
  std::random_device rd;
  std::mt19937 g(rd());
  std::shuffle(gates.begin(), gates.end(), g);

  // --------------------------- computation phase ---------------------------

  // evaluates the operator()
  std::size_t counter = 0;
  for (auto _ : state) {
    encrypto::motion::FiberThreadPool fiber_pool(0, 2 * number_of_gates);
    for (auto& gate : gates) {
      if (gate->HasWork()) {
        fiber_pool.post([gate] { gate->operator()(); });
      }
    }
    fiber_pool.join();
    counter += number_of_gates;
  }
  state.counters["Gates"] = benchmark::Counter(counter, benchmark::Counter::kIsRate);

  // -------------------------------------------------------------------------
}
BENCHMARK(BM_FiberMixComputationWithCheck)
    ->ArgsProduct({benchmark::CreateRange(1, 1 << 20, 8), {0, 20, 40, 60, 80, 100}});
