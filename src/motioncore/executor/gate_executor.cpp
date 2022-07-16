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

#include "gate_executor.h"

#include "base/register.h"
#include "protocols/gate.h"
#include "statistics/run_time_statistics.h"
#include "utility/fiber_thread_pool/fiber_thread_pool.hpp"
#include "utility/logger.h"

namespace encrypto::motion {

GateExecutor::GateExecutor(Register& reg, std::function<void(void)> presetup_function,
                           std::shared_ptr<Logger> logger)
    : register_(reg),
      presetup_function_(std::move(presetup_function)),
      logger_(std::move(logger)) {}

void GateExecutor::EvaluateSetupOnline(RunTimeStatistics& statistics) {
  statistics.RecordStart<RunTimeStatistics::StatisticsId::kEvaluate>();

  presetup_function_();

  if (logger_) {
    logger_->LogInfo(
        "Start evaluating the circuit gates sequentially (online after all finished setup)");
  }

  // create a pool with std::thread::hardware_concurrency() no. of threads
  // to execute fibers
  FiberThreadPool fiber_pool(0, 2 * register_.GetTotalNumberOfGates());

  // ------------------------------ setup phase ------------------------------
  statistics.RecordStart<RunTimeStatistics::StatisticsId::kGatesSetup>();

  // Evaluate the setup phase of all the gates
  for (auto& gate : register_.GetGates()) {
    if (gate->NeedsSetup()) {
      fiber_pool.post([&] {
        gate->EvaluateSetup();
        gate->SetSetupIsReady();
        register_.IncrementEvaluatedGatesSetupCounter();
      });
    } else {
      // cannot be done earlier because output wires did not yet exist
      gate->SetSetupIsReady();
    }
  }

  register_.CheckSetupCondition();
  register_.GetGatesSetupDoneCondition()->Wait();
  assert(register_.GetNumberOfEvaluatedGatesSetup() == register_.GetNumberOfGatesSetup());

  statistics.RecordEnd<RunTimeStatistics::StatisticsId::kGatesSetup>();

  // ------------------------------ online phase ------------------------------
  statistics.RecordStart<RunTimeStatistics::StatisticsId::kGatesOnline>();

  // Evaluate the online phase of all the gates
  for (auto& gate : register_.GetGates()) {
    if (gate->NeedsOnline()) {
      fiber_pool.post([&] {
        gate->EvaluateOnline();
        gate->SetOnlineIsReady();
        register_.IncrementEvaluatedGatesOnlineCounter();
      });
    } else {
      // cannot be done earlier because output wires did not yet exist
      gate->SetOnlineIsReady();
    }
  }

  register_.CheckOnlineCondition();
  register_.GetGatesOnlineDoneCondition()->Wait();
  assert(register_.GetNumberOfGatesOnline() == register_.GetNumberOfGatesOnline());

  statistics.RecordEnd<RunTimeStatistics::StatisticsId::kGatesOnline>();

  // --------------------------------------------------------------------------

  fiber_pool.join();

  statistics.RecordEnd<RunTimeStatistics::StatisticsId::kEvaluate>();
}

void GateExecutor::Evaluate(RunTimeStatistics& statistics) {
  logger_->LogInfo(
      "Start evaluating the circuit gates in parallel (online as soon as some finished setup)");

  statistics.RecordStart<RunTimeStatistics::StatisticsId::kEvaluate>();

  // Run preprocessing setup in a separate thread
  auto preprocessing_future = std::async(std::launch::async, [this] { presetup_function_(); });

  // create a pool with std::thread::hardware_concurrency() no. of threads
  // to execute fibers
  FiberThreadPool fiber_pool(0, register_.GetTotalNumberOfGates());

  // Evaluate all the gates
  for (auto& gate : register_.GetGates()) {
    if (gate->NeedsSetup() || gate->NeedsOnline()) {
      fiber_pool.post([&] {
        gate->EvaluateSetup();
        gate->SetSetupIsReady();
        if (gate->NeedsSetup()) {
          register_.IncrementEvaluatedGatesSetupCounter();
        }

        // XXX: maybe insert a 'yield' here?
        gate->EvaluateOnline();
        gate->SetOnlineIsReady();
        if (gate->NeedsOnline()) {
          register_.IncrementEvaluatedGatesOnlineCounter();
        }
      });
    } else {
      // cannot be done earlier because output wires did not yet exist
      gate->SetSetupIsReady();
      gate->SetOnlineIsReady();
    }
  }

  preprocessing_future.get();

  // we have to wait until all gates are evaluated before we close the pool
  register_.CheckOnlineCondition();
  register_.GetGatesOnlineDoneCondition()->Wait();
  fiber_pool.join();

  statistics.RecordEnd<RunTimeStatistics::StatisticsId::kEvaluate>();
}

}  // namespace encrypto::motion
