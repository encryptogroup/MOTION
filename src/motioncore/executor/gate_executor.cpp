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
#include "gate/gate.h"
#include "statistics/run_time_stats.h"
#include "utility/fiber_thread_pool/fiber_thread_pool.hpp"
#include "utility/logger.h"

namespace MOTION {

GateExecutor::GateExecutor(Register &reg, std::function<void(void)> preprocessing_fctn,
                           std::shared_ptr<Logger> logger)
    : register_(reg),
      preprocessing_fctn_(std::move(preprocessing_fctn)),
      logger_(std::move(logger)) {}

void GateExecutor::evaluate_setup_online(Statistics::RunTimeStats &stats) {
  stats.record_start<Statistics::RunTimeStats::StatID::evaluate>();

  preprocessing_fctn_();

  if (logger_) {
    logger_->LogInfo(
        "Start evaluating the circuit gates sequentially (online after all finished setup)");
  }

  // create a pool with std::thread::hardware_concurrency() no. of threads
  // to execute fibers
  ENCRYPTO::FiberThreadPool fpool(0, 2 * register_.GetTotalNumOfGates());

  // ------------------------------ setup phase ------------------------------
  stats.record_start<Statistics::RunTimeStats::StatID::gates_setup>();

  // evaluate the setup phase of all the gates
  for (auto &gate : register_.GetGates()) {
    fpool.post([&] { gate->EvaluateSetup(); });
  }
  register_.GetGatesSetupDoneCondition()->Wait();
  assert(register_.GetNumOfEvaluatedGateSetups() == register_.GetTotalNumOfGates());

  stats.record_end<Statistics::RunTimeStats::StatID::gates_setup>();

  // ------------------------------ online phase ------------------------------
  stats.record_start<Statistics::RunTimeStats::StatID::gates_online>();

  // evaluate the online phase of all the gates
  for (auto &gate : register_.GetGates()) {
    fpool.post([&] { gate->EvaluateOnline(); });
  }
  register_.GetGatesOnlineDoneCondition()->Wait();
  assert(register_.GetNumOfEvaluatedGates() == register_.GetTotalNumOfGates());

  stats.record_end<Statistics::RunTimeStats::StatID::gates_online>();

  // --------------------------------------------------------------------------

  fpool.join();

  // XXX: since we never pop elements from the active queue, clear it manually for now
  // otherwise there will be complains that it is not empty upon repeated execution
  // -> maybe remove the active queue in the future
  register_.ClearActiveQueue();

  stats.record_end<Statistics::RunTimeStats::StatID::evaluate>();
}

void GateExecutor::evaluate(Statistics::RunTimeStats &stats) {
  logger_->LogInfo(
      "Start evaluating the circuit gates in parallel (online as soon as some finished setup)");

  stats.record_start<Statistics::RunTimeStats::StatID::evaluate>();

  // Run preprocessing setup in a separate thread
  auto f_preprocessing = std::async(std::launch::async, [this] { preprocessing_fctn_(); });

  // create a pool with std::thread::hardware_concurrency() no. of threads
  // to execute fibers
  ENCRYPTO::FiberThreadPool fpool(0, register_.GetTotalNumOfGates());

  // evaluate all the gates
  for (auto &gate : register_.GetGates()) {
    fpool.post([&] {
      gate->EvaluateSetup();
      // XXX: maybe insert a 'yield' here?
      gate->EvaluateOnline();
    });
  }

  f_preprocessing.get();

  // we have to wait until all gates are evaluated before we close the pool
  register_.GetGatesOnlineDoneCondition()->Wait();
  fpool.join();

  // XXX: since we never pop elements from the active queue, clear it manually for now
  // otherwise there will be complains that it is not empty upon repeated execution
  // -> maybe remove the active queue in the future
  register_.ClearActiveQueue();

  stats.record_end<Statistics::RunTimeStats::StatID::evaluate>();
}

}  // namespace MOTION
