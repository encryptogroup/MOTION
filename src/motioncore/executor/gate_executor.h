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

#pragma once

#include <functional>
#include <memory>
#include <queue>

namespace encrypto::motion {

struct RunTimeStatistics;

class Logger;
class Register;

// Evaluates all registered gates.
class GateExecutor {
 public:
  GateExecutor(Register&, std::function<void()> preprocessing_function, std::shared_ptr<Logger>);

  // Run the setup phases first for all gates before starting with the online
  // phases.
  void EvaluateSetupOnline(RunTimeStatistics& statistics);
  // Run setup and online phase of each gate as soon as possible.
  void Evaluate(RunTimeStatistics& statistics);
  
  void AddCustomSetupJob(std::function<void()> job);
  
  void AddCustomOnlineJob(std::function<void()> job);

 private:
  Register& register_;
  std::function<void()> preprocessing_function_;
  std::queue<std::function<void()>> custom_setup_;
  std::queue<std::function<void()>> custom_online_;
  std::shared_ptr<Logger> logger_;
};

}  // namespace encrypto::motion
