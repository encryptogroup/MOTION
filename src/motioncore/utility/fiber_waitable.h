// MIT License
//
// Copyright (c) 2021 Oleksandr Tkachenko, Lennart Braun
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

#pragma once

#include <atomic>
#include <memory>

namespace encrypto::motion {

class FiberCondition;

class FiberSetupWaitable {
 public:
  FiberSetupWaitable();

  void WaitSetup() const;

  void SetSetupIsReady();

  bool IsSetupReady() { return setup_ready_; }

  void ResetSetupIsReady() { setup_ready_.store(false); }

 protected:
  std::atomic<bool> setup_ready_{false};
  std::shared_ptr<FiberCondition> setup_ready_condition_;
};

class FiberOnlineWaitable {
 public:
  FiberOnlineWaitable();

  void WaitOnline() const;

  void SetOnlineIsReady();

  bool IsOnlineReady() { return online_ready_; }

  void ResetOnlineIsReady() { online_ready_.store(false); }

 protected:
  std::atomic<bool> online_ready_{false};
  std::shared_ptr<FiberCondition> online_ready_condition_;
};

}  // namespace encrypto::motion
