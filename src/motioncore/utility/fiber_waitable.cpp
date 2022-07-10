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

#include "fiber_waitable.h"

#include "fiber_condition.h"

namespace encrypto::motion {

FiberSetupWaitable::FiberSetupWaitable() {
  setup_ready_condition_ =
      std::make_unique<FiberCondition>([this]() { return setup_ready_.load(); });
}

void FiberSetupWaitable::WaitSetup() const { setup_ready_condition_->Wait(); }

void FiberSetupWaitable::SetSetupIsReady() {
  {
    std::scoped_lock lock(setup_ready_condition_->GetMutex());
    setup_ready_.store(true);
  }
  setup_ready_condition_->NotifyAll();
}

FiberOnlineWaitable::FiberOnlineWaitable() {
  online_ready_condition_ =
      std::make_unique<FiberCondition>([this]() { return online_ready_.load(); });
}

void FiberOnlineWaitable::WaitOnline() const { online_ready_condition_->Wait(); }

void FiberOnlineWaitable::SetOnlineIsReady() {
  {
    std::scoped_lock lock(online_ready_condition_->GetMutex());
    online_ready_.store(true);
  }
  online_ready_condition_->NotifyAll();
}

}  // namespace encrypto::motion
