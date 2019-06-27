#include "condition.h"

namespace ENCRYPTO {

bool Condition::Wait() {
  while (!condition_function_()) {
    std::unique_lock<std::mutex> lock(mutex_);
    condition_variable_.wait(lock, [this] { return condition_function_(); });
  }
  return condition_function_();
}

}