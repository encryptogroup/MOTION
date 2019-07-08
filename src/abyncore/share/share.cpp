#include "share.h"

#include "base/backend.h"

namespace ABYN::Shares{
  std::shared_ptr<Register> Share::GetRegister(){
    auto backend_ptr = backend_.lock();
    assert(backend_ptr);
    return backend_ptr->GetRegister();
  }
}
