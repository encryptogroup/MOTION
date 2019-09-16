// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
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

#include "share_wrapper.h"

#include "base/backend.h"

namespace ABYN::Shares {
using SharePtr = std::shared_ptr<Share>;

ShareWrapper &ShareWrapper::operator^(const ShareWrapper &other) {
  if (share_->GetSharingType() == MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Boolean primitive operations are only supported for Boolean GMW shares");
  }
  assert(share_);
  assert(*other);
  auto this_b = std::dynamic_pointer_cast<GMWShare>(share_);
  auto other_b = std::dynamic_pointer_cast<GMWShare>(*other);

  auto xor_gate = std::make_shared<Gates::GMW::GMWXORGate>(this_b, other_b);
  share_->GetRegister()->RegisterNextGate(xor_gate);
  *this = ShareWrapper(xor_gate->GetOutputAsShare());
  return *this;
}

ShareWrapper &ShareWrapper::operator&(const ShareWrapper &other) {
  assert(*other);
  assert(share_);
  assert(share_->GetSharingType() == other->GetSharingType());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetSharingType() != MPCProtocol::BooleanGMW) {
    throw std::runtime_error(
        "Boolean primitive operations are only supported for boolean GMW shares");
  }

  auto this_b = std::dynamic_pointer_cast<GMWShare>(share_);
  auto other_b = std::dynamic_pointer_cast<GMWShare>(*other);

  auto and_gate = std::make_shared<Gates::GMW::GMWANDGate>(this_b, other_b);
  share_->GetRegister()->RegisterNextGate(and_gate);
  *this = ShareWrapper(and_gate->GetOutputAsShare());
  return *this;
}

ShareWrapper &ShareWrapper::operator+(const ShareWrapper &other) {
  assert(*other);
  assert(share_);
  assert(share_->GetSharingType() == other->GetSharingType());
  assert(share_->GetBitLength() == other->GetBitLength());
  if (share_->GetSharingType() != MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW shares");
  }

  if (share_->GetBitLength() == 8u) {
    *this = Add<std::uint8_t>(share_, *other);
  } else if (share_->GetBitLength() == 16u) {
    *this = Add<std::uint16_t>(share_, *other);
  } else if (share_->GetBitLength() == 32u) {
    *this = Add<std::uint32_t>(share_, *other);
  } else if (share_->GetBitLength() == 64u) {
    *this = Add<std::uint64_t>(share_, *other);
  } else {
    throw std::bad_cast();
  }
  return *this;
}

ShareWrapper &ShareWrapper::operator*(const ShareWrapper &other) {
  assert(*other);
  assert(share_);
  assert(share_->GetSharingType() == other->GetSharingType());
  assert(share_->GetBitLength() == other->GetBitLength());
  assert(share_->GetNumOfParallelValues() == other->GetNumOfParallelValues());
  if (share_->GetSharingType() != MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW shares");
  }

  if (share_->GetBitLength() == 8u) {
    *this = Mul<std::uint8_t>(share_, *other);
  } else if (share_->GetBitLength() == 16u) {
    *this = Mul<std::uint16_t>(share_, *other);
  } else if (share_->GetBitLength() == 32u) {
    *this = Mul<std::uint32_t>(share_, *other);
  } else if (share_->GetBitLength() == 64u) {
    *this = Mul<std::uint64_t>(share_, *other);
  } else {
    throw std::bad_cast();
  }
  return *this;
}

const SharePtr ShareWrapper::Out(std::size_t output_owner) {
  assert(share_);
  auto backend = share_->GetBackend().lock();
  assert(backend);
  switch (share_->GetSharingType()) {
    case MPCProtocol::ArithmeticGMW: {
      switch (share_->GetBitLength()) {
        case 8u: {
          return backend->ArithmeticGMWOutput<std::uint8_t>(share_, output_owner);
        }
        case 16u: {
          return backend->ArithmeticGMWOutput<std::uint16_t>(share_, output_owner);
        }
        case 32u: {
          return backend->ArithmeticGMWOutput<std::uint32_t>(share_, output_owner);
        }
        case 64u: {
          return backend->ArithmeticGMWOutput<std::uint64_t>(share_, output_owner);
        }
        default: {
          throw(std::runtime_error(
              fmt::format("Unknown arithmetic ring of {} bilength", share_->GetBitLength())));
        }
      }
    }
    case MPCProtocol::BooleanGMW: {
      return backend->BooleanGMWOutput(share_, output_owner);
    }
    case MPCProtocol::BMR: {
      throw(std::runtime_error("BMR output gate is not implemented yet"));
      // TODO
    }
    default: {
      throw(std::runtime_error(
          fmt::format("Unknown protocol with id {}", static_cast<uint>(share_->GetSharingType()))));
    }
  }
}
}