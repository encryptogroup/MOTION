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
#include "bmr_share.h"
#include "gate/bmr_gate.h"

namespace MOTION::Shares {
using SharePtr = std::shared_ptr<Share>;

ShareWrapper ShareWrapper::operator~() const {
  assert(share_);
  if (share_->GetSharingType() == MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for Arithmetic GMW shares");
  }

  if (share_->GetSharingType() == MPCProtocol::BooleanGMW) {
    auto gmw_share = std::dynamic_pointer_cast<GMWShare>(share_);
    assert(gmw_share);
    auto inv_gate = std::make_shared<Gates::GMW::GMWINVGate>(gmw_share);
    share_->GetRegister()->RegisterNextGate(inv_gate);
    return ShareWrapper(inv_gate->GetOutputAsShare());
  } else {
    auto bmr_share = std::dynamic_pointer_cast<BMRShare>(share_);
    assert(bmr_share);
    auto inv_gate = std::make_shared<Gates::BMR::BMRINVGate>(bmr_share);
    share_->GetRegister()->RegisterNextGate(inv_gate);
    return ShareWrapper(inv_gate->GetOutputAsShare());
  }
}

ShareWrapper ShareWrapper::operator^(const ShareWrapper &other) const {
  assert(share_);
  assert(*other);
  assert(share_->GetSharingType() == other->GetSharingType());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetSharingType() == MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for Arithmetic GMW shares");
  }

  if (share_->GetSharingType() == MPCProtocol::BooleanGMW) {
    auto this_b = std::dynamic_pointer_cast<GMWShare>(share_);
    auto other_b = std::dynamic_pointer_cast<GMWShare>(*other);

    assert(this_b);
    assert(other_b);

    auto xor_gate = std::make_shared<Gates::GMW::GMWXORGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(xor_gate);
    return ShareWrapper(xor_gate->GetOutputAsShare());
  } else {
    auto this_b = std::dynamic_pointer_cast<BMRShare>(share_);
    auto other_b = std::dynamic_pointer_cast<BMRShare>(*other);

    auto xor_gate = std::make_shared<Gates::BMR::BMRXORGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(xor_gate);
    return ShareWrapper(xor_gate->GetOutputAsShare());
  }
}

ShareWrapper ShareWrapper::operator&(const ShareWrapper &other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetSharingType() == other->GetSharingType());
  assert(share_->GetBitLength() == other->GetBitLength());

  if (share_->GetSharingType() == MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Boolean primitive operations are not supported for Arithmetic GMW shares");
  }

  if (share_->GetSharingType() == MPCProtocol::BooleanGMW) {
    auto this_b = std::dynamic_pointer_cast<GMWShare>(share_);
    auto other_b = std::dynamic_pointer_cast<GMWShare>(*other);

    auto and_gate = std::make_shared<Gates::GMW::GMWANDGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(and_gate);
    return ShareWrapper(and_gate->GetOutputAsShare());
  } else {
    auto this_b = std::dynamic_pointer_cast<BMRShare>(share_);
    auto other_b = std::dynamic_pointer_cast<BMRShare>(*other);

    auto and_gate = std::make_shared<Gates::BMR::BMRANDGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(and_gate);
    return ShareWrapper(and_gate->GetOutputAsShare());
  }
}

ShareWrapper ShareWrapper::operator+(const ShareWrapper &other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetSharingType() == other->GetSharingType());
  assert(share_->GetBitLength() == other->GetBitLength());
  if (share_->GetSharingType() != MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW shares");
  }

  if (share_->GetBitLength() == 8u) {
    return Add<std::uint8_t>(share_, *other);
  } else if (share_->GetBitLength() == 16u) {
    return Add<std::uint16_t>(share_, *other);
  } else if (share_->GetBitLength() == 32u) {
    return Add<std::uint32_t>(share_, *other);
  } else if (share_->GetBitLength() == 64u) {
    return Add<std::uint64_t>(share_, *other);
  } else {
    throw std::bad_cast();
  }
}

ShareWrapper ShareWrapper::operator*(const ShareWrapper &other) const {
  assert(*other);
  assert(share_);
  assert(share_->GetSharingType() == other->GetSharingType());
  assert(share_->GetBitLength() == other->GetBitLength());
  assert(share_->GetNumOfSIMDValues() == other->GetNumOfSIMDValues());
  if (share_->GetSharingType() != MPCProtocol::ArithmeticGMW) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW shares");
  }

  if (share_->GetBitLength() == 8u) {
    return Mul<std::uint8_t>(share_, *other);
  } else if (share_->GetBitLength() == 16u) {
    return Mul<std::uint16_t>(share_, *other);
  } else if (share_->GetBitLength() == 32u) {
    return Mul<std::uint32_t>(share_, *other);
  } else if (share_->GetBitLength() == 64u) {
    return Mul<std::uint64_t>(share_, *other);
  } else {
    throw std::bad_cast();
  }
}

ShareWrapper ShareWrapper::MUX(const ShareWrapper &a, const ShareWrapper &b) const {
  assert(*a);
  assert(*b);
  assert(share_);
  assert(share_->GetSharingType() == a->GetSharingType());
  assert(share_->GetSharingType() == b->GetSharingType());
  assert(a->GetBitLength() == b->GetBitLength());
  assert(share_->GetBitLength() == 1);

  if (share_->GetSharingType() == MPCProtocol::ArithmeticGMW) {
    // TODO implement
    throw std::runtime_error("C-OT-based MUX for Arithmetic GMW shares is not implemented yet");
  }

  if (share_->GetSharingType() == MPCProtocol::BooleanGMW) {
    auto this_gmw = std::dynamic_pointer_cast<GMWShare>(share_);
    auto a_gmw = std::dynamic_pointer_cast<GMWShare>(*a);
    auto b_gmw = std::dynamic_pointer_cast<GMWShare>(*b);

    assert(this_gmw);
    assert(a_gmw);
    assert(b_gmw);

    auto mux_gate = std::make_shared<Gates::GMW::GMWMUXGate>(a_gmw, b_gmw, this_gmw);
    share_->GetRegister()->RegisterNextGate(mux_gate);
    return ShareWrapper(mux_gate->GetOutputAsShare());
  } else {
    auto a_xor_b = a ^ b;

    return a_xor_b;
  }
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
      return backend->BMROutput(share_, output_owner);
    }
    default: {
      throw(std::runtime_error(fmt::format("Unknown MPC protocol with id {}",
                                           static_cast<uint>(share_->GetSharingType()))));
    }
  }
}
}