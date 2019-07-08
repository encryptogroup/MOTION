#pragma once

#include "gate/arithmetic_gmw_gate.h"
#include "gate/boolean_gmw_gate.h"

#include "share/arithmetic_gmw_share.h"
#include "share/boolean_gmw_share.h"

namespace ABYN::Shares {
class ShareWrapper {
 public:
  ShareWrapper(const SharePtr &share) : share_(share) {}
  ShareWrapper(const ShareWrapper &sw) : share_(sw.share_) {}

  ShareWrapper() = delete;

  void operator=(SharePtr share) { share_ = share; }
  void operator=(const ShareWrapper &sw) { share_ = sw.share_; }

  ShareWrapper operator^(const ShareWrapper &other) {
    if (share_->GetSharingType() == Protocol::ArithmeticGMW) {
      throw std::runtime_error(
          "Boolean primitive operations are only supported for Boolean GMW shares");
    }
    assert(share_);
    assert(*other);
    auto this_b = std::dynamic_pointer_cast<GMWShare>(share_);
    auto other_b = std::dynamic_pointer_cast<GMWShare>(*other);

    auto xor_gate = std::make_shared<Gates::GMW::GMWXORGate>(this_b, other_b);
    share_->GetRegister()->RegisterNextGate(xor_gate);
    return ShareWrapper(xor_gate->GetOutputAsShare());
  }

  void operator^=(const ShareWrapper &other) { *this = *this ^ other; }

  std::shared_ptr<Share> operator&(const ShareWrapper &other) {
    throw std::runtime_error(
        "Arithmetic primitive operations are only supported for arithmetic GMW shares");
  }

  void operator&=(const ShareWrapper &other) { *this = *this & other; }

  ShareWrapper operator+(const ShareWrapper &other) {
    assert(*other);
    assert(share_->GetSharingType() == Protocol::ArithmeticGMW);
    assert(share_->GetSharingType() == other->GetSharingType());
    assert(share_->GetBitLength() == other->GetBitLength());
    if (share_->GetSharingType() != Protocol::ArithmeticGMW) {
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

  void operator+=(const ShareWrapper &other) { *this = *this + other; }

  std::shared_ptr<Share> operator*(const ShareWrapper &other) {
    throw std::runtime_error("Arithmetic GMW multiplication is not implemented yet");
  }

  void operator*=(const ShareWrapper &other) { *this = *this * other; }

  SharePtr &Get() { return share_; }

  const SharePtr &operator*() const { return share_; }

  const SharePtr &operator->() const { return share_; }

  const SharePtr Out(std::size_t output_owner) {
    assert(share_);
    auto backend = share_->GetBackend().lock();
    assert(backend);
    switch (share_->GetSharingType()) {
      case Protocol::ArithmeticGMW: {
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
      case Protocol::BooleanGMW: {
        return backend->BooleanGMWOutput(share_, output_owner);
      }
      case Protocol::BMR: {
        throw(std::runtime_error("BMR output gate is not implemented yet"));
        // TODO
      }
      default: {
        throw(std::runtime_error(fmt::format("Unknown protocol with id {}",
                                             static_cast<uint>(share_->GetSharingType()))));
      }
    }
  }

 private:
  SharePtr share_;

  template <typename T>
  ShareWrapper Add(SharePtr share, SharePtr other) {
    auto this_a = std::dynamic_pointer_cast<ArithmeticShare<T>>(share);
    auto wire_a = this_a->GetArithmeticWire();
    auto other_a = std::dynamic_pointer_cast<ArithmeticShare<T>>(other);
    assert(other_a);
    auto wire_b = other_a->GetArithmeticWire();
    auto addition_gate =
        std::make_shared<Gates::Arithmetic::ArithmeticAdditionGate<T>>(wire_a, wire_b);
    auto addition_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(addition_gate);
    share_->GetRegister()->RegisterNextGate(addition_gate_cast);
    auto res = std::static_pointer_cast<Shares::Share>(addition_gate->GetOutputAsArithmeticShare());
    return ShareWrapper(res);
  }
};
}