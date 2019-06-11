#pragma once

#include <memory>

#include "utility/typedefs.h"
#include "wire/wire.h"

namespace ABYN::Shares {

class Share {
 public:
  virtual ~Share() = default;

  virtual std::size_t GetNumOfParallelValues() = 0;

  virtual Protocol GetSharingType() = 0;

  virtual std::size_t GetBitLength() = 0;

  virtual const std::vector<Wires::WirePtr> GetWires() const = 0;

  virtual std::shared_ptr<Share> Clone() = 0;

  std::weak_ptr<ABYN::Register> GetRegister() const { return register_; }

  Share(Share &) = delete;

  Share(const Share &) = delete;

 protected:
  Share() = default;

  std::weak_ptr<ABYN::Register> register_;
};

using SharePtr = std::shared_ptr<Share>;

/*
 * Allow only unsigned integers for Arithmetic shares.
 */
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticShare : public Share {
 public:
  ArithmeticShare(const ABYN::Wires::WirePtr &wire) {
    wires_ = {std::dynamic_pointer_cast<ArithmeticShare<T>>(wire)};
    if (!wires_.at(0)) {
      throw(std::runtime_error("Something went wrong with creating an arithmetic share"));
    }
    register_ = wires_.at(0)->GetRegister();
  }

  ArithmeticShare(ABYN::Wires::ArithmeticWirePtr<T> &wire) : wires_({wire}) {
    wires_ = {wire};
    assert(wire);
    register_ = wires_.at(0)->GetRegister();
  }

  ArithmeticShare(std::vector<ABYN::Wires::ArithmeticWirePtr<T>> &wires) : wires_(wires) {
    if (wires.size() == 0) {
      throw(std::runtime_error("Trying to create an arithmetic share without wires"));
    }
    if (wires.size() > 1) {
      throw(
          std::runtime_error(fmt::format("Cannot create an arithmetic share "
                                         "from more than 1 wire; got {} wires",
                                         wires.size())));
    }
    register_ = wires_.at(0)->GetRegister();
  }

  ArithmeticShare(std::vector<ABYN::Wires::WirePtr> &wires) {
    if (wires.size() == 0) {
      throw(std::runtime_error("Trying to create an arithmetic share without wires"));
    }
    if (wires.size() > 1) {
      throw(
          std::runtime_error(fmt::format("Cannot create an arithmetic share "
                                         "from more than 1 wire; got {} wires",
                                         wires.size())));
    }
    wires_ = {std::dynamic_pointer_cast<ArithmeticShare<T>>(wires.at(0))};
    if (!wires_.at(0)) {
      throw(std::runtime_error("Something went wrong with creating an arithmetic share"));
    }
    register_ = wires_.at(0)->GetRegister();
  }

  ArithmeticShare(std::vector<T> &input, const RegisterPtr &reg) {
    register_ = reg;
    wires_ = {std::make_shared<Wires::ArithmeticWire<T>>(input, reg)};
  }

  ArithmeticShare(T input, const RegisterPtr &reg) {
    register_ = reg;
    wires_ = {std::make_shared<Wires::ArithmeticWire<T>>(input, reg)};
  }

  ~ArithmeticShare() override = default;

  std::size_t GetNumOfParallelValues() final { return wires_.at(0)->GetNumOfParallelValues(); };

  Protocol GetSharingType() final { return wires_.at(0)->GetProtocol(); }

  const Wires::ArithmeticWirePtr<T> &GetArithmeticWire() { return wires_.at(0); }

  const std::vector<Wires::WirePtr> GetWires() const final {
    std::vector<Wires::WirePtr> result{std::static_pointer_cast<Wires::Wire>(wires_.at(0))};
    return std::move(result);
  }

  const bool &Finished() { return wires_.at(0)->IsReady(); }

  const std::vector<T> &GetValue() const { return wires_->GetRawSharedValues(); }

  std::size_t GetBitLength() final { return sizeof(T) * 8; }

  std::shared_ptr<Share> Clone() final {
    // TODO
    return std::static_pointer_cast<Share>(std::make_shared<ArithmeticShare<T>>(wires_));
  }

  std::shared_ptr<ArithmeticShare> NonVirtualClone() {
    return std::make_shared<ArithmeticShare>(wires_);
  }

  ArithmeticShare(ArithmeticShare &) = delete;

 protected:
  std::vector<Wires::ArithmeticWirePtr<T>> wires_;

 private:
  ArithmeticShare() = default;
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using ArithmeticSharePtr = std::shared_ptr<ArithmeticShare<T>>;

/*
 * Allow only unsigned integers for Arithmetic shares.
 */
template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
class ArithmeticConstantShare : public Share {
 public:
  ArithmeticConstantShare(T input, const RegisterPtr &reg) : values_({input}) { register_ = reg; }

  ArithmeticConstantShare(std::vector<T> &input, const RegisterPtr &reg) : values_(input) {
    register_ = reg;
  }

  ArithmeticConstantShare(std::vector<T> &&input, const RegisterPtr &reg)
      : values_(std::move(input)) {
    register_ = reg;
  }

  ~ArithmeticConstantShare() override = default;

  std::size_t GetNumOfParallelValues() final { return values_.size(); };

  Protocol GetSharingType() final { return ArithmeticGMW; }

  const std::vector<T> &GetValue() const { return values_; }

  std::shared_ptr<Share> Clone() final {
    // TODO
    return std::static_pointer_cast<Share>(
        std::make_shared<ArithmeticConstantShare>(values_, register_));
  };

  ArithmeticConstantShare() = delete;

  ArithmeticConstantShare(ArithmeticConstantShare &) = delete;

  std::size_t GetBitLength() final { return sizeof(T) * 8; }

 protected:
  std::vector<T> values_;

 private:
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using ArithmeticConstantSharePtr = std::shared_ptr<ArithmeticConstantShare<T>>;

class BooleanShare : public Share {
 public:
  ~BooleanShare() override = default;

  BooleanShare(BooleanShare &) = delete;

 protected:
  BooleanShare() = default;

  std::size_t bits_;
};

using BooleanSharePtr = std::shared_ptr<BooleanShare>;

class GMWShare : public BooleanShare {
 public:
  GMWShare(std::vector<std::uint8_t> &input, RegisterPtr &reg, std::size_t bits) {
    wires_ = {std::make_shared<Wires::GMWWire>(input, reg, bits)};
    register_ = reg;
    bits_ = bits;
  }

  GMWShare(std::vector<std::uint8_t> &&input, RegisterPtr &reg, std::size_t bits) {
    wires_ = {std::make_shared<Wires::GMWWire>(std::move(input), reg, bits)};
    register_ = reg;
    bits_ = bits;
  }

  GMWShare(std::vector<std::vector<std::uint8_t>> &input, RegisterPtr &reg, std::size_t bits) {
    if (input.size() == 0) {
      throw(std::runtime_error("Trying to create a Boolean GMW share without wires"));
    }
    for (auto &v : input) {
      wires_.push_back(std::make_shared<Wires::GMWWire>(v, reg, bits));
    }
    register_ = reg;
    bits_ = bits;
  }

  GMWShare(std::vector<std::vector<std::uint8_t>> &&input, RegisterPtr &reg, std::size_t bits) {
    if (input.size() == 0) {
      throw(std::runtime_error("Trying to create a Boolean GMW share without wires"));
    }
    for (auto &v : input) {
      wires_.push_back(std::make_shared<Wires::GMWWire>(std::move(v), reg, bits));
    }
    register_ = reg;
    bits_ = bits;
  }

  GMWShare(const std::vector<ABYN::Wires::WirePtr> &wires) {
    if (wires.size() == 0) {
      throw(std::runtime_error("Trying to create a Boolean GMW share without wires"));
    }
    for (auto &wire : wires) {
      if (wire->GetProtocol() != ABYN::Protocol::BooleanGMW) {
        throw(
            std::runtime_error("Trying to create a Boolean GMW share from wires "
                               "of different sharing type"));
      }
    }
    wires_ = wires;
    register_ = wires.at(0)->GetRegister();
    bits_ = wires.at(0)->GetBitLength();
  }

  const std::vector<Wires::WirePtr> GetWires() const final { return wires_; }

  std::size_t GetNumOfParallelValues() final { return wires_.size(); };

  Protocol GetSharingType() final { return ArithmeticGMW; }

  std::size_t GetBitLength() final { return wires_.size(); }

  std::shared_ptr<Share> Clone() final {
    // TODO
    return std::static_pointer_cast<Share>(std::make_shared<GMWShare>(wires_));
  };

 private:
  std::vector<ABYN::Wires::WirePtr> wires_;
  bool finished_ = false;
};

using GMWSharePtr = std::shared_ptr<GMWShare>;

class BMRShare : public BooleanShare {
  // TODO
};

using BMRSharePtr = std::shared_ptr<BMRShare>;
}  // namespace ABYN::Shares
