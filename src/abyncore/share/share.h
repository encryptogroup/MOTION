#ifndef SHARE_H
#define SHARE_H

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

  const ABYN::CorePtr &GetCore() const { return core_; }

  Share(Share &) = delete;

  Share(const Share &) = delete;

 protected:
  Share() = default;

  ABYN::CorePtr core_;
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
    core_ = wires_.at(0)->GetCore();
  }

  ArithmeticShare(ABYN::Wires::ArithmeticWirePtr<T> &wire) : wires_({wire}) {
    wires_ = {wire};
    assert(wire);
    core_ = wires_.at(0)->GetCore();
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
    core_ = wires_.at(0)->GetCore();
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
    core_ = wires_.at(0)->GetCore();
  }

  ArithmeticShare(std::vector<T> &input, const CorePtr &core) {
    core_ = core;
    wires_ = {std::make_shared<Wires::ArithmeticWire<T>>(input, core)};
  }

  ArithmeticShare(T input, const CorePtr &core) {
    core_ = core;
    wires_ = {std::make_shared<Wires::ArithmeticWire<T>>(input, core)};
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
  ArithmeticConstantShare(T input, const CorePtr &core) : values_({input}) { core_ = core; }

  ArithmeticConstantShare(std::vector<T> &input, const CorePtr &core) : values_(input) {
    core_ = core;
  }

  ArithmeticConstantShare(std::vector<T> &&input, const CorePtr &core) : values_(std::move(input)) {
    core_ = core;
  }

  ~ArithmeticConstantShare() override = default;

  std::size_t GetNumOfParallelValues() final { return values_.size(); };

  Protocol GetSharingType() final { return ArithmeticGMW; }

  const std::vector<T> &GetValue() const { return values_; }

  std::shared_ptr<Share> Clone() final {
    // TODO
    return std::static_pointer_cast<Share>(
        std::make_shared<ArithmeticConstantShare>(values_, core_));
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
  GMWShare(std::vector<u8> &input, CorePtr &core, std::size_t bits) {
    wires_ = {std::make_shared<Wires::GMWWire>(input, core, bits)};
    core_ = core;
    bits_ = bits;
  }

  GMWShare(std::vector<u8> &&input, CorePtr &core, std::size_t bits) {
    wires_ = {std::make_shared<Wires::GMWWire>(std::move(input), core, bits)};
    core_ = core;
    bits_ = bits;
  }

  GMWShare(std::vector<std::vector<u8>> &input, CorePtr &core, std::size_t bits) {
    if (input.size() == 0) {
      throw(std::runtime_error("Trying to create a Boolean GMW share without wires"));
    }
    for (auto &v : input) {
      wires_.push_back(std::make_shared<Wires::GMWWire>(v, core, bits));
    }
    core_ = core;
    bits_ = bits;
  }

  GMWShare(std::vector<std::vector<u8>> &&input, CorePtr &core, std::size_t bits) {
    if (input.size() == 0) {
      throw(std::runtime_error("Trying to create a Boolean GMW share without wires"));
    }
    for (auto &v : input) {
      wires_.push_back(std::make_shared<Wires::GMWWire>(std::move(v), core, bits));
    }
    core_ = core;
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
    core_ = wires.at(0)->GetCore();
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
#endif  // SHARE_H
