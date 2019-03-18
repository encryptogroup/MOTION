#ifndef SHARE_H
#define SHARE_H

#include <memory>

#include "utility/typedefs.h"
#include "wire/wire.h"

namespace ABYN::Shares {

  class Share {
  public:
    virtual ~Share() {}

    virtual std::size_t GetNumOfParallelValues() = 0;

    virtual Protocol GetSharingType() = 0;

    virtual std::vector<Wires::WirePtr> GetWires() = 0;

    virtual const std::vector<Wires::WirePtr> GetWires() const = 0;

    virtual const bool &Finished() = 0;

    virtual std::shared_ptr<Share> Clone() = 0;

    const ABYN::CorePtr &GetCore() { return core_; }

  protected:
    Share() {};

    ABYN::CorePtr core_;

  private:

    Share(Share &) = delete;

    Share(const Share &) = delete;
  };


  using SharePtr = std::shared_ptr<Share>;

/*
 * Allow only unsigned integers for Arithmetic shares.
 */
  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  class ArithmeticShare : public Share {
  public:
    ArithmeticShare(ABYN::Wires::WirePtr &wire) {
      wires_ = {std::dynamic_pointer_cast<ArithmeticShare<T>>(wire)};
      if (!wires_.at(0)) { throw (std::runtime_error("Something went wrong with creating an arithmetic share")); }
      core_ = wires_.at(0)->GetCore();
    }

    ArithmeticShare(ABYN::Wires::ArithmeticWirePtr<T> &wire) : wires_({wire}) {
      core_ = wires_.at(0)->GetCore();
    }

    ArithmeticShare(std::vector<ABYN::Wires::ArithmeticWirePtr<T>> &wires) : wires_(wires) {
      if (wires.size() == 0) { throw (std::runtime_error("Trying to create an arithmetic share without wires")); }
      if (wires.size() > 1) {
        throw (std::runtime_error(
            fmt::format("Cannot create an arithmetic share from more than 1 wire; got {} wires", wires.size())));
      }
      core_ = wires_.at(0)->GetCore();
    }

    ArithmeticShare(std::vector<ABYN::Wires::WirePtr> &wires) {
      if (wires.size() == 0) { throw (std::runtime_error("Trying to create an arithmetic share without wires")); }
      if (wires.size() > 1) {
        throw (std::runtime_error(
            fmt::format("Cannot create an arithmetic share from more than 1 wire; got {} wires", wires.size())));
      }
      wires_ = {std::dynamic_pointer_cast<ArithmeticShare<T>>(wires.at(0))};
      if (!wires_.at(0)) { throw (std::runtime_error("Something went wrong with creating an arithmetic share")); }
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

    ~ArithmeticShare() {}

    std::size_t GetNumOfParallelValues() override final { return wires_.at(0)->GetNumOfParallelValues(); };

    Protocol GetSharingType() override final { return wires_.at(0)->GetProtocol(); }

    const Wires::ArithmeticWirePtr<T> &GetArithmeticWire() { return wires_.at(0); }

    std::vector<Wires::WirePtr> GetWires() override final {
      std::vector<Wires::WirePtr> result;
      result.push_back(std::static_pointer_cast<Wires::Wire>(wires_.at(0)));
      return std::move(result);
    }

    virtual const std::vector<Wires::WirePtr> GetWires() const override final {
      std::vector<Wires::WirePtr> result{std::static_pointer_cast<Wires::Wire>(wires_.at(0))};
      return std::move(result);
    }

    const bool &Finished() override final { return wires_.at(0)->IsReady(); }

    const std::vector<T> &GetValue() const { return wires_->GetRawSharedValues(); }

    auto GetValueByteLength() { return sizeof(T); }

    std::shared_ptr<Share> Clone() override final {
      //TODO
      return std::static_pointer_cast<Share>(std::make_shared<ArithmeticShare<T>>(wires_));
    }

    std::shared_ptr<ArithmeticShare> NonVirtualClone() {
      return std::make_shared<ArithmeticShare>(wires_);
    }

  protected:
    std::vector<Wires::ArithmeticWirePtr<T>> wires_;

  private:
    ArithmeticShare() {};

    ArithmeticShare(ArithmeticShare &) = delete;
  };

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using ArithmeticSharePtr = std::shared_ptr<ArithmeticShare<T>>;

/*
 * Allow only unsigned integers for Arithmetic shares.
 */
  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  class ArithmeticConstantShare : public Share {
  private:
    ArithmeticConstantShare() = delete;

    ArithmeticConstantShare(ArithmeticConstantShare &) = delete;

    static const bool CONSTANT_ALWAYS_FINISHED = true;
  protected:
    std::vector<T> values_;

  public:
    ArithmeticConstantShare(T input, const CorePtr &core) : values_(std::move(std::vector{input})) {
      core_ = core;
    }

    ArithmeticConstantShare(std::vector<T> &input, const CorePtr &core) : values_(input) {
      core_ = core;
    }

    ArithmeticConstantShare(std::vector<T> &&input, const CorePtr &core) : values_(std::move(input)) {
      core_ = core;
    }

    ~ArithmeticConstantShare() {};

    std::size_t GetNumOfParallelValues() override final { return values_.size(); };

    Protocol GetSharingType() override final { return ArithmeticGMW; }

    const bool &Finished() override final { return CONSTANT_ALWAYS_FINISHED; }

    const std::vector<T> &GetValue() const { return values_; }

    std::shared_ptr<Share> Clone() override final {
      //TODO
      return std::static_pointer_cast<Share>(std::make_shared<ArithmeticConstantShare>(values_, core_));
    };

  };

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using ArithmeticConstantSharePtr = std::shared_ptr<ArithmeticConstantShare<T>>;

  class BooleanShare : public Share {
  };

  using BooleanSharePtr = std::shared_ptr<BooleanShare>;


  class BooleanGMWShare : public BooleanShare {
  public:
    BooleanGMWShare(std::vector<bool> &input, CorePtr &core) {
      core_ = core;
      wires_ = {std::make_shared<Wires::GMWWire>(input, core)};
    }

    BooleanGMWShare(std::vector<bool> &&input, CorePtr &core) {
      core_ = core;
      wires_ = {std::make_shared<Wires::GMWWire>(std::move(input), core)};
    }

    BooleanGMWShare(std::vector<std::vector<bool>> &input, CorePtr &core) {
      if (input.size() == 0) { throw (std::runtime_error("Trying to create a Boolean GMW share without wires")); }
      core_ = core;
      for (auto &v : input) { wires_.push_back(std::make_shared<Wires::GMWWire>(v, core)); }
    }

    BooleanGMWShare(std::vector<std::vector<bool>> &&input, CorePtr &core) {
      if (input.size() == 0) { throw (std::runtime_error("Trying to create a Boolean GMW share without wires")); }
      core_ = core;
      for (auto &v : input) { wires_.push_back(std::make_shared<Wires::GMWWire>(std::move(v), core)); }
    }

    BooleanGMWShare(const std::vector<ABYN::Wires::WirePtr> &wires) {
      if (wires.size() == 0) { throw (std::runtime_error("Trying to create a Boolean GMW share without wires")); }
      wires_ = wires;
      this->core_ = wires.at(0)->GetCore();
    }

    virtual std::vector<Wires::WirePtr> GetWires() {
      return wires_;
    }

    virtual const std::vector<Wires::WirePtr> GetWires() const {
      return wires_;
    }

    std::size_t GetNumOfParallelValues() override final { return wires_.size(); };

    Protocol GetSharingType() override final { return ArithmeticGMW; }

    const bool &Finished() override final {
      return finished_;
    }

    std::shared_ptr<Share> Clone() override final {
      //TODO
      return std::static_pointer_cast<Share>(std::make_shared<BooleanGMWShare>(wires_));
    };
  private:
    std::vector<ABYN::Wires::WirePtr> wires_;
    bool finished_ = false;
  };

  using BooleanGMWSharePtr = std::shared_ptr<BooleanGMWShare>;


  class BMRShare : public BooleanShare {

  };

  using BMRSharePtr = std::shared_ptr<BMRShare>;
}
#endif //SHARE_H
