#ifndef SHARE_H
#define SHARE_H

#include <memory>

#include "utility/typedefs.h"
#include "wire/wire.h"

namespace ABYN::Shares {

  class Share {
  public:
    virtual ~Share() {}

    virtual Protocol GetSharingType() = 0;

    virtual bool IsConstantShare() = 0;

    virtual std::vector<Wires::WirePtr> GetWires() = 0;

    virtual bool IsDone() = 0;

  protected:
    Share() {};

    ABYNCorePtr core_;
    bool done_ = false;

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
    ArithmeticShare(T input, const ABYNCorePtr &core) {
      wire_ = std::make_shared<Wires::ArithmeticWire<T>>(input, core);
      core_ = core;
    }

    ~ArithmeticShare() {}

    Protocol GetSharingType() override final { return wire_->GetProtocol(); }

    bool IsConstantShare() override final { return false; }

    std::vector<Wires::WirePtr> GetWires() override final {
      std::vector<Wires::WirePtr> result;
      result.push_back(std::static_pointer_cast<Wires::Wire>(wire_));
      return std::move(result);
    }

    bool IsDone() override final { return wire_->IsDone(); }

    const std::vector<T> &GetValue() const { return wire_->GetRawValues(); }

    auto GetValueByteLength() { return sizeof(T); }

  protected:
    //Arithmetic share can have only one wire
    Wires::ArithmeticWirePtr<T> wire_;

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

  protected:
    std::vector<T> values_;

  public:
    ArithmeticConstantShare(T input, const ABYNCorePtr &core) : values_(std::move(std::vector{input})) { core_ = core; }

    ArithmeticConstantShare(std::vector<T> &input, const ABYNCorePtr &core) : values_(input) {
      core_ = core;
    }

    ArithmeticConstantShare(std::vector<T> &&input, const ABYNCorePtr &core) : values_(std::move(input)) {
      core_ = core;
    }

    ~ArithmeticConstantShare() {};

    Protocol GetSharingType() override final { return ArithmeticGMW; }

    bool IsConstantShare() override final { return true; }

    bool IsDone() override final { return true; }

    const std::vector<T> &GetValue() const { return values_; }

  };

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using ArithmeticConstantSharePtr = std::shared_ptr<ArithmeticConstantShare<T>>;

}
#endif //SHARE_H
