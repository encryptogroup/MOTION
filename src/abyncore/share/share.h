#ifndef SHARE_H
#define SHARE_H

#include <memory>

#include "utility/typedefs.h"
#include "wire/wire.h"

namespace ABYN::Gates::Interfaces {
  class Gate;

  using GatePtr = std::shared_ptr<Gate>;
}

namespace ABYN::Shares {

  class Share {
  public:
    virtual Protocol GetSharingType() = 0;

    virtual bool IsConstantShare() = 0;

    virtual ~Share() {}

  protected:
    ABYNBackendPtr backend_;
    bool done_ = false;
    std::vector<ABYN::Gates::Interfaces::GatePtr> waiting_gates_;

  private:
    Share() = delete;

    Share(Share &) = delete;
  };


  using SharePtr = std::shared_ptr<Share>;

/*
 * Allow only unsigned integers for Arithmetic shares.
 */
  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  class ArithmeticShare : public Share {
  public:
    virtual std::vector<T> &GetValue() final { return wire_->GetRawValues(); }

    virtual Protocol GetSharingType() final { return wire_->GetProtocol(); }

    virtual bool IsConstantShare() final { return false; }

    auto GetValueByteLength() { return sizeof(T); }

    ArithmeticShare(T input, ABYNBackendPtr &backend) {
      wire_ = ArithmeticWirePtr<T>(input, backend);
      backend_ = backend;
    }

    ~ArithmeticShare() {}

  protected:
    //Arithmetic share can have only one wire
    ArithmeticWirePtr<T> wire_;

  private:
    ArithmeticShare() = delete;

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
    virtual std::vector<T> &GetValue() final { return values_; }

    virtual Protocol GetSharingType() final { return ArithmeticGMW; }

    virtual bool IsConstantShare() final { return true; }

    ArithmeticConstantShare(T input, ABYNBackendPtr &backend) : values_(
        std::move(std::vector{input})) { backend_ = backend; }

    ArithmeticConstantShare(std::vector<T> &input, ABYNBackendPtr &backend) : values_(input) {
      backend_ = backend;
    }

    ArithmeticConstantShare(std::vector<T> &&input, ABYNBackendPtr &backend) : values_(std::move(input)) {
      backend_ = backend;
    }

    ~ArithmeticConstantShare() {};
  };

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using ArithmeticConstantSharePtr = std::shared_ptr<ArithmeticConstantShare<T>>;

}
#endif //SHARE_H
