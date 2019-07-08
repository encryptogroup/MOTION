#pragma once

#include <memory>
#include <vector>

namespace ABYN::Wires {
class Wire;  // forward declaration
using WirePtr = std::shared_ptr<Wire>;
}  // namespace ABYN::Wires

namespace ABYN {
class Backend;  // forward declaration
using BackendPtr = std::shared_ptr<Backend>;

class Register;

enum MPCProtocol : uint;
}  // namespace ABYN

namespace ABYN::Shares {

 class Share : public std::enable_shared_from_this<Share> {
 public:
  virtual ~Share() = default;

  virtual std::size_t GetNumOfParallelValues() const noexcept = 0;

  virtual MPCProtocol GetSharingType() const noexcept= 0;

  virtual std::size_t GetBitLength() const noexcept = 0;

  virtual const std::vector<Wires::WirePtr> GetWires() const = 0;

  virtual std::shared_ptr<Share> Clone() = 0;

  std::weak_ptr<Backend> GetBackend() const { return backend_; }

  std::shared_ptr<Register> GetRegister();

  Share(Share &) = delete;

  Share(const Share &) = delete;

 protected:
  Share() = default;

  std::weak_ptr<Backend> backend_;
};

using SharePtr = std::shared_ptr<Share>;

class BooleanShare : public Share {
 public:
  ~BooleanShare() override = default;

  BooleanShare(BooleanShare &) = delete;

 protected:
  BooleanShare() = default;

  std::size_t bits_;
};

using BooleanSharePtr = std::shared_ptr<BooleanShare>;

class BMRShare : public BooleanShare {
  // TODO
};

using BMRSharePtr = std::shared_ptr<BMRShare>;
}  // namespace ABYN::Shares
