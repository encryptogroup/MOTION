#pragma once

#include <memory>
#include <vector>

#include "utility/typedefs.h"

namespace ABYN::Wires {
class Wire;  // forward declaration
using WirePtr = std::shared_ptr<Wire>;
}  // namespace ABYN::Wires

namespace ABYN {
class Register;  // forward declaration
using RegisterPtr = std::shared_ptr<Register>;
}  // namespace ABYN

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
