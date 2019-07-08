#pragma once

#include "share.h"

namespace ABYN::Shares {

class GMWShare : public BooleanShare {
 public:
  GMWShare(const std::vector<ABYN::Wires::WirePtr> &wires);

  const std::vector<Wires::WirePtr> GetWires() const noexcept final { return wires_; }

  std::size_t GetNumOfParallelValues() const noexcept final;

  MPCProtocol GetSharingType() const noexcept final;

  std::size_t GetBitLength() const noexcept final { return wires_.size(); }

  std::shared_ptr<Share> Clone() final {
    return std::static_pointer_cast<Share>(std::make_shared<GMWShare>(wires_));
  }

 private:
  std::vector<ABYN::Wires::WirePtr> wires_;
  bool finished_ = false;
};

using GMWSharePtr = std::shared_ptr<GMWShare>;

}