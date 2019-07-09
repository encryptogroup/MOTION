#pragma once

#include "gate.h"

#include "share/boolean_gmw_share.h"
#include "utility/bit_vector.h"

namespace ABYN::Gates::GMW {

class GMWInputGate : public Gates::Interfaces::InputGate {
 public:
  GMWInputGate(const std::vector<ENCRYPTO::BitVector> &input, std::size_t party_id,
               std::weak_ptr<Backend> reg);

  GMWInputGate(std::vector<ENCRYPTO::BitVector> &&input, std::size_t party_id,
               std::weak_ptr<Backend> reg);

  void InitializationHelper();

  ~GMWInputGate() final = default;

  void EvaluateSetup() final;

  void EvaluateOnline() final;

  const Shares::GMWSharePtr GetOutputAsGMWShare();

 protected:
  /// two-dimensional vector for storing the raw inputs
  std::vector<ENCRYPTO::BitVector> input_;

  std::size_t bits_;                ///< Number of parallel values on wires
  std::size_t boolean_sharing_id_;  ///< Sharing ID for Boolean GMW for generating
  ///< correlated randomness using AES CTR
};

class GMWOutputGate : public Interfaces::OutputGate {
 public:
  GMWOutputGate(const std::vector<Wires::WirePtr> &parent, std::size_t output_owner);

  ~GMWOutputGate() final = default;

  void EvaluateSetup() final { SetSetupIsReady(); }

  void EvaluateOnline() final;

  const Shares::GMWSharePtr GetOutputAsGMWShare() const;

  const Shares::SharePtr GetOutputAsShare() const;

 protected:
  std::vector<ENCRYPTO::BitVector> output_;
  std::vector<std::vector<ENCRYPTO::BitVector>> shared_outputs_;

  // indicates whether this party obtains the output
  bool is_my_output_ = false;

  std::mutex m;
};

class GMWXORGate : public Gates::Interfaces::TwoGate {
 public:
  GMWXORGate(const Shares::GMWSharePtr &a, const Shares::GMWSharePtr &b);

  ~GMWXORGate() final = default;

  void EvaluateSetup() final { SetSetupIsReady(); }

  void EvaluateOnline() final;

  const Shares::GMWSharePtr GetOutputAsGMWShare() const;

  const Shares::SharePtr GetOutputAsShare() const;

  GMWXORGate() = delete;

  GMWXORGate(const Gate &) = delete;
};

}  // namespace ABYN::Gates::GMW