#ifndef ABYNPARTY_H
#define ABYNPARTY_H

#include <vector>
#include <memory>
#include <omp.h>
#include <fmt/format.h>

#include "utility/typedefs.h"
#include "utility/constants.h"
#include "utility/configuration.h"
#include "abynparty/backend.h"
#include "gate/gate.h"
#include "share/share.h"
//#include "OTExtension/ot/ot-ext.h"

namespace ABYN {

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using ArithmeticSharePtr = ABYN::Shares::ArithmeticSharePtr<T>;

  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using ArithmeticShare = ABYN::Shares::ArithmeticShare<T>;

  class Party {
  public:

    Party(std::vector<CommunicationContextPtr> &parties, std::size_t my_id) {
      config_ = std::make_shared<Configuration>(parties, my_id);
      backend_ = std::make_shared<Backend>(config_);
    }

    Party(std::vector<CommunicationContextPtr> &&parties, std::size_t my_id) {
      config_ = std::make_shared<Configuration>(std::move(parties), my_id);
      backend_ = std::make_shared<Backend>(config_);
    }

    Party(std::initializer_list<CommunicationContextPtr> &list_parties, std::size_t my_id) {
      config_ = std::make_shared<Configuration>(list_parties, my_id);
      backend_ = std::make_shared<Backend>(config_);
    }

    Party(std::initializer_list<CommunicationContextPtr> &&list_parties, std::size_t my_id) {
      config_ = std::make_shared<Configuration>(std::move(list_parties), my_id);
      backend_ = std::make_shared<Backend>(config_);
    }

    Party(ConfigurationPtr &configuration) : config_(configuration) {}

    ~Party() {
      backend_->WaitForConnectionEnd();
      backend_->GetLogger()->LogInfo("ABYN::Party has been deallocated");
    }

    ConfigurationPtr GetConfiguration() { return config_; }

    template<ABYN::Protocol P, typename T = u8, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ABYN::Shares::SharePtr IN(std::size_t party_id, const std::vector<T> &input, std::size_t bits = 0) {
      switch (P) {
        case ABYN::Protocol::ArithmeticGMW: {
          return ArithmeticGMWInput(party_id, input);
        }
        case ABYN::Protocol::BooleanGMW: {
//          return BooleanGMWInput(party_id, input);
        }
        case ABYN::Protocol::BMR: {
          throw (std::runtime_error("BMR protocol is not implemented yet"));
          //TODO
        }
        default: {
          throw (std::runtime_error(fmt::format("Unknown protocol with id {}", static_cast<uint>(P))));
        }
      }
    }

    template<ABYN::Protocol P, typename T = u8, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ABYN::Shares::SharePtr IN(std::size_t party_id, std::vector<T> &&input, std::size_t bits = 0) {
      switch (P) {
        case ABYN::Protocol::ArithmeticGMW: {
          return ArithmeticGMWInput(party_id, std::move(input));
        }
        case ABYN::Protocol::BooleanGMW: {
          //        return BooleanGMWInput(party_id, std::move(input));
        }
        case ABYN::Protocol::BMR: {
          throw (std::runtime_error("BMR input gate is not implemented yet"));
          //TODO
        }
        default: {
          throw (std::runtime_error(fmt::format("Unknown protocol with id {}", static_cast<uint>(P))));
        }
      }
    }

    template<ABYN::Protocol P, typename T = u8, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ABYN::Shares::SharePtr IN(std::size_t party_id, T input, std::size_t bits = 0) {
      if constexpr (std::is_same_v<T, bool>) {
        static_assert(P != ABYN::Protocol::ArithmeticGMW);
        //    return BooleanGMWInput(party_id, input);
      } else {
        return IN<P, T>(party_id, std::vector<T>{input}, bits);
      }
    }

    ABYN::Shares::SharePtr OUT(ABYN::Shares::SharePtr parent, std::size_t output_owner) {
      switch (parent->GetSharingType()) {
        case ABYN::Protocol::ArithmeticGMW: {
          switch (parent->GetBitLength()) {
            case 8u: {
              return ArithmeticGMWOutput<u8>(parent, output_owner);
            }
            case 16u: {
              return ArithmeticGMWOutput<u16>(parent, output_owner);
            }
            case 32u: {
              return ArithmeticGMWOutput<u32>(parent, output_owner);
            }
            case 64u: {
              return ArithmeticGMWOutput<u64>(parent, output_owner);
            }
            default: {
              throw (std::runtime_error(fmt::format("Unknown arithmetic ring of {} bilength", parent->GetBitLength())));
            }
          }
        }
        case ABYN::Protocol::BooleanGMW: {
          throw (std::runtime_error("BooleanGMW output gate is not implemented yet"));
          //return BooleanGMWOutput(parent, output_owner);
        }
        case ABYN::Protocol::BMR: {
          throw (std::runtime_error("BMR output gate is not implemented yet"));
          //TODO
        }
        default: {
          throw (std::runtime_error(fmt::format("Unknown protocol with id {}",
                                                static_cast<uint>(parent->GetSharingType()))));
        }
      }
    }

    ABYN::Shares::SharePtr ADD(const ABYN::Shares::SharePtr &a, const ABYN::Shares::SharePtr &b) {
      assert(a->GetSharingType() == b->GetSharingType());

      switch (a->GetSharingType()) {
        case ABYN::Protocol::ArithmeticGMW: {
          assert(a->GetBitLength() == b->GetBitLength());
          switch (a->GetBitLength()) {
            case 8u: {
              return ArithmeticGMWAddition<u8>(a, b);
            }
            case 16u: {
              return ArithmeticGMWAddition<u16>(a, b);
            }
            case 32u: {
              return ArithmeticGMWAddition<u32>(a, b);
            }
            case 64u: {
              return ArithmeticGMWAddition<u64>(a, b);
            }
            default: {
              throw (std::runtime_error(fmt::format("Unknown arithmetic ring of {} bilength", a->GetBitLength())));
            }
          }
        }
        case ABYN::Protocol::BooleanGMW: {
          throw (std::runtime_error("BooleanGMW addition gate is not implemented yet"));
          //return BooleanGMWOutput(parent, output_owner);
        }
        case ABYN::Protocol::BMR: {
          throw (std::runtime_error("BMR addition gate is not implemented yet"));
          //TODO
        }
        default: {
          throw (std::runtime_error(fmt::format("Unknown protocol with id {}",
                                                static_cast<uint>(a->GetSharingType()))));
        }
      }
    }

    std::size_t GetNumOfParties() { return config_->GetNumOfParties(); }

    void Connect();

    void Run(std::size_t repeats = 1);

    static std::vector<std::unique_ptr<Party>> GetNLocalParties(std::size_t num_parties, u16 port);

    const auto &GetLogger() { return backend_->GetLogger(); }


  private:
    ConfigurationPtr config_;
    BackendPtr backend_;

    //Let's make only ABYNConfiguration be copyable
    Party() = delete;

    Party(Party &party) = delete;

    void EvaluateCircuit();

    void Finish();

    ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id, bool input = false) {
      std::vector<u8> input_vector{input};
      return BooleanGMWInput(party_id, std::move(input_vector), 1);
    };

    //if \param bits is set to 0, the bit-length of the input vector is taken
    ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id, const std::vector<u8> &input,
                                           std::size_t bits = 0) {
      auto in_gate = std::make_shared<Gates::GMW::GMWInputGate>(input, party_id, backend_->GetCore(), bits);
      auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
      backend_->RegisterInputGate(in_gate_cast);
      return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
    };

    //if \param bits is set to 0, the bit-length of the input vector is taken
    ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id, std::vector<u8> &&input, std::size_t bits = 0) {
      auto in_gate = std::make_shared<Gates::GMW::GMWInputGate>(std::move(input), party_id, backend_->GetCore(), bits);
      auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
      backend_->RegisterInputGate(in_gate_cast);
      return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
    };

    //if \param bits is set to 0, the bit-length of the input vector is taken
    ABYN::Shares::SharePtr BooleanGMWInput(
        std::size_t party_id, std::vector<std::vector<u8>> &input, std::size_t bits = 0) {
      auto in_gate = std::make_shared<Gates::GMW::GMWInputGate>(input, party_id, backend_->GetCore(), bits);
      auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
      backend_->RegisterInputGate(in_gate_cast);
      return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsGMWShare());
    };

    //if \param bits is set to 0, the bit-length of the input vector is taken
    ABYN::Shares::SharePtr BooleanGMWInput(
        std::size_t party_id, std::vector<std::vector<u8>> &&input, std::size_t bits = 0) {
      auto in_gate = std::make_shared<ABYN::Gates::GMW::GMWInputGate>(
          std::move(input), party_id, backend_->GetCore(), bits);
      auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
      backend_->RegisterInputGate(in_gate_cast);
      return std::static_pointer_cast<ABYN::Shares::Share>(in_gate->GetOutputAsGMWShare());
    };

    //if \param bits is set to 0, the bit-length of the input vector is taken
    template<typename T>
    ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id, const std::vector<T> &input, std::size_t bits = 0) {
      throw (std::runtime_error("BooleanGMWInput for arbitrary types is not implemented yet"));
    }

    //if \param bits is set to 0, the bit-length of the input vector is taken
    template<typename T>
    ABYN::Shares::SharePtr BooleanGMWInput(std::size_t party_id, std::vector<T> &&input, std::size_t bits = 0) {
      throw (std::runtime_error("BooleanGMWInput for arbitrary types is not implemented yet"));
    }

    //if \param bits is set to 0, the bit-length of the input vector is taken
    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ABYN::Shares::SharePtr ArithmeticGMWInput(std::size_t party_id, T input = 0) {
      std::vector<T> input_vector{input};
      return IN(party_id, std::move(input_vector));
    };

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ABYN::Shares::SharePtr ArithmeticGMWInput(std::size_t party_id, const std::vector<T> &input_vector) {
      auto in_gate = std::make_shared<Gates::Arithmetic::ArithmeticInputGate<T>>(
          input_vector, party_id, backend_->GetCore());
      auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
      backend_->RegisterInputGate(in_gate_cast);
      return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsArithmeticShare());
    }

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ABYN::Shares::SharePtr ArithmeticGMWInput(std::size_t party_id, std::vector<T> &&input_vector) {
      auto in_gate = std::make_shared<Gates::Arithmetic::ArithmeticInputGate<T>>(
          std::move(input_vector), party_id, backend_->GetCore());
      auto in_gate_cast = std::static_pointer_cast<Gates::Interfaces::InputGate>(in_gate);
      backend_->RegisterInputGate(in_gate_cast);
      return std::static_pointer_cast<Shares::Share>(in_gate->GetOutputAsArithmeticShare());
    }

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ABYN::Shares::SharePtr ArithmeticGMWOutput(const ArithmeticSharePtr<T> &parent, std::size_t output_owner) {
      assert(parent);
      auto out_gate = std::make_shared<Gates::Arithmetic::ArithmeticOutputGate<T>>(parent, output_owner);
      auto out_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(out_gate);
      backend_->RegisterGate(out_gate_cast);
      return std::static_pointer_cast<ABYN::Shares::Share>(out_gate->GetOutputAsArithmeticShare());
    }

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ABYN::Shares::SharePtr ArithmeticGMWOutput(const ABYN::Shares::SharePtr &parent, std::size_t output_owner) {
      assert(parent);
      auto casted_parent_ptr = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(parent);
      assert(casted_parent_ptr);
      return ArithmeticGMWOutput(casted_parent_ptr, output_owner);
    }

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ABYN::Shares::SharePtr ArithmeticGMWAddition(const ArithmeticSharePtr<T> &a, const ArithmeticSharePtr<T> &b) {
      assert(a);
      assert(b);
      auto wire_a = a->GetArithmeticWire();
      auto wire_b = b->GetArithmeticWire();
      auto addition_gate = std::make_shared<Gates::Arithmetic::ArithmeticAdditionGate<T>>(wire_a, wire_b);
      auto addition_gate_cast = std::static_pointer_cast<Gates::Interfaces::Gate>(addition_gate);
      backend_->RegisterGate(addition_gate_cast);
      return std::static_pointer_cast<ABYN::Shares::Share>(addition_gate->GetOutputAsArithmeticShare());
    }

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    ABYN::Shares::SharePtr ArithmeticGMWAddition(const ABYN::Shares::SharePtr &a, const ABYN::Shares::SharePtr &b) {
      assert(a);
      assert(b);
      auto casted_parent_a_ptr = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(a);
      auto casted_parent_b_ptr = std::dynamic_pointer_cast<ABYN::Shares::ArithmeticShare<T>>(b);
      assert(casted_parent_a_ptr);
      assert(casted_parent_b_ptr);
      return ArithmeticGMWAddition(casted_parent_a_ptr, casted_parent_b_ptr);
    }
  };

  using PartyPtr = std::unique_ptr<Party>;
}
#endif //ABYNPARTY_H
