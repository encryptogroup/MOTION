// MIT License
//
// Copyright (c) 2019 Oleksandr Tkachenko
// Cryptography and Privacy Engineering Group (ENCRYPTO)
// TU Darmstadt, Germany
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "benchmark.h"

#include "algorithm/algorithm_description.h"
#include "base/backend.h"
#include "base/register.h"
#include "share/arithmetic_gmw_share.h"
#include "share/bmr_share.h"
#include "share/boolean_gmw_share.h"
#include "share/share_wrapper.h"
#include "statistics/analysis.h"
#include "statistics/run_time_stats.h"
#include "utility/block.h"
#include "utility/config.h"
#include "wire/arithmetic_gmw_wire.h"
#include "wire/bmr_wire.h"
#include "wire/boolean_gmw_wire.h"

template <typename T>
MOTION::Shares::ShareWrapper DummyArithmeticGMWShare(MOTION::PartyPtr& party, std::size_t bit_size,
                                                     std::size_t num_simd) {
  std::vector<MOTION::Wires::WirePtr> wires(1);
  const std::vector<T> dummy_in(num_simd, 0);

  MOTION::BackendPtr backend{party->GetBackend()};
  MOTION::RegisterPtr reg{backend->GetRegister()};

  wires[0] = std::make_shared<MOTION::Wires::ArithmeticWire<T>>(dummy_in, *backend);
  reg->RegisterNextWire(wires[0]);
  wires[0]->SetOnlineFinished();

  return MOTION::Shares::ShareWrapper(std::make_shared<MOTION::Shares::ArithmeticShare<T>>(wires));
}

MOTION::Shares::ShareWrapper DummyBMRShare(MOTION::PartyPtr& party, std::size_t num_wires,
                                           std::size_t num_simd) {
  std::vector<MOTION::Wires::WirePtr> wires(num_wires);
  const ENCRYPTO::BitVector<> dummy_in(num_simd);

  MOTION::BackendPtr backend{party->GetBackend()};
  MOTION::RegisterPtr reg{backend->GetRegister()};

  for (auto& w : wires) {
    auto bmr_wire{std::make_shared<MOTION::Wires::BMRWire>(dummy_in, *backend)};
    w = bmr_wire;
    reg->RegisterNextWire(bmr_wire);
    bmr_wire->GetMutablePublicKeys() =
        ENCRYPTO::block128_vector::make_zero(backend->GetConfig()->GetNumOfParties() * num_simd);
    bmr_wire->GetMutableSecretKeys() = ENCRYPTO::block128_vector::make_zero(num_simd);
    bmr_wire->GetMutablePermutationBits() = ENCRYPTO::BitVector<>(num_simd);
    bmr_wire->SetSetupIsReady();
    bmr_wire->SetOnlineFinished();
  }

  return MOTION::Shares::ShareWrapper(std::make_shared<MOTION::Shares::BMRShare>(wires));
}

MOTION::Shares::ShareWrapper DummyBooleanGMWShare(MOTION::PartyPtr& party, std::size_t num_wires,
                                                  std::size_t num_simd) {
  std::vector<MOTION::Wires::WirePtr> wires(num_wires);
  const ENCRYPTO::BitVector<> dummy_in(num_simd);

  MOTION::BackendPtr backend{party->GetBackend()};
  MOTION::RegisterPtr reg{backend->GetRegister()};

  for (auto& w : wires) {
    w = std::make_shared<MOTION::Wires::GMWWire>(dummy_in, *backend);
    reg->RegisterNextWire(w);
    w->SetOnlineFinished();
  }

  return MOTION::Shares::ShareWrapper(std::make_shared<MOTION::Shares::GMWShare>(wires));
}

MOTION::Statistics::RunTimeStats EvaluateProtocol(MOTION::PartyPtr& party, std::size_t num_simd,
                                                  std::size_t bit_size,
                                                  MOTION::MPCProtocol protocol,
                                                  ENCRYPTO::PrimitiveOperationType op_type) {
  const std::vector<ENCRYPTO::BitVector<>> tmp_bool(bit_size, ENCRYPTO::BitVector<>(num_simd));

  MOTION::Shares::ShareWrapper a, b;

  switch (protocol) {
    case MOTION::MPCProtocol::BooleanGMW: {
      a = DummyBooleanGMWShare(party, bit_size, num_simd);
      b = DummyBooleanGMWShare(party, bit_size, num_simd);
      break;
    }
    case MOTION::MPCProtocol::BMR: {
      a = DummyBMRShare(party, bit_size, num_simd);
      b = DummyBMRShare(party, bit_size, num_simd);
      break;
    }
    case MOTION::MPCProtocol::ArithmeticGMW: {
      switch (bit_size) {
        case 8u: {
          a = DummyArithmeticGMWShare<std::uint8_t>(party, bit_size, num_simd);
          b = DummyArithmeticGMWShare<std::uint8_t>(party, bit_size, num_simd);
          break;
        }
        case 16u: {
          a = DummyArithmeticGMWShare<std::uint16_t>(party, bit_size, num_simd);
          b = DummyArithmeticGMWShare<std::uint16_t>(party, bit_size, num_simd);
          break;
        }
        case 32u: {
          a = DummyArithmeticGMWShare<std::uint32_t>(party, bit_size, num_simd);
          b = DummyArithmeticGMWShare<std::uint32_t>(party, bit_size, num_simd);
          break;
        }
        case 64u: {
          a = DummyArithmeticGMWShare<std::uint64_t>(party, bit_size, num_simd);
          b = DummyArithmeticGMWShare<std::uint64_t>(party, bit_size, num_simd);
          break;
        }
        default:
          throw std::invalid_argument("Invalid bit size");
      }
      break;
    }
    default:
      throw std::invalid_argument("Invalid MPC protocol");
  }

  switch (op_type) {
    case ENCRYPTO::PrimitiveOperationType::XOR: {
      a ^ b;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::AND: {
      a& b;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::MUX: {
      const std::vector<ENCRYPTO::BitVector<>> tmp_s(1, ENCRYPTO::BitVector<>(num_simd));
      MOTION::Shares::ShareWrapper sel{protocol == MOTION::MPCProtocol::BooleanGMW
                                           ? DummyBooleanGMWShare(party, 1, num_simd)
                                           : DummyBMRShare(party, 1, num_simd)};
      sel.MUX(a, b);
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::INV: {
      ~a;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::OR: {
      a | b;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::ADD: {
      a + b;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::MUL: {
      a* b;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::SQR: {
      a* a;
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::IN: {
      if (protocol == MOTION::MPCProtocol::BooleanGMW)
        a = party->IN<MOTION::MPCProtocol::BooleanGMW>(tmp_bool, 0);
      else if (protocol == MOTION::MPCProtocol::BMR)
        a = party->IN<MOTION::MPCProtocol::BMR>(tmp_bool, 0);
      else if (protocol == MOTION::MPCProtocol::ArithmeticGMW) {
        switch (bit_size) {
          case 8: {
            std::vector<std::uint8_t> tmp_arith(num_simd);
            a = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
            break;
          }
          case 16: {
            std::vector<std::uint16_t> tmp_arith(num_simd);
            a = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
            break;
          }
          case 32: {
            std::vector<std::uint32_t> tmp_arith(num_simd);
            a = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
            break;
          }
          case 64: {
            std::vector<std::uint64_t> tmp_arith(num_simd);
            a = party->IN<MOTION::MPCProtocol::ArithmeticGMW>(tmp_arith, 0);
            break;
          }
          default:
            throw std::invalid_argument("Unknown bit size");
        }
      } else
        throw std::invalid_argument("Unknown protocol");
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::OUT: {
      a.Out();
      break;
    }
    // conversions
    case ENCRYPTO::PrimitiveOperationType::A2B: {
      a.Convert<MOTION::MPCProtocol::BooleanGMW>();
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::A2Y: {
      a.Convert<MOTION::MPCProtocol::BMR>();
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::B2A: {
      a.Convert<MOTION::MPCProtocol::ArithmeticGMW>();
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::B2Y: {
      a.Convert<MOTION::MPCProtocol::BMR>();
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::Y2A: {
      a.Convert<MOTION::MPCProtocol::ArithmeticGMW>();
      break;
    }
    case ENCRYPTO::PrimitiveOperationType::Y2B: {
      a.Convert<MOTION::MPCProtocol::BooleanGMW>();
      break;
    }
    default:
      throw std::invalid_argument("Unknown operation type");
  }

  party->Run();
  party->Finish();
  const auto& stats = party->GetBackend()->GetRunTimeStats();
  return stats.front();
}
