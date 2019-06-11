#pragma once

namespace ABYN {

namespace Gates::Interfaces {};
namespace Gates::Arithmetic {};
namespace Gates::Boolean {};
namespace Gates::Yao {};
namespace Gates::Conversion {};

// fast-access aliases for Gates
namespace Arithmetic = Gates::Arithmetic;
namespace Boolean = Gates::Boolean;
namespace Conversion = Gates::Conversion;

enum Protocol {
  ArithmeticGMW = 0u,
  BooleanGMW = 1u,
  BMR = 2u,
  InvalidProtocol = 3u  // for checking whether the value is valid
};

enum CircuitType {
  ArithmeticType = 0u,
  BooleanType = 1u,
  InvalidType = 2u  // for checking whether the value is valid
};

enum Role {
  Server = 0u,
  Client = 1u,
  InvalidRole = 2u  // for checking whether the value is valid
};

enum GateType {
  InputGate = 0u,
  InteractiveGate = 1u,
  NonInteractiveGate = 2u,
  InvalidGate = 3u
};

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using MultiplicationTriple = std::tuple<T, T, T>;

template <typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
using MT = MultiplicationTriple<T>;
}  // namespace ABYN