#ifndef TYPEDEFS_H
#define TYPEDEFS_H

namespace ABYN {

  using u8 = unsigned char;
  static_assert(sizeof(u8) == 1);
  using u16 = unsigned short int;
  static_assert(sizeof(u16) == 2);
  using u32 = unsigned int;
  static_assert(sizeof(u32) == 4);
  using u64 = unsigned long long int;
  static_assert(sizeof(u64) == 8);


  namespace Gates::Interfaces {};
  namespace Gates::Arithmetic {};
  namespace Gates::Boolean {};
  namespace Gates::Yao {};
  namespace Gates::Conversion {};

  //fast-access aliases for Gates
  namespace Arithmetic = Gates::Arithmetic;
  namespace Boolean = Gates::Boolean;
  namespace Conversion = Gates::Conversion;

  enum Protocol {
    ArithmeticGMW = 0u,
    BooleanGMW = 1u,
    BMR = 2u,
    InvalidProtocol = 3u // for checking whether the value is valid
  };

  enum CircuitType {
    ArithmeticType = 0u,
    BooleanType = 1u,
    InvalidType = 2u // for checking whether the value is valid
  };

  enum Role {
    Server = 0u,
    Client = 1u,
    InvalidRole = 2u // for checking whether the value is valid
  };

  enum GateType {
    InvalidGate = -1,
    InputGate = 0,
    InteractiveGate = 1,
    NonInteractiveGate = 2,
  };


  template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
  using MultiplicationTriple = std::tuple<T, T, T>;

}

#endif //TYPEDEFS_H
