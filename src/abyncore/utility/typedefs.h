#ifndef TYPEDEFS_H
#define TYPEDEFS_H

#include <inttypes.h>

namespace ABYN {

    using u8 = uint8_t;
    using u16 = uint16_t;
    using u32 = uint32_t;
    using u64 = uint64_t;

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

}

#endif //TYPEDEFS_H
