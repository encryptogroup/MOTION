#ifndef TYPEDEFS_H
#define TYPEDEFS_H

#include <inttypes.h>

namespace ABYN {

    using u8 = uint8_t;
    using u16 = uint16_t;
    using u32 = uint32_t;
    using u64 = uint64_t;

    const bool DEBUG = false;
    const bool VERBOSE_DEBUG = false;

    namespace Gates::Arithmetic{};
    namespace Gates::Boolean{};
    namespace Gates::Yao{};
    namespace Gates::Conversion{};

    //fast-access aliases for Gates
    namespace Arithmetic = Gates::Arithmetic;
    namespace Boolean = Gates::Boolean;
    namespace Conversion = Gates::Conversion;

    enum Protocol {
        ArithmeticGMW = 0u,
        BooleanGMW = 1u,
        BMR = 2u,
        InvalidProtocol = 3u
    };

    enum CircuitType {
        ArithmeticType = 0u,
        BooleanType = 1u,
        InvalidType = 2u
    };

    enum Role {
        Server = 0u,
        Client = 1u,
        InvalidRole = 2u
    };

    const auto MAXIMUM_CONNECTION_TIMEOUT = 60;//seconds
}

#endif //TYPEDEFS_H
