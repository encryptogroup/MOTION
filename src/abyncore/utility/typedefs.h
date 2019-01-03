#ifndef TYPEDEFS_H
#define TYPEDEFS_H

#include <inttypes.h>

namespace ABYN {

    typedef uint64_t u64;
    typedef uint32_t u32;
    typedef uint16_t u16;
    typedef uint8_t u8;

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

    enum ShareType {
        ArithmeticShareType = 0,
        GMWShareType = 1,
        BMRShareType = 2,
        InvalidShareType = 3
    };

    enum Role {
        Server = 0,
        Client = 1,
        InvalidRole = 2
    };
}

#endif //TYPEDEFS_H
