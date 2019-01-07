#ifndef WIRE_H
#define WIRE_H

#include <cstdlib>
#include <string>
#include <vector>

#include "utility/typedefs.h"

namespace ABYN {

    class Wire {
    public:
        size_t GetNumOfParallelValues() { return num_of_parallel_values; }

        virtual WireType GetWireType() = 0;

        Wire() {};

        virtual ~Wire() {};

    protected:
    private:
        size_t num_of_parallel_values = 0;
    };


// Allow only unsigned integers for Arithmetic wires.
    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    class ArithmeticWire : Wire {
    private:
        std::vector<T> values{};
    public:
        ArithmeticWire(T value) {};

        ArithmeticWire(std::initializer_list<T> &values) {
            this->values.emplace_back(values);
        };

        ArithmeticWire(std::vector<T> &values) {
            this->values = std::move(values);
        };

        virtual ~ArithmeticWire() {};

        virtual WireType GetWireType() final { return WireType::ArithmeticWireType; };
    };

    //TODO: implement boolean wires
    class BooleanWire : Wire {
    public:
        virtual WireType GetWireType() final { return WireType::BooleanWireType; };
    };


}

#endif //WIRE_H