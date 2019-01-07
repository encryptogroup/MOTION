#ifndef WIRE_H
#define WIRE_H

#include <cstdlib>
#include <string>
#include <vector>
#include <memory>

#include "utility/typedefs.h"

namespace ABYN {

    class Wire {
    public:
        size_t GetNumOfParallelValues() { return num_of_parallel_values; }

        virtual CircuitType GetCircuitType() = 0;

        virtual Protocol GetProtocol() = 0;

        Wire() {};

        virtual ~Wire() {};

    protected:
        // number of values that are _logically_ processed in parallel
        size_t num_of_parallel_values = 0;

        // flagging variables as constants is useful, since this allows for tricks, such as non-interactive
        // multiplication by a constant in (arithmetic) GMW
        bool is_constant = false;

        // is_done_* variables are needed for callbacks, i.e.,
        // gates will wait for wires to be evaluated to proceed with their evaluation
        bool is_done_setup = false;
        bool is_done_online = false;

        ssize_t id = -1;
    };

    using WirePtr = std::shared_ptr<Wire>;


// Allow only unsigned integers for Arithmetic wires.
    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    class ArithmeticWire : Wire {
        bool is_constant = false;
    private:
        std::vector<T> values{};
    public:

        ArithmeticWire(std::initializer_list<T> &values, bool is_constant = false) {
            this->values.emplace_back(values);
            this->is_constant = is_constant;
            num_of_parallel_values = this->values.size();
        };

        ArithmeticWire(std::vector<T> &values, bool is_constant = false) {
            this->values = std::move(values);
            this->is_constant = is_constant;
            num_of_parallel_values = this->values.size();
        };

        ArithmeticWire(T t, bool is_constant = false) {
            values.push_back(t);
            this->is_constant = is_constant;
            num_of_parallel_values = 1;
        }

        virtual ~ArithmeticWire() {};

        virtual CircuitType GetCircuitType() final { return CircuitType::ArithmeticType; };

        std::vector<T> &GetRawValues() { return values; };
    };

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    using ArithmeticWirePtr = std::shared_ptr<ArithmeticWire<T>>;

    //TODO: implement boolean wires
    class BooleanWire : Wire {
    public:
        virtual CircuitType GetCircuitType() final { return CircuitType::BooleanType; };

        virtual ~BooleanWire() {};

        BooleanWire() {};
    };

    class GMWWire : BooleanWire {
    public:
        virtual ~GMWWire() {};

        GMWWire() {};
    };

    class BMRWire : BooleanWire {
    public:
        virtual ~BMRWire() {};

        BMRWire() {};
    };


}

#endif //WIRE_H