#ifndef GATE_H
#define GATE_H

#include <iostream>
#include <vector>

#include "share/share.h"
#include "abynparty/abynbackend.h"
#include "utility/typedefs.h"
#include "utility/constants.h"

namespace ABYN::Gates::Interfaces {

//
//  inputs are not defined in the Gate class but in the child classes
//
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one abstract output
//

    class Gate {
    public:
        virtual ~Gate() {};

        virtual void Evaluate() = 0;

        virtual ABYN::Shares::SharePtr &GetOutputShare() = 0;

    protected:
        ABYN::Shares::SharePtr output_share_;
        ABYN::ABYNBackendPtr backend_;
        ssize_t gate_id_ = -1;
        size_t n_parallel_values_ = 1;

        Gate() {};

    private:
        Gate(Gate &) = delete;
    };

    using GatePtr = std::shared_ptr<Gate>;

//
//     | <- one abstract input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one abstract output
//

    class OneGate : public Gate {
    public:
        virtual ~OneGate() {};

        virtual void Evaluate() = 0;

        virtual ABYN::Shares::SharePtr &GetOutputShare() = 0;

    protected:
        ABYN::Shares::SharePtr parent_;

        OneGate() {};

    private:
        OneGate(OneGate &) = delete;

    };


//
//     | <- one abstract (perhaps !SharePointer) input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

    class InputGate : public OneGate {

    public:

        virtual void Evaluate() {
            if constexpr (ABYN::VERBOSE_DEBUG) { backend_->LogTrace("Evaluate InputGate"); }
        }

        virtual ABYN::Shares::SharePtr &GetOutputShare() = 0;

    protected:
        virtual ~InputGate() {};

        InputGate() {};

    private:
        InputGate(InputGate &) = delete;

    };


//
//     | <- one SharePointer input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- abstract output
//

    class OutputGate : public OneGate {
    public:
        OutputGate(ABYN::Shares::SharePtr &parent, ABYN::ABYNBackendPtr &backend) {
            backend_ = backend;
            parent_ = parent;
        };

        virtual void Evaluate() {
            if constexpr (ABYN::VERBOSE_DEBUG) { std::cout << "Evaluate OutputGate" << std::endl; }
        }

        virtual ABYN::Shares::SharePtr &GetOutputShare() = 0;

        virtual ~OutputGate() {};
    };

//
//   |    | <- two SharePointers input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

    class TwoGate : public Gate {

    protected:
        ABYN::Shares::SharePtr parent_a_;
        ABYN::Shares::SharePtr parent_b_;

    public:
        TwoGate(ABYN::Shares::SharePtr &parent_a, ABYN::Shares::SharePtr &parent_b, ABYN::ABYNBackendPtr &backend) {
            if constexpr (ABYN::VERBOSE_DEBUG) { std::cout << "TwoGate constructor" << std::endl; }
            parent_a_ = parent_a;
            parent_b_ = parent_b;
            backend_ = backend;
        };

        virtual ~TwoGate() { if constexpr (ABYN::VERBOSE_DEBUG) { std::cout << "TwoGate destructor" << std::endl; }};

        virtual void Evaluate() {
            if constexpr (ABYN::VERBOSE_DEBUG) { std::cout << "Evaluate TwoGate" << std::endl; }
        }

        virtual ABYN::Shares::SharePtr &GetOutputShare() = 0;
    };


//
//  | |... |  <- n SharePointers input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- SharePointer output
//

    class nInputGate : public Gate {

    protected:
        std::vector<ABYN::Shares::SharePtr> parents;

        nInputGate(std::vector<ABYN::Shares::SharePtr> &parents) {
            if constexpr (ABYN::VERBOSE_DEBUG) { std::cout << "nInputGate constructor" << std::endl; }
            this->parents = parents;
        };

    public:
        virtual ~nInputGate() {
            if constexpr (ABYN::VERBOSE_DEBUG) { std::cout << "nInputGate destructor" << std::endl; }
        };

        virtual void Evaluate() {
            if constexpr (ABYN::VERBOSE_DEBUG) { std::cout << "nInputGate TwoGate" << std::endl; }
        }

        virtual ABYN::Shares::SharePtr &GetOutputShare() = 0;
    };
}

namespace ABYN::Gates::Arithmetic {

//
//     | <- one unsigned integer input
//  --------
//  |      |
//  | Gate |
//  |      |
//  --------
//     | <- one SharePointer(new ArithmeticShare) output
//

//TODO Implement interactive sharing

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    class ArithmeticInputGate : ABYN::Gates::Interfaces::InputGate {

    protected:
        T input_;

        //indicates whether this party shares the input
        bool my_input_ = false;

    public:
        ArithmeticInputGate(T input, bool my_input, ABYN::ABYNBackendPtr &backend) {
            if constexpr (ABYN::VERBOSE_DEBUG) { std::cout << "ArithmeticInputGate constructor" << std::endl; }
            my_input_ = my_input;
            backend_ = backend;
            input_ = input;
        };

        virtual ~ArithmeticInputGate() {
            if constexpr (ABYN::VERBOSE_DEBUG) { std::cout << "ArithmeticInputGate destructor" << std::endl; }
        };

        virtual void Evaluate() final {
            // implement seed extension-based sharing
            output_share_ = std::move(
                    std::static_pointer_cast<ABYN::Shares::Share>(
                            std::make_shared<ABYN::Shares::ArithmeticShare>(input_)));
        };

        //perhaps, we should return a copy of the pointer and not move it for the case we need it multiple times
        virtual ABYN::Shares::SharePtr &GetOutputShare() final { return output_share_; };
    };

    template<typename T, typename = std::enable_if_t<std::is_unsigned_v<T>>>
    class ArithmeticOutputGate : ABYN::Gates::Interfaces::OutputGate {
    protected:
        T output;
        std::vector<T> shares_of_others_parties;

        //indicates whether this party obtains the output
        bool my_output = false;
        bool others_get_output = false;
    public:
        ArithmeticOutputGate(ABYN::Shares::ArithmeticSharePtr<T> &previous_gate, size_t id, ABYNBackendPtr &backend) {
            backend_ = backend;
            // TODO: implement
        }

        virtual ~ArithmeticOutputGate() {
            if constexpr (ABYN::VERBOSE_DEBUG) { std::cout << "ArithmeticOutputGate destructor called" << std::endl; }
        };

        virtual void Evaluate() final {
            //TODO: implement
            ;
        }

        virtual ABYN::Shares::SharePtr &GetOutputShare() final { return output; };
    };
}


#endif //GATE_H
