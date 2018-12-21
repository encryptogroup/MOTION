#include <iostream>
#include <memory>
#include <vector>

#include "gate.h"

using namespace ABYN::Gates::Interfaces;
using namespace ABYN::Gates::Arithmetic;
using namespace ABYN::Shares;

int main() {

    auto p = ArithmeticInputGate(1u);
    return 0;
}