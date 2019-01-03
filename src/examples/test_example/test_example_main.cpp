#include <iostream>
#include <memory>
#include <vector>

#include "gate/gate.h"
#include "abynparty/abynparty.h"

using namespace ABYN;
using namespace ABYN::Gates::Interfaces;
using namespace ABYN::Gates::Arithmetic;
using namespace ABYN::Shares;

using ABYNPartyPtr = std::unique_ptr<ABYNParty>;

int main() {
    auto p = ABYNPartyPtr(new ABYNParty{Party("127.0.0.1", 7777u), Party("127.0.0.1", 7777u), Party("127.0.0.1", 7777u)});
    return 0;
}