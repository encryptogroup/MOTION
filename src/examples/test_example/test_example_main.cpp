#include <iostream>
#include <memory>

#include "abynparty/abynparty.h"

using namespace ABYN;

int main() {
    auto p = ABYNPartyPtr(new ABYNParty{Party("127.0.0.1", 7777u), Party("127.0.0.1", 7777u), Party("127.0.0.1", 7777u)});
    return 0;
}