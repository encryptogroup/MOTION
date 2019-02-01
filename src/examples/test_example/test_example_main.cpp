#include <iostream>
#include <memory>

#include "abynparty/abynparty.h"

using namespace ABYN;

int main() {
  try {
    auto p = ABYNPartyPtr(new ABYNParty{{
                                            std::make_shared<Party>("127.0.0.1", 7777u, ABYN::Role::Client, 0),
                                            std::make_shared<Party>("127.0.0.1", 7777u, ABYN::Role::Client, 1),
                                            std::make_shared<Party>("127.0.0.1", 7777u, ABYN::Role::Server, 2)}, 3});
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
  return 0;
}