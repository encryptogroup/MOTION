#include <iostream>
#include <memory>

#include "abynparty/abynparty.h"

using namespace ABYN;

int main() {
  try {
    auto p = ABYNPartyPtr(new ABYNParty{{
                                            Party("127.0.0.1", 7777u, ABYN::Role::Client, 0),
                                            Party("127.0.0.1", 7777u, ABYN::Role::Client, 1),
                                            Party("127.0.0.1", 7777u, ABYN::Role::Server, 2)}, 3});
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
  return 0;
}