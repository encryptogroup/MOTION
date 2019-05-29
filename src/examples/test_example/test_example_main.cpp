#include <iostream>
#include <memory>

#include <fmt/format.h>

#include "abynparty/party.h"

using namespace ABYN;

void test() {
  auto num_parties = 4u;
  std::srand(time(nullptr));
  std::size_t input_owner = std::rand() % num_parties, output_owner = std::rand() % num_parties;
  std::cout << fmt::format("Input owner: {}, output owner: {}\n", input_owner, output_owner);
  try {
    std::vector<PartyPtr> abyn_parties(std::move(Party::GetNLocalParties(num_parties, 7777)));
    std::vector<std::thread> threads;
    //#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
    //#pragma omp single
    //#pragma omp taskloop num_tasks(abyn_parties.size())
    for (auto &party : abyn_parties) {
      threads.emplace_back([&]() {
        bool in[4] = {true, true, true, false};
        auto s_in_0 = party->IN<Protocol::BooleanGMW>(0, in[0]);
        auto s_in_1 = party->IN<Protocol::BooleanGMW>(1, in[1]);
        auto s_in_2 = party->IN<Protocol::BooleanGMW>(2, in[2]);
        auto s_in_3 = party->IN<Protocol::BooleanGMW>(3, in[3]);

        // auto added_share = abyn_parties.at(party_id)->IN<Protocol::BooleanGMW>(s_in_0, s_in_1);
        // // s_add = s_in_0 + s_in_1 added_share = abyn_parties.at(party_id)->ADD(added_share,
        // s_in_2);
        // // s_add += s_in_2 added_share = abyn_parties.at(party_id)->ADD(added_share, s_in_3); //
        // s_add += s_in_3

        // auto output_share = abyn_parties.at(party_id)->OUT(added_share, output_owner);

        party->Run();

        /* if (party_id == output_owner) {
           auto wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
               output_share->GetWires().at(0));
           T circuit_result = wire->GetValuesOnWire().at(0);
           T expected_result = inputs.at(0) + inputs.at(1) + inputs.at(2) + inputs.at(3);
           std::cout << "Circuit result : " << unsigned(circuit_result) <<
                     " \t Expected result: " << unsigned(expected_result) << "\n";
           assert(circuit_result == expected_result);
         }*/
      });
    }
    for (auto &t : threads) {
      t.join();
    }
  } catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
}

int main() {
  test();
  return 0;
}
