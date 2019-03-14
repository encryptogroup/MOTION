#include <iostream>
#include <memory>

#include <fmt/format.h>

#include "abynparty/party.h"

using namespace ABYN;


template<typename T>
void test() {
  auto num_parties = 4u;
  srand(time(NULL));
  size_t input_owner = rand() % num_parties, output_owner = rand() % num_parties;
  std::vector<T> inputs(num_parties);
  for (auto &v : inputs) {
    v = rand();
    if (sizeof(T) == 8) {
      v <<= 4;
      v += rand();
    }
  };
  std::cout << fmt::format("Input owner: {}, output owner: {}\n", input_owner, output_owner);
  try {
    std::vector<PartyPtr> abyn_parties(std::move(Party::GetNLocalParties(num_parties, 7777)));
#pragma omp parallel num_threads(abyn_parties.size() + 1) default(shared)
#pragma omp single
#pragma omp taskloop num_tasks(abyn_parties.size())
    for (auto party_id = 0u; party_id < abyn_parties.size(); ++party_id) {
      std::vector<T> private_inputs(num_parties, 0);
      for (auto j = 0u; j < private_inputs.size(); ++j) { if (party_id == j) { private_inputs.at(j) = inputs.at(j); }}
      auto s_in_0 = abyn_parties.at(party_id)->IN<T>(0, private_inputs.at(0));
      auto s_in_1 = abyn_parties.at(party_id)->IN<T>(1, private_inputs.at(1));
      auto s_in_2 = abyn_parties.at(party_id)->IN<T>(2, private_inputs.at(2));
      auto s_in_3 = abyn_parties.at(party_id)->IN<T>(3, private_inputs.at(3));

      auto added_share = abyn_parties.at(party_id)->ADD(s_in_0, s_in_1); // s_add = s_in_0 + s_in_1
      added_share = abyn_parties.at(party_id)->ADD(added_share, s_in_2); // s_add += s_in_2
      added_share = abyn_parties.at(party_id)->ADD(added_share, s_in_3); // s_add += s_in_3

      auto output_share = abyn_parties.at(party_id)->OUT(added_share, output_owner);

      abyn_parties.at(party_id)->Run();

      if (party_id == output_owner) {
        auto wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<T>>(
            output_share->GetWires().at(0));
        T circuit_result = wire->GetValuesOnWire().at(0);
        T expected_result = inputs.at(0) + inputs.at(1) + inputs.at(2) + inputs.at(3);
        std::cout << "Circuit result : " << unsigned(circuit_result) <<
                  " \t Expected result: " << unsigned(expected_result) << "\n";
        assert(circuit_result == expected_result);
      }
    }
  }
  catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
}

int main() {
  test<u64>();
  test<u32>();
  test<u16>();
  test<u8>();
  return 0;
}
