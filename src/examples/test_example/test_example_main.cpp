#include <iostream>
#include <memory>

#include <fmt/format.h>

#include "abynparty/abynparty.h"

using namespace ABYN;

int main() {
  auto num_parties = 4u;
  srand(time(NULL));
  size_t input_owner = rand() % num_parties, output_owner = rand() % num_parties, global_input = rand();
  std::cout << fmt::format("Input owner: {}, output owner: {}\n", input_owner, output_owner);
  try {
    std::vector<ABYNPartyPtr> abyn_parties(std::move(ABYNParty::GetNLocalConnectedParties(num_parties, 7777)));
#pragma omp parallel num_threads(10) default(shared)
    {
#pragma omp single
      {
#pragma omp taskloop num_tasks(abyn_parties.size())
        for (auto party_id = 0u; party_id < abyn_parties.size(); ++party_id) {
          auto input = 0u;
          if (party_id == input_owner) {
            input = global_input;
          }
          auto input_share = abyn_parties.at(party_id)->ShareArithmeticInput<u32>(input_owner, input);
          auto output_gate =
              std::make_shared<Gates::Arithmetic::ArithmeticOutputGate<u32>>(input_share, output_owner);
          auto output_share = std::dynamic_pointer_cast<ArithmeticShare<u32>>(output_gate->GetOutputShare());

          abyn_parties.at(party_id)->Run();

          if (party_id == output_owner) {
            auto wire = std::dynamic_pointer_cast<ABYN::Wires::ArithmeticWire<u32>>(
                output_share->GetWires().at(0));
            assert(wire->GetValuesOnWire().at(0) == global_input);
          }
        }
      }
    }
  }
  catch (std::exception &e) {
    std::cerr << e.what() << std::endl;
  }
  return 0;
}