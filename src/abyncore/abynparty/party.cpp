#include "party.h"

#include <map>

namespace ABYN {

  void Party::Connect() {
//assign 1 thread for each connection
    auto n = configuration_->GetNumOfParties();
#pragma omp parallel num_threads(n + 1)
#pragma omp single
    {
#pragma omp taskloop num_tasks(n) default(shared)
      for (auto destination_id = 0u; destination_id < n; ++destination_id) {
        if (destination_id == configuration_->GetMyId()) { continue; }
        auto &p = configuration_->GetCommunicationContext(destination_id);
        backend_->GetLogger()->LogDebug(fmt::format("Trying to connect to {}:{}\n", p->GetIp().data(), p->GetPort()));

        auto result = configuration_->GetCommunicationContext(destination_id)->Connect();
        backend_->GetLogger()->LogInfo(result);
      }
      backend_->InitializeCommunicationHandlers();
    }
    backend_->SendHelloToOthers();
  }

  void Party::Run(size_t repeats) {
    backend_->VerifyHelloMessages();
    for (auto i = 0ull; i < repeats; ++i) { EvaluateCircuit(); };
    Finish();
  }

  void Party::EvaluateCircuit() {
    backend_->EvaluateSequential();
    /*if (configuration_->OnlineAfterSetup()) { backend_->EvaluateSequential(); } //TODO
    else { backend_->EvaluateParallel(); }*/
  }

  void Party::Finish() {
    backend_->TerminateCommunication();
  }

  std::vector<std::unique_ptr<Party>> Party::GetNLocalParties(size_t num_parties, u16 port) {
    if (num_parties < 3) {
      throw (std::runtime_error(fmt::format("Can generate only >= 3 local parties, current input: {}", num_parties)));
    }

    std::vector<PartyPtr> abyn_parties(num_parties);
    //std::vector<std::future<ABYNPartyPtr>> futures(0);
    std::map<u32, u16> assigned_ports;

    //portid generation function - we require symmetric port generation for parties, e.g., parties #4 and #7
    //independent of the position of the ids, i.e., sort them always in ascending order and generate a bigger number
    //out of two ids.
    auto portid = [](u32 my_id, u32 other_id) -> u32 {
      return other_id < my_id ?
             (other_id << 16) + (my_id) :
             (my_id << 16) + (other_id);
    };

    //generate ports sequentially using the map data structure using the offset @param port
    //the generated ports given port=10000 and 4 parties are 10000--10005
    for (auto my_id = 0ul; my_id < num_parties; ++my_id) {
      for (auto other_id = 0ul; other_id < num_parties; ++other_id) {
        if (my_id == other_id) continue;
        u32 port_id = portid(my_id, other_id);
        if (assigned_ports.find(port_id) == assigned_ports.end()) {
          assigned_ports.insert({port_id, port++});
        }
      }
    }

    //generate parties using separate threads
#pragma omp parallel num_threads(num_parties + 1)
#pragma omp single
#pragma omp taskloop num_tasks(num_parties)
    for (auto my_id = 0ul; my_id < num_parties; ++my_id) {
      std::vector<CommunicationContextPtr> parties;
      for (auto other_id = 0ul; other_id < num_parties; ++other_id) {
        if (my_id == other_id) continue;
        ABYN::Role role = other_id < my_id ?
                          ABYN::Role::Client : ABYN::Role::Server;

        u32 port_id = portid(my_id, other_id);

        u16 this_port;
        auto search = assigned_ports.find(port_id);
        if (search != assigned_ports.end()) {
          this_port = search->second;
        } else {
          throw (std::runtime_error(
              fmt::format("Didn't find the port id in the lookup table: {}", port_id)));
        };

        parties.emplace_back(
            std::make_shared<CommunicationContext>("127.0.0.1", this_port, role, other_id));
      }
      abyn_parties.at(my_id) = std::move(std::make_unique<Party>(parties, my_id));
      abyn_parties.at(my_id)->Connect();
    }

    return std::move(abyn_parties);
  }
}