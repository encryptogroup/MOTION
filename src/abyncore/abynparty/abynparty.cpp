#include "abynparty.h"

#include <map>

namespace ABYN {

  void ABYNParty::Connect() {
//assign 1 thread for each connection
#pragma omp parallel for num_threads(configuration_->GetNumOfParties()) schedule(static, 1) default(shared)
    for (auto i = 0u; i < configuration_->GetNumOfParties(); ++i) {
      auto &&p = configuration_->GetParty(i);
      backend->LogDebug(fmt::format("Trying to connect {}:{}\n", p.GetIp().data(), p.GetPort()));

      auto &&result = configuration_->GetParty(i).Connect();
      backend->LogInfo(std::move(result));
    }
  };

  std::vector<std::unique_ptr<ABYNParty>> ABYNParty::GetNLocalConnectedParties(size_t num_parties, u16 port) {
    if (num_parties < 3) {
      throw (std::runtime_error(fmt::format("Can generate only >= 3 local parties, current input: {}", num_parties)));
    }

    std::vector<ABYNPartyPtr> abyn_parties(0);
    std::vector<std::future<ABYNPartyPtr>> futures(0);
    std::map<u32, u16> assigned_ports;

    auto portid = [](u32 my_id, u32 other_id) -> u32 {
      return other_id < my_id ?
             (other_id << 16) + (my_id) :
             (my_id << 16) + (other_id);
    };

    for (auto my_id = 0ul; my_id < num_parties; ++my_id) {
      for (auto other_id = 0ul; other_id < num_parties; ++other_id) {
        if (my_id == other_id) continue;
        u32 port_id = portid(my_id, other_id);
        if (assigned_ports.find(port_id) == assigned_ports.end()) {
          assigned_ports.insert({port_id, port++});
        }
      }
    }

    for (auto my_id = 0ul; my_id < num_parties; ++my_id) {
      futures.push_back(std::async(std::launch::async,
                                   [num_parties, my_id, &assigned_ports, &portid]() mutable {
                                     std::vector<Party> parties;
                                     for (auto other_id = 0ul; other_id < num_parties; ++other_id) {
                                       if (my_id == other_id) continue;
                                       ABYN::Role role = other_id < my_id ?
                                                         ABYN::Role::Client : ABYN::Role::Server;

                                       /// always use smaller id as the first one to map to a port
                                       u32 port_id = portid(my_id, other_id);

                                       u16 this_port;
                                       auto search = assigned_ports.find(port_id);
                                       if (search != assigned_ports.end()) {
                                         this_port = search->second;
                                       } else {
                                         throw (std::runtime_error(
                                             fmt::format("Didn't find the port id in the lookup table: {}", port_id)));
                                       };

                                       parties.emplace_back("127.0.0.1", this_port, role, 1);
                                     }
                                     auto abyn = std::move(ABYNPartyPtr(new ABYNParty{parties, my_id}));
                                     abyn->Connect();
                                     return std::move(abyn);
                                   }));
    }
    for (auto &f : futures)
      abyn_parties.push_back(f.get());

    return std::move(abyn_parties);
  };

}