#include <map>

#include "abynparty.h"
#include "communication/message.h"
#include "communication/hellomessage.h"

namespace ABYN {

  void ABYNParty::Connect() {
//assign 1 thread for each connection
    auto n = configuration_->GetNumOfParties();
#pragma omp parallel num_threads(n)
    {
#pragma omp single
      {
#pragma omp taskloop num_tasks(n) default(shared)
        for (auto destination_id = 0u; destination_id < n; ++destination_id) {
          if (destination_id == configuration_->GetMyId()) { continue; }
          auto &p = configuration_->GetParty(destination_id);
          backend_->GetLogger()->LogDebug(fmt::format("Trying to connect to {}:{}\n", p->GetIp().data(), p->GetPort()));

          auto result = configuration_->GetParty(destination_id)->Connect();
          backend_->GetLogger()->LogInfo(std::move(result));
        }
        backend_->InitializeCommunicationHandlers();
      }
    }

    SendHelloToOthers();
    //VerifyHelloMessages();
  }

  void ABYNParty::SendHelloToOthers() {
    backend_->GetLogger()->LogInfo("Send hello message to other parties");
    for (auto destination_id = 0u; destination_id < backend_->GetConfig()->GetNumOfParties(); ++destination_id) {
      if (destination_id == configuration_->GetMyId()) { continue; }
      auto hello_message = ABYN::Communication::BuildHelloMessage(backend_->GetConfig()->GetMyId(), destination_id,
                                                                  backend_->GetConfig()->GetNumOfParties());
      backend_->Send(destination_id, hello_message);
    }
  }

  void ABYNParty::VerifyHelloMessages() {
      if(!backend_->VerifyHelloMessages()) {backend_->GetLogger()->LogError("Hello message verification failed");}
  }

  std::vector<std::unique_ptr<ABYNParty>> ABYNParty::GetNLocalConnectedParties(size_t num_parties, u16 port) {
    if (num_parties < 3) {
      throw (std::runtime_error(fmt::format("Can generate only >= 3 local parties, current input: {}", num_parties)));
    }

    std::vector<ABYNPartyPtr> abyn_parties(0);
    std::vector<std::future<ABYNPartyPtr>> futures(0);
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
    for (auto my_id = 0ul; my_id < num_parties; ++my_id) {
      futures.push_back(std::async(std::launch::async,
                                   [num_parties, my_id, &assigned_ports, &portid]() mutable {
                                     std::vector<PartyPtr> parties;
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
                                           std::make_shared<Party>("127.0.0.1", this_port, role, other_id));
                                     }
                                     auto abyn = std::move(std::make_unique<ABYNParty>(parties, my_id));
                                     abyn->Connect();
                                     return std::move(abyn);
                                   }));
    }
    for (auto &f : futures)
      abyn_parties.push_back(f.get());

    return std::move(abyn_parties);
  }

  void ABYNParty::Finish() {
    backend_->TerminateCommunication();
  }
}