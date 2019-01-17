#include "abynparty.h"

namespace ABYN {

    void ABYNParty::Connect() {
//assign 1 thread for each connection
#pragma omp parallel for num_threads(configuration->GetNumOfParties()) schedule(static, 1) default(shared)
        for (auto i = 0u; i < configuration->GetNumOfParties(); ++i) {
            auto &p = configuration->GetParty(i);

//TODO: pass into logger ( after it is implemented :O )
            std::cout << fmt::format("Trying to connect {}:{}\n", p.GetIp().data(), p.GetPort());
            configuration->GetParty(i).Connect();
        }
    };

}