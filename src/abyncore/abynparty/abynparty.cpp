#include "abynparty.h"

namespace ABYN {

    void ABYNParty::Connect() {
//assign 1 thread for each connection
#pragma omp parallel for num_threads(configuration->GetNumOfParties()) schedule(static, 1) default(shared)
        for (auto i = 0u; i < configuration->GetNumOfParties(); ++i) {
            auto &p = configuration->GetParty(i);

            backend->LogDebug(fmt::format("Trying to connect {}:{}\n", p.GetIp().data(), p.GetPort()));
            auto result = configuration->GetParty(i).Connect();
            backend->LogInfo(std::move(result));
        }
    };

}