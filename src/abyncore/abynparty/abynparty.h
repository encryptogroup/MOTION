#ifndef ABYNPARTY_H
#define ABYNPARTY_H

#include <vector>
#include <memory>

#include "utility/abynconfiguration.h"

namespace ABYN {

    class ABYNParty {
    private:
        std::shared_ptr<ABYNConfiguration> configuration;
    protected:
        ABYNParty() {};
    public:
        ABYNParty(std::vector<Party> &parties) {
            configuration = std::shared_ptr<ABYNConfiguration>(new ABYNConfiguration(parties));
        };

        ABYNParty(std::initializer_list<Party> list_parties){
            configuration = std::shared_ptr<ABYNConfiguration>(new ABYNConfiguration(list_parties));
        }

        ABYNParty(std::shared_ptr<ABYNConfiguration> configuration) { this->configuration = configuration; };

        ~ABYNParty() {};
    };

}
#endif //ABYNPARTY_H
