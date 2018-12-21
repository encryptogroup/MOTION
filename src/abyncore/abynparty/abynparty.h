#ifndef ABYNPARTY_H
#define ABYNPARTY_H

#include <vector>
#include "utility/abynconfiguration.h"

namespace ABYN {

    class ABYNParty {
    private:
        std::vector<Party> parties;
    protected:
        ABYNParty() {};
    public:
        ABYNParty(std::vector<Party> &parties) {};

        ~ABYNParty() {};
    };

}
#endif //ABYNPARTY_H
