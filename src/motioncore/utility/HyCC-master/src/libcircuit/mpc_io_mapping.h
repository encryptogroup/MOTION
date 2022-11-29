/* 
 * File:   mpc_io_mapping.h
 * Author: niklas
 *
 * Created on April 23, 2014, 3:22 PM
 */

#ifndef MPC_IO_MAPPING_H
#define	MPC_IO_MAPPING_H

#include <string>
#include <map>

struct mpc_io_mapping {
    // ToDo: Maybe more information needed?
    ::std::map< ::std::string, ::std::map<unsigned int, unsigned int> > lInputVariableToPortsMap;
    ::std::map< ::std::string, ::std::map<unsigned int, unsigned int> > lOutputVariableToPortsMap;
};

#endif	/* MPC_IO_MAPPING_H */

