/**
 \copyright	ABY - A Framework for Efficient Mixed-protocol Secure Two-party Computation
			Copyright (C) 2015 Engineering Cryptographic Protocols Group, TU Darmstadt
			This program is free software: you can redistribute it and/or modify
			it under the terms of the GNU Affero General Public License as published
			by the Free Software Foundation, either version 3 of the License, or
			(at your option) any later version.
			This program is distributed in the hope that it will be useful,
			but WITHOUT ANY WARRANTY; without even the implied warranty of
			MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
			GNU Affero General Public License for more details.
			You should have received a copy of the GNU Affero General Public License
			along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#pragma once

#include "../../abycore/circuit/booleancircuits.h"
#include "../../abycore/circuit/arithmeticcircuits.h"
#include "../../abycore/circuit/circuit.h"
#include "../../abycore/aby/abyparty.h"


#include <string>


struct Options
{
	// Role played by the program which can be server or client part.
	e_role role = ALL;
	uint32_t nvals = 31;

	// Symmetric Security Bits, default: 128
	uint32_t secparam = 128;

	uint16_t port = 7766;
	std::string ip_address = "127.0.0.1";

	// Default boolean sharing
	e_sharing boolean_sharing = S_YAO;
	std::string spec;
	std::vector<std::string> circuit_files;
	std::string main_circuit;

	bool perform_test = false;
	bool quiet = false;
};

/**
 \param 	seclvl 		Security level
 \param 	nthreads	Number of threads
 \param		mt_alg		The algorithm for generation of multiplication triples
 */
bool test_cbmc_circuit(
	Options const &options,
	seclvl seclvl,
	uint32_t nthreads,
	e_mt_gen_alg mt_alg);


inline std::ifstream open_ifile(std::string const &filename)
{
	std::ifstream file{filename};
	if(!file)
		throw std::runtime_error{"Failed to open file: " + filename};

	return file;
}

