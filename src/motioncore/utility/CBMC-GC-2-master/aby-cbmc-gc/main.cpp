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

#include "../../abycore/util/crypto/crypto.h"
#include "../../abycore/util/parse_options.h"
#include "../../abycore/aby/abyparty.h"

#include "cbmc_adapter.h"


bool read_test_options(int32_t* argcp, char*** argvp, e_role* role,
		uint32_t* bitlen, uint32_t* nvals, uint32_t* secparam, string* address,
		uint16_t* port, int32_t* test_op, string *spec, bool *yao, bool *gmw) {

	uint32_t int_role = 0, int_port = 0;
	bool useffc = false;

	parsing_ctx options[] = {
		{(void*)&int_role, T_NUM, "r", "Role: 0/1", true, false},
		{(void*)nvals, T_NUM, "n", "Number of parallel operation elements", false, false},
		{(void*)bitlen, T_NUM, "b", "Bit-length, default 32", false, false},
		{(void*)secparam, T_NUM, "s", "Symmetric Security Bits, default: 128", false, false},
		{(void*)address, T_STR, "a", "IP-address, default: localhost", false, false},
		{(void*)&int_port, T_NUM, "p", "Port, default: 7766", false, false},
		{(void*)test_op, T_NUM, "t", "Single test (leave out for all operations), default: off", false, false},
		{(void*)spec, T_STR, "-spec", "Specify input values", false, false},
		{(void*)yao, T_FLAG, "-yao", "Use the YAO protocol (default)", false, true},
		{(void*)gmw, T_FLAG, "-gmw", "Use the GMW protocol", false, false},
	};

	if (!parse_options(argcp, argvp, options,
			sizeof(options) / sizeof(parsing_ctx))) {
		print_usage(*argvp[0], options, sizeof(options) / sizeof(parsing_ctx));
		cout << "Exiting" << endl;
		return false;
	}

	if(int_role < 0 || int_role > 1)
	{
		std::cout << "Invalid role\n";
		return false;
	}

	*role = (e_role) int_role;

	if (int_port != 0) {
		assert(int_port < 1 << (sizeof(uint16_t) * 8));
		*port = (uint16_t) int_port;
	}

	//delete options;

	return true;
}

int main(int argc, char** argv) {

	e_role role;
	uint32_t bitlen = 32, nvals = 31, secparam = 128, nthreads = 1;
	uint16_t port = 7766;
	string address = "127.0.0.1";
	int32_t test_op = -1;
	e_mt_gen_alg mt_alg = MT_OT;
	std::string spec;
	bool yao = false, gmw = false;

	if(!read_test_options(&argc, &argv, &role, &bitlen, &nvals, &secparam, &address, &port, &test_op, &spec, &yao, &gmw))
		return 1;

	e_sharing sharing = S_YAO;
	if(gmw)
		sharing = S_BOOL;

	if(sharing == S_YAO)
		std::cout << "Using YAO protocol" << std::endl;
	else if(sharing == S_BOOL)
		std::cout << "Using GMW protocol" << std::endl;

	seclvl seclvl = get_sec_lvl(secparam);
	test_cbmc_circuit(role, (char*) address.c_str(), seclvl, 1, 1, nthreads, mt_alg, sharing, spec);

	return 0;
}

