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

#include "ENCRYPTO_utils/crypto/crypto.h"
#include "../../abycore/aby/abyparty.h"

#include "hycc_adapter.h"
#include <libcircuit/logger.h>

#include <libcircuit/utils.h>


Options parse_options(int32_t argc, char** argv)
{
	Options opts;

	for(int i = 1; i < argc; ++i)
	{
		// Role: 0/1
		if(strcmp(argv[i], "-r") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected a role"};

			int role = std::stoi(argv[i]);
			if(role < 0 || role > 1)
				throw std::runtime_error{"Invalid role"};

			opts.role = (e_role)role;
		}
		// Number of parallel operation elements
		else if(strcmp(argv[i], "-n") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected a number"};

			opts.nvals = std::stoi(argv[i]);
		}
		// Symmetric Security Bits, default: 128
		else if(strcmp(argv[i], "-s") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected a number"};

			opts.secparam = std::stoi(argv[i]);
		}
		// IP-address, default: localhost
		else if(strcmp(argv[i], "-a") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected a IP address"};

			opts.ip_address = argv[i];
		}
		// Port, default: 7766
		else if(strcmp(argv[i], "-p") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected a port"};

			opts.port = std::stoi(argv[i]);
		}


		// Port, default: 7766
		else if(strcmp(argv[i], "-q") == 0)
			opts.quiet = true;
		// Specify input values
		else if(strcmp(argv[i], "--spec") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected a string"};

			opts.spec = argv[i];
		}
		// Specify input file
		else if(strcmp(argv[i], "--spec-file") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected a filename"};

			std::ifstream file = open_ifile(argv[i]);
			std::stringstream ss;
			file >> ss.rdbuf();
			opts.spec.append(ss.str());
		}
		// Use the YAO protocol (default)
		else if(strcmp(argv[i], "--yao") == 0)
			opts.boolean_sharing = S_YAO;
		// Use the GMW protocol
		else if(strcmp(argv[i], "--gmw") == 0)
			opts.boolean_sharing = S_BOOL;
		else if(strcmp(argv[i], "--main") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected a string"};

			opts.main_circuit = argv[i];
		}
		// File containing the filenames of the circuits that should be used
		else if(strcmp(argv[i], "-c") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected a filename"};

			std::ifstream file = open_ifile(argv[i]);
			std::string line;
			while(std::getline(file, line))
				opts.circuit_files.push_back(line);
		}
		else if(strcmp(argv[i], "--perform-test") == 0)
			opts.perform_test = true;
		else
			opts.circuit_files.push_back(argv[i]);
	}

	if(opts.role == ALL)
		throw std::runtime_error{"You must specify a role"};

	if(opts.circuit_files.empty())
		throw std::runtime_error{"You must specify at least one circuit file"};

	return opts;
}

int main(int argc, char** argv)
{
	default_logger().add_target<default_log_targett>();

	Options opts = parse_options(argc, argv);
	if(opts.quiet)
		default_logger().level(log_levelt::warning);

	if(opts.boolean_sharing == S_YAO)
		default_logger().info() << "Using YAO protocol for boolean gates" << eom;
	else if(opts.boolean_sharing == S_BOOL)
		default_logger().info() << "Using GMW protocol for boolean gates" << eom;

	return !test_cbmc_circuit(opts, get_sec_lvl(opts.secparam), 1, MT_OT);
}

