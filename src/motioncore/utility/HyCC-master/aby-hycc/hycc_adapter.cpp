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

#include <libcircuit/simple_circuit.h>
#include <libcircuit/simulation.h>

#include "hycc_adapter.h"
#include "circuit_converter.h"


//==================================================================================================
RawValue get_output_from_aby(ABYOutputVariable const &var, Circuit *circ)
{
	std::vector<bool> bit_vals;
	for(auto pair: var.ids)
	{
		UGATE_T value = *circ->GetOutputGateValue(pair.id);
		for(int i = 0; i < pair.width; ++i)
			bit_vals.push_back((value >> i) & 1);
	}

	return bits_to_raw_value(bit_vals);
}

// Copies the output of the ABY circuit into our context.
void update_ctx(EvaluationContext &ctx, simple_circuitt &cbmc, Circuit *circ, ABYOutputMap const &outputs)
{
	for(auto const *output_var: cbmc.ordered_outputs())
	{
		RawValue new_value = get_output_from_aby(outputs.at(output_var->name), circ);
		auto &opt_cur_value = ctx.get(output_var->name);
		if(opt_cur_value)
			assign(*opt_cur_value, std::move(new_value));
		else
			opt_cur_value = TypedValue{output_var->type, new_value};
	}
}

std::vector<Spec> create_specs(simple_circuitt const &c, std::string const &spec)
{
	SymbolTable table;
	for(auto *input: c.ordered_inputs())
		table[input->name] = {Type{input->type}, SymbolEntry::input};

	for(auto *output: c.ordered_outputs())
		table[output->name] = {Type{output->type}, SymbolEntry::output};

	std::vector<Spec> specs;

	ParseState parser{spec.c_str(), "<command-line-spec>"};
	auto inline_specs = parse_spec_list(parser, table);

	for(auto &s: inline_specs)
		specs.push_back(std::move(s));

	return specs;
}

EvaluationContext create_context(simple_circuitt const &circuit, std::string const &spec)
{
	auto specs = create_specs(circuit, spec);

	EvaluationContext ctx;
	if(specs.size())
	{
		auto &spec = specs[0];
		for(auto &stmt: spec.before)
			stmt->evaluate(ctx);
	}

	return ctx;
}

std::unordered_map<gatet*, uint64_t> create_input_value_mapping(
	EvaluationContext &ctx,
	simple_circuitt const &circuit,
	variable_ownert own_party,
	bool require_inputs_both_parties,
	loggert &logger)
{
	// Set inputs
	std::unordered_map<gatet*, uint64_t> input_values;
	for(auto const *input_var: circuit.ordered_inputs())
	{
		auto &opt_value = ctx.get(input_var->name);
		if(opt_value)
		{
			if(input_var->owner != own_party)
			{
				if(!require_inputs_both_parties)
				{
					logger.debug()
						<< "Warning: " << input_var->name << " belongs to the other party. "
						<< "Setting it will have no effect." << eom;
				}
			}
		}
		else
		{
			if(require_inputs_both_parties)
				throw std::runtime_error{input_var->name + " is not initialized"};

			// By default, unitinialized variables are set to zero.
			opt_value = TypedValue{input_var->type};
		}

		// Get value for each input gate
		int offset = 0;
		for(auto *in: input_var->gates)
		{
			assert(in->get_width() <= 64);
			input_values[in] = get_bits(*opt_value, offset, in->get_width());
			offset += in->get_width();
		}
	}

	return input_values;
}


void print_result(
	EvaluationContext &ctx,
	simple_circuitt const &circuit,
	variable_ownert own_party)
{
	// Print inputs
	for(auto *input_var: circuit.ordered_inputs())
	{
		if(input_var->owner == own_party)
		{
			auto const &val = ctx.get(input_var->name);
			std::cout << input_var->name << " : " << val->type << " = " << *val << std::endl;
		}
	}

	// Print outputs
	for(auto *output_var: circuit.ordered_outputs())
	{
		auto const &val = ctx.get(output_var->name);
		std::cout << output_var->name << " : " << val->type << " = " << *val << std::endl;
	}
}


//==================================================================================================
std::pair<cstring_ref, e_sharing> split_filename_kind_deprecated(std::string const &str)
{
	e_sharing kind = e_sharing::S_LAST;

	size_t last_colon = str.rfind(':');
	if(last_colon == std::string::npos || last_colon + 1 == str.length())
		return {str, kind};

	cstring_ref kind_str{str.data() + last_colon + 1, str.data() + str.length()};
	kind_str = trim(kind_str);
	if(!isalpha(kind_str))
		return {str, kind};

	if(kind_str == "yao")
		kind = e_sharing::S_YAO;
	else if(kind_str == "gmw")
		kind = e_sharing::S_BOOL;
	else
		throw std::runtime_error{"Invalid circuit kind: " + ::str(kind_str)};

	auto filename = trim(cstring_ref{str.data(), str.data() + last_colon});
	return {filename, kind};
}

std::pair<cstring_ref, e_sharing> split_filename_kind(std::string const &str)
{
	e_sharing kind = e_sharing::S_LAST;

	size_t at_sign = str.rfind('@');
	if (at_sign == std::string::npos || at_sign + 1 == str.length())
	{
		return {str, kind};
	}

	cstring_ref kind_str{str.data() + at_sign + 1, str.data() + str.length()};
	kind_str = trim(kind_str);

	if (kind_str == "bool_size.circ")
		kind = e_sharing::S_YAO;
	else if (kind_str == "bool_depth.circ")
		kind = e_sharing::S_BOOL;
	else if (kind_str == "arith.circ")
		kind = e_sharing::S_ARITH;
	else
		throw std::runtime_error{"Invalid circuit kind: " + ::str(kind_str)};

	return {str, kind};
}

void update_sharing_kind(simple_circuitt  &circuit, e_sharing boolean_sharing)
{
	set_sharing(&circuit.get_one_gate(), boolean_sharing);
	set_sharing(&circuit.get_zero_gate(), boolean_sharing);

	for(auto &gate: circuit.gates())
	{
		if(gate.get_operation() == simple_circuitt::SPLIT || is_boolean_op(gate.get_operation()))
			set_sharing(&gate, boolean_sharing);
	}

	for(auto &input: circuit.inputs())
	{
		// Assume that single bit inputs are boolean
		if(input.get_width() == 1)
			set_sharing(&input, boolean_sharing);
		else
			set_sharing(&input, e_sharing::S_ARITH);
	}

	for(auto &output: circuit.outputs())
	{
		// Assume that single bit outputs are boolean
		if(output.get_width() == 1)
			set_sharing(&output, boolean_sharing);
		else
			set_sharing(&output, e_sharing::S_ARITH);
	}
}

std::unordered_map<std::string, simple_circuitt> load_circuits(
	std::vector<std::string> const &circuit_files,
	e_sharing default_boolean_sharing,
	loggert &logger)
{
	std::unordered_map<std::string, simple_circuitt> circuits;
	for(auto const &filename_kind: circuit_files)
	{
		// Extract filename and the boolean sharing kind (either YAO or GMW)
		cstring_ref filename;
		e_sharing boolean_sharing;
		std::tie(filename, boolean_sharing) = split_filename_kind(filename_kind);
		if(boolean_sharing == e_sharing::S_LAST)
			boolean_sharing = default_boolean_sharing;

		logger.info() << "Loading " << filename << " (using " << cstr(boolean_sharing) << " for boolean gates)" << eom;
		simple_circuitt cbmc_circ{logger, ""};
		std::ifstream circ_file = open_ifile(str(filename));
		cbmc_circ.read(circ_file);

		update_sharing_kind(cbmc_circ, boolean_sharing);

		auto name = cbmc_circ.name();
		circuits.emplace(name, std::move(cbmc_circ));
	}

	assert(circuits.size());
	return circuits;
}


void update_arith_bit_width(int &cur_width, int new_width)
{
	if(new_width > 1)
	{
		if(cur_width == 0)
			cur_width = new_width;

		if(cur_width != new_width)
		{
			throw std::runtime_error{
				"Different bit widths in arithmetic circuit: " + std::to_string(cur_width) +
					" vs " + std::to_string(new_width)
			};
		}
	}
}

int compute_arith_bit_width(std::unordered_map<std::string, simple_circuitt> const &circuits)
{
	// The bit-width of gates used in arithmetic circuits
	int arith_bit_width = 0;

	for(auto const &pair: circuits)
	{
		simple_circuitt const &circuit = pair.second;

		if(circuit.get_number_of_gates())
			update_arith_bit_width(arith_bit_width, circuit.gates().b->get_width());
	}

	if(arith_bit_width != 0 && arith_bit_width != 8 && arith_bit_width != 16 &&
	   arith_bit_width != 32 && arith_bit_width != 64)
		throw std::runtime_error{"Invalid arithmetic bit width: " + std::to_string(arith_bit_width)};

	return arith_bit_width;
}


//==================================================================================================
uint64_t clear_unused_bits(uint64_t value, int width)
{
	assert(width <= 64);

	if(width == 64)
		return value;

	uint64_t mask = (1ull << width) - 1;
	return value & mask;
}

using GateValueMap = std::unordered_map<wire_endpointt, uint64_t, wire_endpoint_hasht>;

// TODO Take circuit by const-reference
GateValueMap simulate(simple_circuitt &circuit, std::unordered_map<gatet*, uint64_t> const &input_values)
{
	GateValueMap gate_values;

	circuit.topological_traversal([&](simple_circuitt::gatet *gate)
	{
		switch(gate->get_operation())
		{
			case simple_circuitt::NOT:
			{
				gate_values[primary_output(gate)] = !gate_values.at(gate->fanin_range()[0]);
			} break;

			case simple_circuitt::AND:
			{
				uint64_t fanin0 = gate_values.at(gate->fanin_range()[0]);
				uint64_t fanin1 = gate_values.at(gate->fanin_range()[1]);
				gate_values[primary_output(gate)] = fanin0 & fanin1;
			} break;

			case simple_circuitt::OR:
			{
				uint64_t fanin0 = gate_values.at(gate->fanin_range()[0]);
				uint64_t fanin1 = gate_values.at(gate->fanin_range()[1]);
				gate_values[primary_output(gate)] = fanin0 | fanin1;
			} break;

			case simple_circuitt::XOR:
			{
				uint64_t fanin0 = gate_values.at(gate->fanin_range()[0]);
				uint64_t fanin1 = gate_values.at(gate->fanin_range()[1]);
				gate_values[primary_output(gate)] = fanin0 ^ fanin1;
			} break;

			case simple_circuitt::NEG:
			{
				uint64_t fanin = gate_values.at(gate->fanin_range()[0]);
				gate_values[primary_output(gate)] = clear_unused_bits(-fanin, gate->get_width());
			} break;

			case simple_circuitt::ADD:
			{
				uint64_t fanin0 = gate_values.at(gate->fanin_range()[0]);
				uint64_t fanin1 = gate_values.at(gate->fanin_range()[1]);
				gate_values[primary_output(gate)] = clear_unused_bits(fanin0 + fanin1, gate->get_width());
			} break;

			case simple_circuitt::SUB:
			{
				uint64_t fanin0 = gate_values.at(gate->fanin_range()[0]);
				uint64_t fanin1 = gate_values.at(gate->fanin_range()[1]);
				gate_values[primary_output(gate)] = clear_unused_bits(fanin0 - fanin1, gate->get_width());
			} break;

			case simple_circuitt::MUL:
			{
				uint64_t fanin0 = gate_values.at(gate->fanin_range()[0]);
				uint64_t fanin1 = gate_values.at(gate->fanin_range()[1]);
				gate_values[primary_output(gate)] = clear_unused_bits(fanin0 * fanin1, gate->get_width());
			} break;

			case simple_circuitt::COMBINE:
			{
				uint64_t value = 0;
				auto const &fanins = gate->fanin_range();
				for(size_t i = 0; i < fanins.size(); ++i)
					value |= gate_values.at(fanins[i]) << i;

				gate_values[primary_output(gate)] = value;
			} break;

			case simple_circuitt::SPLIT:
			{
				wire_endpointt fanin = gate->fanin_range()[0];
				uint64_t value = gate_values.at(fanin);
				for(int i = 0; i < fanin.gate->get_width(); ++i)
					gate_values[wire_endpointt(gate, i)] = (value >> i) & 1;
			} break;

			case simple_circuitt::ONE:
			{
				gate_values[primary_output(gate)] = 1;
			} break;

			case simple_circuitt::CONST:
			{
				gate_values[primary_output(gate)] = gate->get_value();
			} break;

			case simple_circuitt::INPUT:
			{
				gate_values[primary_output(gate)] = input_values.at(gate);
			} break;

			case simple_circuitt::OUTPUT:
			{
				gate_values[{gate, 0}] = gate_values.at(gate->fanin_range()[0]);
			} break;

			case simple_circuitt::LUT:
				throw std::runtime_error{"LUTs are not supported"};
		}
	});

	return gate_values;
}

void add_bits(std::vector<uint8_t> raw_value, uint64_t new_value, int width)
{
	assert(width <= 64);
	assert(width % 8 == 0);

	int num_bytes = (width + 7) / 8;
	for(int i = 0; i < num_bytes; ++i)
	{
		uint8_t cur_byte = new_value >> (i * 8);
		raw_value.push_back(cur_byte);
	}
}

std::unordered_map<std::string, TypedValue> extract_simulation_outputs(
	GateValueMap const &gate_values,
	simple_circuitt const &circuit)
{
	std::unordered_map<std::string, TypedValue> result;

	for(auto *output_var: circuit.ordered_outputs())
	{
		TypedValue value{output_var->type};
		int bit_offset = 0;
		for(auto *gate: output_var->gates)
		{
			set_bits(value.value, gate_values.at({gate, 0}), bit_offset, gate->get_width());
			bit_offset += gate->get_width();
		}

		result[output_var->name] = std::move(value);
	}

	return result;
}

bool validate_result(
	EvaluationContext const &aby_result,
	simple_circuitt &circuit,
	std::unordered_map<gatet*, uint64_t> const &input_values,
	loggert &logger)
{
	auto gate_values = simulate(circuit, input_values);
	auto expected_outputs = extract_simulation_outputs(gate_values, circuit);
	
	bool success = true;
	for(auto const &pair: expected_outputs)
	{
		optional<TypedValue> const &aby_value = aby_result.get(pair.first);
		if(aby_value)
		{
			if(*aby_value != pair.second)
			{
				logger.error() << "Wrong value for: " << pair.first << eom;
				logger.error() << "    EXPECTED: " << pair.second << eom;
				logger.error() << "    ABY:      " << *aby_value << eom;
				success = false;
			}
		}
		else
		{
			logger.error() << "Missing value for: " << pair.first << eom;
			success = false;
		}
	}

	if(success)
		logger.info() << "Test successful" << eom;
	else
		logger.error() << "Test failed" << eom;

	return success;
}


//==================================================================================================
bool test_cbmc_circuit(Options const &options, seclvl seclvl, uint32_t nthreads, e_mt_gen_alg mt_alg)
{
	variable_ownert own_party = options.role == CLIENT ? variable_ownert::input_alice : variable_ownert::input_bob;

	// Read circuits
	std::unordered_map<std::string, simple_circuitt> cbmc_circuits = load_circuits(
		options.circuit_files,
		options.boolean_sharing,
		default_logger()
	);
	int arith_bit_width = compute_arith_bit_width(cbmc_circuits);

	// Find the main circuit
	// 1. If the user explicitly specified a main circuit, then use it
	// 2. If not, and we only have a single circuit, then use that one as the main circuit
	// 3. Otherwise, use a circuit with the name "mpc_main"
	std::string main_name = options.main_circuit;
	if(main_name.empty())
	{
		if(cbmc_circuits.size() == 1)
			main_name = cbmc_circuits.begin()->first;
		else
			main_name = "mpc_main";
	}

	auto it = cbmc_circuits.find(main_name);
	if(it == cbmc_circuits.end())
		throw std::runtime_error{"Couldn't find main circuit \"" + main_name + "\""};

	simple_circuitt &main_circuit = it->second;
	main_circuit.link(cbmc_circuits);
	replace_input_combiners(main_circuit, default_logger());

	if(arith_bit_width != 0)
		default_logger().info() << "Arithmetic bit-width: " << arith_bit_width << "bit" << eom;


	EvaluationContext ctx = create_context(main_circuit, options.spec);
	std::unordered_map<gatet*, uint64_t> input_values = create_input_value_mapping(
		ctx,
		main_circuit,
		own_party,
		options.perform_test,
		default_logger()
	);


	// Create the ABYParty object which defines the basis of all the operations which are happening.
	// Operations performed are on the basis of the role played by this object.
	ABYParty* party = new ABYParty(
		options.role,
		(char*)options.ip_address.c_str(),
		options.port,
		seclvl,
		arith_bit_width,
		nthreads,
		mt_alg
	);


	std::vector<Sharing*>& sharings = party->GetSharings();

	BooleanCircuit *aby_yao = dynamic_cast<BooleanCircuit*>(sharings.at(e_sharing::S_YAO)->GetCircuitBuildRoutine());
	BooleanCircuit *aby_bool = dynamic_cast<BooleanCircuit*>(sharings.at(e_sharing::S_BOOL)->GetCircuitBuildRoutine());
	ArithmeticCircuit *aby_arith = dynamic_cast<ArithmeticCircuit*>(sharings.at(e_sharing::S_ARITH)->GetCircuitBuildRoutine());


	/*uint32_t in1_yao = aby_yao->PutINGate(1, e_role::CLIENT);
	uint32_t in2_yao = aby_yao->PutINGate(0, e_role::SERVER);
	uint32_t and_yao = aby_yao->PutANDGate(in1_yao, in2_yao);
	uint32_t and_gmw = aby_bool->PutY2BCONVGate(and_yao);
	aby_bool->PutOUTGate(and_gmw, ALL);

	party->ExecCircuit();*/


	// Convert the CBMC circuit to an ABY circuit
	CircuitConverter cc{&main_circuit, input_values, party};
	main_circuit.topological_traversal(cc);

	party->ExecCircuit();

	// It doesn't matter which circuit we pass to update_ctx() because they all
	// work on the same ABYCircuit
	update_ctx(ctx, main_circuit, cc.boolean_circuit(S_YAO), cc.create_output_map());

	print_result(ctx, main_circuit, own_party);

	if(options.perform_test)
		return validate_result(ctx, main_circuit, input_values, default_logger());

	return true;
}

