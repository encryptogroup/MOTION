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

#include <circuit-utils/circuit.hpp>

#include "cbmc_adapter.h"


// CircuitConverter
//==================================================================================================
// Returns the two inputs of the element `id`. Throws if the number of inputs to `id` is not two.
std::pair<circ::ElementID, circ::ElementID> get_two_inputs(circ::Circuit &circ, circ::ElementID id)
{
	auto input_wires = circ.wires.equal_range(id);
	auto num = std::distance(input_wires.first, input_wires.second);
	if(num != 2)
		throw std::runtime_error{"Invalid number of inputs: " + std::to_string(num)};

	auto input_a = *input_wires.first++;
	auto input_b = *input_wires.first;

	return {input_a.second, input_b.second};
}

// Returns the input of the element `id`. Throws if the number of inputs to `id` is not one.
circ::ElementID get_one_input(circ::Circuit &circ, circ::ElementID id)
{
	auto input_wires = circ.wires.equal_range(id);
	auto num = std::distance(input_wires.first, input_wires.second);
	if(num != 1)
		throw std::runtime_error{"Invalid number of inputs: " + std::to_string(num)};

	return input_wires.first->second;
}

e_role cbmc_party_to_aby_role(circ::Party p)
{
	return p == circ::Party::alice ? CLIENT : SERVER;
}

struct ABYOutputVariable
{
	std::string name;
	std::vector<uint32_t> ids;
};

using ABYOutputMap = std::unordered_map<std::string, ABYOutputVariable>;

class CircuitConverter
{
public:
	CircuitConverter(circ::Circuit *cbmc, BooleanCircuit *aby) :
		m_cbmc{cbmc},
		m_aby{aby} 
	{}

	// Converts a single element (gate, constant, input, output).
	void operator () (circ::ElementID id)
	{
		assert(m_cbmc_to_aby.find(id) == m_cbmc_to_aby.end());

		switch(id.kind())
		{
			case circ::ElementID::Kind::gate:
			{
				circ::Gate gate = m_cbmc->get_gate(circ::GateID{id.id()});
				add_gate(gate);
			} break;
			case circ::ElementID::Kind::constant:
			{
				int val = m_cbmc->get_constant(circ::ConstantID{id.id()});
				m_cbmc_to_aby[id] = m_aby->PutConstantGate((uint32_t)val, 1);
			} break;
			case circ::ElementID::Kind::input:
			{
				auto input = m_cbmc->get_input(circ::InputID{id.id()});
				m_cbmc_to_aby[id] = m_aby->PutINGate((uint8_t)input.value, cbmc_party_to_aby_role(input.party));
				m_num_inputs_converted++;
			} break;
			case circ::ElementID::Kind::output:
			{
				auto input = get_one_input(*m_cbmc, id);
				m_cbmc_to_aby[id] = m_aby->PutOUTGate(m_cbmc_to_aby.at(input), ALL);
				m_num_outputs_converted++;
			} break;
		}
	}

	size_t get_num_and_gates_converted() const { return m_num_and_gates_converted; }
	size_t get_num_xor_gates_converted() const { return m_num_xor_gates_converted; }
	size_t get_num_not_gates_converted() const { return m_num_not_gates_converted; }
	size_t get_num_inputs_converted() const { return m_num_inputs_converted; }
	size_t get_num_outputs_converted() const { return m_num_outputs_converted; }

	ABYOutputMap create_output_map() const
	{
		ABYOutputMap map;
		for(auto const &pair: m_cbmc->name_to_outputs)
		{
			ABYOutputVariable ov;
			ov.name = pair.first;

			for(auto id: pair.second.outputs)
				ov.ids.push_back(m_cbmc_to_aby.at(id));

			map[ov.name] = ov;
		}

		return map;
	}

private:
	circ::Circuit *m_cbmc;
	BooleanCircuit *m_aby;
	std::unordered_map<circ::ElementID, uint32_t> m_cbmc_to_aby;

	size_t m_num_and_gates_converted = 0;
	size_t m_num_xor_gates_converted = 0;
	size_t m_num_not_gates_converted = 0;
	size_t m_num_inputs_converted = 0;
	size_t m_num_outputs_converted = 0;

	void add_gate(circ::Gate const &gate)
	{
		if(gate.kind == circ::GateKind::not_gate)
		{
			auto input = get_one_input(*m_cbmc, gate.id);
			m_cbmc_to_aby[gate.id] = m_aby->PutINVGate(m_cbmc_to_aby.at(input));
			m_num_not_gates_converted++;
		}
		else
		{
			auto inputs = get_two_inputs(*m_cbmc, gate.id);
			uint32_t aby_input_a = m_cbmc_to_aby.at(inputs.first);
			uint32_t aby_input_b = m_cbmc_to_aby.at(inputs.second);

			if(gate.kind == circ::GateKind::and_gate)
			{
				m_cbmc_to_aby[gate.id] = m_aby->PutANDGate(aby_input_a, aby_input_b);
				m_num_and_gates_converted++;
			}
			else if(gate.kind == circ::GateKind::xor_gate)
			{
				m_cbmc_to_aby[gate.id] = m_aby->PutXORGate(aby_input_a, aby_input_b);
				m_num_xor_gates_converted++;
			}
			else if(gate.kind == circ::GateKind::or_gate)
			{
				// ABY has no direct support for OR, replace 'a OR b' with '(a AND b) XOR (a XOR b)'
				uint32_t left = m_aby->PutANDGate(aby_input_a, aby_input_b);
				uint32_t right = m_aby->PutXORGate(aby_input_a, aby_input_b);

				m_cbmc_to_aby[gate.id] = m_aby->PutXORGate(left, right);
			}
			else
				assert(0 && "This is impossible");
		}
	}
};


//==================================================================================================
circ::RawValue get_output_from_aby(ABYOutputVariable const &var, circ::Type const &type, Circuit *circ)
{
	std::vector<bool> bit_vals;
	for(auto id: var.ids)
		bit_vals.push_back(*circ->GetOutputGateValue(id));

	return circ::bits_to_raw_value(bit_vals, type);
}

// Writes the output of the ABY circuit into our context.
void update_ctx(circ::Context &ctx, circ::Circuit const &cbmc, Circuit *circ, ABYOutputMap const &outputs)
{
	for(auto const &output_entry: cbmc.name_to_outputs)
	{
		circ::OutputVariable const &output_var = output_entry.second;
		circ::RawValue new_value = get_output_from_aby(outputs.at(output_var.name), output_var.type, circ);
		auto &opt_cur_value = ctx.get(output_var.name);
		if(opt_cur_value)
			assign(*opt_cur_value, std::move(new_value));
		else
			opt_cur_value = circ::TypedValue{output_var.type, new_value};
	}
}

std::vector<circ::Spec> create_specs(circ::Circuit const &c, std::string const &spec)
{
	circ::SymbolTable table = circ::create_symbol_table(c);
	std::vector<circ::Spec> specs;

	circ::ParseState parser{spec.c_str(), "<command-line-spec>"};
	auto inline_specs = circ::parse_spec_list(parser, table);

	for(auto &s: inline_specs)
		specs.push_back(std::move(s));

	return specs;
}


int32_t test_cbmc_circuit(e_role role, char* address, seclvl seclvl,
		uint32_t nvals, uint32_t bitlen, uint32_t nthreads, e_mt_gen_alg mt_alg,
		e_sharing sharing, std::string const &specs_string) {


	circ::Party cbmc_party = role == CLIENT ? circ::Party::alice : circ::Party::bob;

	/**
		Step 1: Create the ABYParty object which defines the basis of all the
		 	 	operations which are happening.	Operations performed are on the
		 	 	basis of the role played by this object.
	*/
	ABYParty* party = new ABYParty(role, address, seclvl, bitlen, nthreads, mt_alg);

	/**
		Step 2: Get to know all the sharing types available in the program.
	*/
	vector<Sharing*>& sharings = party->GetSharings();

	/**
		Step 3: Create the circuit object on the basis of the sharing type
				being inputed.
	*/
	Circuit* aby_circ = sharings[sharing]->GetCircuitBuildRoutine();


	// Read CBMC circuit from output.*.txt files
	circ::Circuit cbmc_circ = circ::read_circuit(".");
	circ::validate(cbmc_circ);

	auto specs = create_specs(cbmc_circ, specs_string);

	circ::Context ctx;
	if(specs.size())
	{
		auto &spec = specs[0];
		for(auto &stmt: spec.before)
			stmt->evaluate(ctx);
	}

	// Set inputs
	for(auto const &input: cbmc_circ.name_to_inputs)
	{
		auto const &var_name = input.first;
		auto &opt_value = ctx.get(var_name);
		if(opt_value)
		{
			if(cbmc_circ.get_input_variable_party(var_name) == cbmc_party)
				cbmc_circ.set_input_value(var_name, *opt_value);
			else
				std::cout << "Warning: " << var_name << " belongs to the other party. Setting it will have no effect.\n";
		}
		else
			// By default, unitinialized variables are set to zero.
			opt_value = circ::TypedValue{input.second.type};
	}

	// Convert the CBMC circuit to an ABY circuit
	CircuitConverter cc{&cbmc_circ, (BooleanCircuit*)aby_circ};
	circ::topological_traversal(cbmc_circ, cc);
	auto aby_output_vars = cc.create_output_map();

	party->ExecCircuit();

	// Couldn't get party->GetMyInput() and party->GetOtherInput() to work. Would be nice for
	// checking the output.

	update_ctx(ctx, cbmc_circ, aby_circ, aby_output_vars);

	// Print input/output values.
	std::cout << '\n';
	for(auto &input_entry: cbmc_circ.name_to_inputs)
	{
		auto &name = input_entry.first;
		if(cbmc_circ.get_input_variable_party(name) == cbmc_party)
		{
			auto const &val = ctx.get(name);
			std::cout << name << " : " << val->type << " = " << *val << '\n';
		}
	}
	for(auto &output_entry: cbmc_circ.name_to_outputs)
	{
		auto &name = output_entry.first;
		auto const &val = ctx.get(name);
		std::cout << name << " : " << val->type << " = " << *val << '\n';
	}

	return 0;
}

