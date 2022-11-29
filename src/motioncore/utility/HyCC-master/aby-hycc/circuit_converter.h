#pragma once

#include <libcircuit/simple_circuit.h>

#include "../../abycore/circuit/booleancircuits.h"
#include "../../abycore/circuit/arithmeticcircuits.h"
#include "../../abycore/circuit/circuit.h"
#include "../../abycore/aby/abyparty.h"
#include "../../abycore/sharing/sharing.h"



//==================================================================================================
inline const char* cstr(e_sharing sharing)
{
	switch(sharing)
	{
		case S_BOOL: return "GMW";
		case S_YAO: return "YAO";
		case S_ARITH: return "ARITH";
		case S_YAO_REV: return "YAO_REV";
		case S_SPLUT: return "SPLUT";
		case S_LAST: return "INVALID";
		default: assert(!"Invalid sharing");
	}
}


//==================================================================================================
using gatet = simple_circuitt::gatet;
using wire_endpointt = gatet::wire_endpointt;

// Returns the two inputs of the element `id`. Throws if the number of inputs to `id` is not two.
inline std::pair<wire_endpointt, wire_endpointt> get_two_fanins(gatet *gate)
{
	if(gate->num_fanins() != 2)
		throw std::runtime_error{"Invalid number of inputs: " + std::to_string(gate->num_fanins())};

	return {gate->fanin_range()[0], gate->fanin_range()[1]};
}

// Returns the input of the element `id`. Throws if the number of inputs to `id` is not one.
inline wire_endpointt get_one_fanin(gatet *gate)
{
	if(gate->num_fanins() != 1)
		throw std::runtime_error{"Invalid number of inputs: " + std::to_string(gate->num_fanins())};

	return gate->fanin_range()[0];
}

inline e_role cbmc_party_to_aby_role(variable_ownert owner)
{
	assert(owner != variable_ownert::output);
	return owner == variable_ownert::input_alice ? CLIENT : SERVER;
}


inline void set_sharing(gatet *gate, e_sharing sharing)
{
	// Use the 64th bit to indicate whether a sharing has been set
	gate->user.uint_val |= 1ull << 63;
	gate->user.uint_val |= sharing;
}

inline e_sharing get_sharing(gatet const *gate)
{
	// Check if a sharing has been set
	if(gate->user.uint_val & (1ull << 63))
		return (e_sharing)(gate->user.uint_val & 0xffffffff);
	else
	{
		if(gate->get_operation() == simple_circuitt::SPLIT)
		{
			assert(gate->get_fanouts().size());
			return get_sharing(gate->get_fanouts()[0]->second.gate);
		}

		if(is_arithmetic_op(gate->get_operation()) || gate->get_operation() == simple_circuitt::COMBINE)
			return e_sharing::S_ARITH;

		assert(!"Unexpected gate operation");
	}
}



struct ABYOutputGate
{
	int width;
	uint32_t id;
};

struct ABYOutputVariable
{
	std::string name;
	std::vector<ABYOutputGate> ids;
};

using ABYOutputMap = std::unordered_map<std::string, ABYOutputVariable>;



struct GateSharing
{
	wire_endpointt ep;
	e_sharing sharing;

	struct Hash
	{
		size_t operator () (GateSharing v) const
		{
			size_t h = 0;
			hash_combine(h, (uint32_t)v.sharing);
			hash_combine(h, v.ep.gate);
			hash_combine(h, v.ep.pin);

			return h;
		}
	};
};

inline bool operator == (GateSharing a, GateSharing b)
{
	return a.ep == b.ep && a.sharing == b.sharing;
}



class CircuitConverter
{
public:
	static constexpr uint32_t INVALID_GATE = -1;

	CircuitConverter(
		simple_circuitt *cbmc,
		std::unordered_map<gatet*, uint64_t> const &input_values,
		ABYParty* party
	) :
		m_cbmc{cbmc},
		m_input_values{std::move(input_values)},
		m_aby_party{party}
	{
		std::vector<Sharing*>& sharings = party->GetSharings();

		m_aby_yao = dynamic_cast<BooleanCircuit*>(sharings.at(e_sharing::S_YAO)->GetCircuitBuildRoutine());
		m_aby_bool = dynamic_cast<BooleanCircuit*>(sharings.at(e_sharing::S_BOOL)->GetCircuitBuildRoutine());
		m_aby_arith = dynamic_cast<ArithmeticCircuit*>(sharings.at(e_sharing::S_ARITH)->GetCircuitBuildRoutine());

		for(auto *var: m_cbmc->ordered_inputs())
		{
			for(auto *gate: var->gates)
				m_input_parties[gate] = var->owner;
		}
	}

	// Converts a single element (gate, constant, input, output).
	void operator () (gatet *gate)
	{
		switch(gate->get_operation())
		{
			case simple_circuitt::NOT:
			{
				auto fanin = get_one_aby_fanin(gate);
				map_gate({primary_output(gate), get_sharing(gate)}, boolean_circuit(gate)->PutINVGate(fanin));
			} break;

			case simple_circuitt::NEG:
			{
				throw std::runtime_error{"NEG gate not supported yet"};
			} break;

			case simple_circuitt::AND:
			{
				auto inputs = get_two_aby_fanins(gate);
				uint32_t aby_gate = boolean_circuit(gate)->PutANDGate(inputs.first, inputs.second);
				map_gate({primary_output(gate), get_sharing(gate)}, aby_gate);
			} break;

			case simple_circuitt::OR:
			{
				auto inputs = get_two_aby_fanins(gate);

				// ABY has no direct support for OR, replace 'a OR b' with '(a AND b) XOR (a XOR b)'
				uint32_t left = boolean_circuit(gate)->PutANDGate(inputs.first, inputs.second);
				uint32_t right = boolean_circuit(gate)->PutXORGate(inputs.first, inputs.second);

				map_gate({primary_output(gate), get_sharing(gate)}, boolean_circuit(gate)->PutXORGate(left, right));
			} break;

			case simple_circuitt::XOR:
			{
				auto inputs = get_two_aby_fanins(gate);
				map_gate({primary_output(gate), get_sharing(gate)}, boolean_circuit(gate)->PutXORGate(inputs.first, inputs.second));
			} break;

			case simple_circuitt::ADD:
			{
				verify_arith_bit_width(gate->get_width());
				auto inputs = get_two_aby_fanins(gate);
				map_gate({primary_output(gate), e_sharing::S_ARITH}, m_aby_arith->PutADDGate(inputs.first, inputs.second));
			} break;

			case simple_circuitt::SUB:
			{
				verify_arith_bit_width(gate->get_width());
				auto inputs = get_two_aby_fanins(gate);
				map_gate({primary_output(gate), e_sharing::S_ARITH}, m_aby_arith->PutSUBGate(inputs.first, inputs.second));
			} break;

			case simple_circuitt::MUL:
			{
				verify_arith_bit_width(gate->get_width());
				auto inputs = get_two_aby_fanins(gate);
				map_gate(
					{primary_output(gate), e_sharing::S_ARITH},
					m_aby_arith->PutMULGate(inputs.first, inputs.second)
				);
			} break;

			case simple_circuitt::COMBINE:
			{
				verify_arith_bit_width(gate->get_width());
				assert(gate->fanin_range().size());

				e_sharing boolean_sharing = choose_sharing_for_combine(gate);
				std::vector<uint32_t> bool_wires;
				for(auto fanin: gate->fanin_range())
					bool_wires.push_back(get_aby_gate({fanin, boolean_sharing}));

				boolshare *bool_share = new boolshare{bool_wires, boolean_circuit(boolean_sharing)};
				map_gate({primary_output(gate), e_sharing::S_ARITH}, bool_to_arith_wire(bool_share));
			} break;

			case simple_circuitt::SPLIT:
			{
				arithshare *arith_share = new arithshare{m_aby_arith};
				arith_share->set_wire_id(0, get_aby_gate({get_one_fanin(gate), S_ARITH}));

				// To determine the boolean sharing we want to convert to we look at the fanouts of
				// the SPLIT gate. In case all fanouts are directly connected to a COMBINE gate we
				// will use YAO.
				// TODO Use default boolean sharing as specified in the command line instead of YAO
				e_sharing dest_boolean_sharing = e_sharing::S_YAO;
				for(auto *fanout: gate->get_fanouts())
				{
					e_sharing sharing = get_sharing(fanout->second.gate);
					// If the SPLIT gate is directly connected to a COMBINE gate then the sharing is
					// ARITH
					if(sharing != e_sharing::S_ARITH)
					{
						dest_boolean_sharing = sharing;
						break;
					}
				}
				assert(dest_boolean_sharing == e_sharing::S_YAO || dest_boolean_sharing == e_sharing::S_BOOL);

				// If all fanouts of this SPLIT are connected to a COMBINE, the COMBINE needs a way
				// to find out the boolean sharing.
				set_sharing(gate, dest_boolean_sharing);

				share *bool_share = arith_to_bool_share(arith_share, dest_boolean_sharing);
				uint8_t i = 0;
				for(uint32_t aby_wire: bool_share->get_wires())
					map_gate({wire_endpointt{gate, i++}, dest_boolean_sharing}, aby_wire);
			} break;

			case simple_circuitt::ONE:
			{
				map_gate({primary_output(gate), get_sharing(gate)}, boolean_circuit(gate)->PutConstantGate((uint32_t)1, 1));
			} break;

			case simple_circuitt::CONST:
			{
				verify_arith_bit_width(gate->get_width());
				map_gate({primary_output(gate), e_sharing::S_ARITH}, m_aby_arith->PutConstantGate(gate->get_value(), 1));
			} break;

			case simple_circuitt::INPUT:
			{
				// Inputs are converted on the fly
			} break;

			case simple_circuitt::OUTPUT:
			{
				auto fanin = get_one_fanin(gate);
				if(fanin.gate->get_width() == 1)
					map_gate(
						{wire_endpointt{gate, 0}, get_sharing(gate)},
						boolean_circuit(gate)->PutOUTGate(get_aby_gate({fanin, get_sharing(gate)}), ALL)
					);
				else
					map_gate(
						{wire_endpointt{gate, 0}, S_ARITH},
						m_aby_arith->PutOUTGate(get_aby_gate({fanin, S_ARITH}), ALL)
					);
			} break;

			case simple_circuitt::LUT:
				throw std::runtime_error{"LUTs are not supported"};
		}
	}

	ABYOutputMap create_output_map()
	{
		ABYOutputMap map;
		for(auto const *var: m_cbmc->ordered_outputs())
		{
			ABYOutputVariable ov;
			ov.name = var->name;

			for(auto output: var->gates)
			{
				uint32_t aby_output = get_aby_gate({wire_endpointt{output, 0}, get_sharing(output)});
				ov.ids.push_back({output->get_width(), aby_output});
			}

			map[ov.name] = ov;
		}

		return map;
	}

	BooleanCircuit* boolean_circuit(gatet *gate)
	{
		return boolean_circuit(get_sharing(gate));
	}

	BooleanCircuit* boolean_circuit(e_sharing boolean_sharing)
	{
		switch(boolean_sharing)
		{
			case e_sharing::S_YAO: return m_aby_yao;
			case e_sharing::S_BOOL: return m_aby_bool;
			default: assert(!"Invalid boolean sharing");
		}
	}

private:
	simple_circuitt *m_cbmc;
	// Maps INPUT gates to their values
	std::unordered_map<gatet*, uint64_t> m_input_values;
	// Maps INPUT gates to their party
	std::unordered_map<gatet*, variable_ownert> m_input_parties;

	struct ABYGates
	{
		uint32_t yao_gate = INVALID_GATE;
		uint32_t gmw_gate = INVALID_GATE;
		uint32_t arith_gate = INVALID_GATE;

		void set(e_sharing sharing, uint32_t aby_gate)
		{
			switch(sharing)
			{
				case S_YAO: yao_gate = aby_gate; break;
				case S_BOOL: gmw_gate = aby_gate; break;
				case S_ARITH: arith_gate = aby_gate; break;
				default: assert(!"Invalid sharing");
			}
		}

		uint32_t get(e_sharing sharing)
		{
			switch(sharing)
			{
				case S_YAO: return yao_gate;
				case S_BOOL: return gmw_gate;
				case S_ARITH: return arith_gate;
				default: assert(!"Invalid sharing");
			}
		}
	};
	std::unordered_map<wire_endpointt, ABYGates, wire_endpoint_hasht> m_cbmc_to_aby;

	ABYParty *m_aby_party;
	BooleanCircuit *m_aby_bool;
	BooleanCircuit *m_aby_yao;
	ArithmeticCircuit *m_aby_arith;

	int m_arith_bit_width = 0;


	//--------------------------------------------------------------------------
	// Throws an exception if the specified bit-width is different from the expected width
	void verify_arith_bit_width(int width)
	{
		if(m_arith_bit_width == 0)
			m_arith_bit_width = width;

		if(m_arith_bit_width != width)
		{
			throw std::runtime_error{
				"Different bit widths in arithmetic circuit: " + std::to_string(m_arith_bit_width) +
				" vs " + std::to_string(width)
			};
		}
	}


	//--------------------------------------------------------------------------
	void map_gate(GateSharing gate_sharing, uint32_t aby_gate)
	{
		m_cbmc_to_aby[gate_sharing.ep].set(gate_sharing.sharing, aby_gate);
	}

	uint32_t get_aby_gate(GateSharing gate_sharing)
	{
		auto it = m_cbmc_to_aby.find(gate_sharing.ep);
		if(it != m_cbmc_to_aby.end())
		{
			ABYGates aby_gates = it->second;
			if(aby_gates.get(gate_sharing.sharing) != uint32_t(-1))
				return aby_gates.get(gate_sharing.sharing);

			// Okay, the gate has already been converted, but to a different sharing.
			// We only do conversion between YAO and GMW here. Converting to and from arithmetic
			// gates is handled separately.

			// Converting GMW to YAO
			if(aby_gates.gmw_gate != INVALID_GATE && gate_sharing.sharing == S_YAO)
				return aby_gates.yao_gate = m_aby_yao->PutB2YCONVGate(aby_gates.gmw_gate);

			// Converting YAO to GMW
			if(aby_gates.yao_gate != INVALID_GATE && gate_sharing.sharing == S_BOOL)
			{
				// PutY2BCONVGate() does not work if the source gate is an INPUT. In this case we
				// create a new GMW INPUT
				if(gate_sharing.ep.gate->get_operation() == simple_circuitt::INPUT)
					return create_input(gate_sharing);

				return aby_gates.gmw_gate = m_aby_bool->PutY2BCONVGate(aby_gates.yao_gate);
			}

			assert(!"Invalid sharing coonversion");
		}

		assert(gate_sharing.ep.gate->get_operation() == simple_circuitt::INPUT);
		return create_input(gate_sharing);
	}

	uint32_t create_input(GateSharing input_sharing)
	{
		assert(input_sharing.ep.gate->get_operation() == simple_circuitt::INPUT);

		e_role role = cbmc_party_to_aby_role(m_input_parties.at(input_sharing.ep.gate));
		uint64_t input_value = m_input_values.at(input_sharing.ep.gate);

		uint32_t aby_input;
		switch(input_sharing.sharing)
		{
			case S_YAO: aby_input = m_aby_yao->PutINGate(input_value, role); break;
			case S_BOOL: aby_input = m_aby_bool->PutINGate(input_value, role); break;
			case S_ARITH: aby_input = m_aby_arith->PutINGate(input_value, role); break;
			default: assert(!"Invalid sharing");
		}

		map_gate(input_sharing, aby_input);
		return aby_input;
	}


	// Conversion between arithmetic and boolean gates
	//--------------------------------------------------------------------------
	uint32_t bool_to_arith_wire(boolshare *bool_share)
	{
		switch(bool_share->get_share_type())
		{
			// Converting a YAO gate to an arithmetic gate is done by first converting it to a
			// Boolean (GMW) gate. Converting a YAO gate to a Boolean gate is only possible if the
			// YAO gate is not an INPUT gate. So make sure `bool_share` does not contain 
			case e_sharing::S_YAO:return m_aby_arith->PutY2AGate(bool_share, m_aby_bool)->get_wire_id(0);
			case e_sharing::S_BOOL: return m_aby_arith->PutB2AGate(bool_share->get_wires());
			default: assert(!"Invalid boolean sharing");
		}
	}

	share* arith_to_bool_share(arithshare *arith_share, e_sharing dest_boolean_sharing)
	{
		switch(dest_boolean_sharing)
		{
			case e_sharing::S_YAO: return m_aby_yao->PutA2YGate(arith_share);
			case e_sharing::S_BOOL: return m_aby_bool->PutA2BGate(arith_share, m_aby_yao);
			default: assert(!"Invalid boolean sharing");
		}
	}


	//--------------------------------------------------------------------------
	// A COMBINE gate converts its boolean fanins to a single ARITH gate. For this, all fanins must
	// be of the same kind (either YAO or GMW). This function tries to choose the boolean sharing
	// that requires the least conversions.
	e_sharing choose_sharing_for_combine(gatet *gate)
	{
		assert(gate->get_operation() == simple_circuitt::COMBINE);

		int num_gmw = 0;
		int num_yao = 0;
		for(auto fanin: gate->fanin_range())
		{
			// If at least one fanin is an INPUT we use GMW because because YAO INPUTs cannot
			// directly be converted to ARITH
			// TODO Don't know if this is always the most efficient thing to do
			if(fanin.gate->get_operation() == simple_circuitt::INPUT)
				return S_BOOL;

			auto it = m_cbmc_to_aby.find(fanin);
			if(it != m_cbmc_to_aby.end())
			{
				ABYGates const &aby = it->second;
				num_gmw += aby.gmw_gate != INVALID_GATE;
				num_yao += aby.yao_gate != INVALID_GATE;
			}
		}

		return num_yao > num_gmw ? S_YAO : S_BOOL;
	}


	//--------------------------------------------------------------------------
	std::pair<uint32_t, uint32_t> get_two_aby_fanins(gatet *gate)
	{
		e_sharing sharing = get_sharing(gate);
		auto fanins = get_two_fanins(gate);

		return {
			get_aby_gate({fanins.first, sharing}),
			get_aby_gate({fanins.second, sharing}),
		};
	}

	uint32_t get_one_aby_fanin(gatet *gate)
	{
		return get_aby_gate({get_one_fanin(gate), get_sharing(gate)});
	}
};


//==================================================================================================
// ABY's conversion gates cannot connect a YAO input to an arithmetic gate (converting normal YAO
// gates like AND etc to arithmetic gates is supported though). For this reason we try to replace
// COMBINERs whose fanins consists only of boolean INPUTs with a single new, arithmetic INPUT of the
// same width as the COMBINER.
void replace_input_combiners(simple_circuitt &circuit, loggert &logger);

