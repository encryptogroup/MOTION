#ifndef CBMC_CIRCUIT_H
#define CBMC_CIRCUIT_H

#include "spec.hpp"

#include <cassert>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <unordered_map>


// Helpers
//==================================================================================================
template<typename T, typename Tag>
struct TaggedValue
{
	using value_type = T;

	TaggedValue() = default;
	explicit TaggedValue(T value) :
		value{value} {}

	// To make a TaggedValue usable with std::iota()
	TaggedValue& operator ++ ()
	{
		++value;
		return *this;
	}

	value_type value;
};


// CBMC Circuit
//==================================================================================================
namespace circ {

// Gate
//--------------------------------------------------------------------------
enum class GateKind : uint8_t
{
	not_gate,
	and_gate,
	or_gate,
	xor_gate,
};

inline std::string to_string(GateKind kind)
{
	switch(kind)
	{
		case GateKind::not_gate: return "NOT";
		case GateKind::and_gate: return "AND";
		case GateKind::or_gate: return "OR";
		case GateKind::xor_gate: return "XOR";
		default: return "never happens";
	}
}

struct Gate;
using GateID = TaggedValue<uint64_t, Gate>;


// Input
//--------------------------------------------------------------------------
struct Input;
using InputID = TaggedValue<uint64_t, Input>;

enum class Party
{
	alice,
	bob,
};

inline std::string to_string(Party party)
{
	switch(party)
	{
		case Party::alice: return "alice";
		case Party::bob: return "bob";
		default: return "never happens";
	}
}


// Output
//--------------------------------------------------------------------------
struct Output;
using OutputID = TaggedValue<uint64_t, Output>;

// ElementID
//--------------------------------------------------------------------------
struct ConstOneTag {};

class ElementID
{
public:
	using value_type = uint64_t;

	enum class Kind : uint64_t
	{
		const_one = 0,
		gate = 1ull << 63,
		input = 1ull << 62,
		output = 3ull << 62,
	};

	ElementID() = default;

	ElementID(ConstOneTag) :
		m_id{static_cast<uint64_t>(Kind::const_one)} {}

	ElementID(GateID id) :
		m_id{id.value | static_cast<uint64_t>(Kind::gate)}
	{
		assert(id.value < 1ull << 62);
	}

	ElementID(InputID id) :
		m_id{id.value | static_cast<uint64_t>(Kind::input)}
	{
		assert(id.value < 1ull << 62);
	}

	ElementID(OutputID id) :
		m_id{id.value | static_cast<uint64_t>(Kind::output)}
	{
		assert(id.value < 1ull << 62);
	}

	uint64_t id() const { return m_id & 0x3fffffff'ffffffff; }
	Kind kind() const { return static_cast<Kind>(m_id & (3ull << 62)); }

	uint64_t raw() const { return m_id; }

	GateID as_gate_id() const
	{
		assert(kind() == Kind::gate);
		return GateID{id()};
	}

	OutputID as_output_id() const
	{
		assert(kind() == Kind::output);
		return OutputID{id()};
	}

private:
	uint64_t m_id;
};

inline ElementID const_one_id()
{
	return ElementID{ConstOneTag{}};
}

inline bool operator == (ElementID a, ElementID b)
{
	return a.raw() == b.raw();
}

inline std::ostream& operator << (std::ostream &os, ElementID id)
{
	switch(id.kind())
	{
		case ElementID::Kind::gate: os << "Gate" << '(' << id.id() << ')'; break;
		case ElementID::Kind::output: os << "Output" << '(' << id.id() << ')'; break;
		case ElementID::Kind::input: os << "Input" << '(' << id.id() << ')'; break;
		case ElementID::Kind::const_one: os << "ConstOne"; break;
	}

	return os;
}

}


namespace std {

template<>
struct hash<::circ::ElementID>
{
	using argument_type = ::circ::ElementID;
	using result_type = size_t;

	result_type operator () (argument_type id) const
	{
		return hash<argument_type::value_type>{}(id.raw());
	}
};

template<typename T, typename Tag>
struct hash<::TaggedValue<T, Tag>>
{
	using argument_type = ::TaggedValue<T, Tag>;
	using result_type = size_t;

	result_type operator () (argument_type const &v) const
	{
		return hash<T>{}(v.value);
	}
};

}


namespace circ {

struct Gate
{
	Gate() :
		num_fanins{0} {}

	explicit Gate(GateKind kind) :
		kind{kind},
		num_fanins{0} {}

	ElementID fanins[2];
	GateKind kind;
	// Necessary because we may not always know the inputs yet when creating a gate.
	int8_t num_fanins;
};

inline bool all_fanins_specified(Gate const &gate)
{
	if(gate.kind == GateKind::not_gate)
		return gate.num_fanins == 1;
	
	return gate.num_fanins == 2;
}

struct InputVariable
{
	Party party;
	std::string name;
	std::vector<InputID> inputs;
	Type type;
};

struct OutputVariable
{
	std::string name;
	std::vector<OutputID> outputs;
	Type type;
};

struct FaninList
{
	FaninList() :
		count{0} {}

	FaninList(ElementID fanin) :
		ids{fanin, {}},
		count{1} {}

	FaninList(ElementID fanin0, ElementID fanin1) :
		ids{fanin0, fanin1},
		count{2} {}

	ElementID ids[2];
	int8_t count;
};

// Circuit
//--------------------------------------------------------------------------
class Circuit
{
public:
	Gate& operator [] (GateID id) { assert(id.value < gates.size()); return gates[id.value]; }
	Gate const& operator [] (GateID id) const { assert(id.value < gates.size()); return gates[id.value]; }

	Party& operator [] (InputID id) { assert(id.value < inputs.size()); return inputs[id.value]; }
	Party operator [] (InputID id) const { assert(id.value < inputs.size()); return inputs[id.value]; }

	optional<ElementID>& operator [] (OutputID id) { assert(id.value < outputs.size()); return outputs[id.value]; }
	optional<ElementID> const& operator [] (OutputID id) const { assert(id.value < outputs.size()); return outputs[id.value]; }

	void add_wire(ElementID from, ElementID to)
	{
		if(from.kind() == ElementID::Kind::output)
			throw std::runtime_error{"Output(" + std::to_string(from.id()) + ") can't be used as fanin"};

		switch(to.kind())
		{
			case ElementID::Kind::gate:
			{
				assert(to.id() < gates.size());
				Gate &gate = gates[to.id()];

				if(gate.num_fanins == 2)
					throw std::runtime_error{"GateID(" + std::to_string(to.id()) + ") already has max number of fanins"};

				gate.fanins[gate.num_fanins++] = from;
			} break;

			case ElementID::Kind::output:
				if(outputs[to.id()])
					throw std::runtime_error{"Fanin of output is already specified"};

				outputs[to.id()] = from;
				break;

			default:
				throw std::runtime_error{"Invalid element target for wire"};
		}
	}

	FaninList get_fanins(ElementID id) const
	{
		switch(id.kind())
		{
			case ElementID::Kind::gate:
			{
				Gate const &gate = gates[id.id()];
				FaninList list;
				list.count = gate.num_fanins;
				for(int i = 0; i < list.count; ++i)
					list.ids[i] = gate.fanins[i];

				return list;
			};

			case ElementID::Kind::output:
				if(outputs[id.id()])
					return FaninList{*outputs[id.id()]};
				else
					return FaninList{};

			default:
				return FaninList{};
		}
	}


	// InputVariable -------------------------
	InputVariable const* find_variable_of_input(InputID id) const
	{
		for(auto const &pair: name_to_inputs)
		{
			auto &var = pair.second;
			if(std::find(var.inputs.begin(), var.inputs.end(), id) != var.inputs.end())
				return &var;
		}

		return nullptr;
	}

	Party get_input_variable_party(std::string const &name) const
	{
		auto it = name_to_inputs.find(name);
		if(it == name_to_inputs.end())
			throw std::runtime_error{"Invalid variable name: " + name};

		return inputs[it->second.inputs[0].value];
	}

	void add_input_variable(Party party, std::string const &name, std::vector<InputID> &&inputs)
	{
		assert(inputs.size());

		int width = inputs.size();
		name_to_inputs[name] = {party, name, std::move(inputs), Type{BitsType{width}}};

		// TODO Make sure all inputs belong to the same party
	}

	void add_input_variable(Party party, std::string const &name, InputID first, uint64_t width)
	{
		std::vector<InputID> inputs(width);
		iota_n(inputs.begin(), width, first);
		name_to_inputs[name] = {party, name, std::move(inputs), Type{BitsType{(int)width}}};

		// TODO Make sure all inputs belong to the same party
	}

	void add_input_variable(Party party, std::string const &name, std::vector<InputID> const &inputs, Type const &type)
	{
		name_to_inputs[name] = {party, name, inputs, type};

		// TODO Make sure all inputs belong to the same party
	}


	// OutputVariable ------------------------
	void add_output_variable(std::string const &name, std::vector<OutputID> &&outputs)
	{
		int width = outputs.size();
		name_to_outputs[name] = {name, std::move(outputs), Type{BitsType{width}}};
	}

	void add_output_variable(std::string const &name, std::vector<OutputID> const &outputs, Type const &type)
	{
		name_to_outputs[name] = {name, outputs, type};
	}

	void add_output_variable(std::string const &name, OutputID first, uint64_t width)
	{
		std::vector<OutputID> outputs(width);
		iota_n(outputs.begin(), width, first);
		name_to_outputs[name] = {name, std::move(outputs), Type{BitsType{(int)width}}};
	}

	size_t get_output_variable_width(std::string const &name)
	{
		auto it = name_to_outputs.find(name);
		if(it == name_to_outputs.end())
			throw std::runtime_error{"Invalid variable name: " + name};

		return it->second.outputs.size();
	}


	// GateID -> Gate
	std::vector<Gate> gates;
	// OutputID -> input
	std::vector<optional<ElementID>> outputs;
	// InputID -> Party
	// TODO Don't store the party for each input. Store it instead in Input/OutputVariable.
	std::vector<Party> inputs;

	std::unordered_map<std::string, InputVariable> name_to_inputs;
	std::unordered_map<std::string, OutputVariable> name_to_outputs;

	struct DebugMessage
	{
		std::string message;
		Type type;
		std::vector<ElementID> data;
	};

	std::vector<DebugMessage> debug_messages;
};




using InputVarIterator = std::unordered_map<std::string, InputVariable>::const_iterator;
inline std::pair<InputVarIterator, InputVarIterator> get_alice_and_bob(Circuit const &circ)
{
	if(circ.name_to_inputs.size() != 2)
		throw std::runtime_error{
			"Right now, code generation is only supported for circuits with exactly one input per party"
		};

	auto it_a = circ.name_to_inputs.begin();
	auto it_b = std::next(it_a);

	auto party_a = circ.get_input_variable_party(it_a->first);
	auto party_b = circ.get_input_variable_party(it_b->first);
	if(party_a == Party::bob)
	{
		std::swap(it_a, it_b);
		std::swap(party_a, party_b);
	}

	return {it_a, it_b};
}

inline OutputVariable const& get_single_output(Circuit const &circ)
{
	if(circ.name_to_outputs.size() != 1)
		throw std::runtime_error{
			"Right now, code generation is only supported for circuits with exactly one output"
		};

	return circ.name_to_outputs.begin()->second;
}

inline void validate(Circuit &circ)
{
	for(size_t id = 0; id < circ.gates.size(); ++id)
	{
		Gate const &gate = circ.gates[id];

		// Make sure all gates have the correct number of inputs.
		switch(gate.kind)
		{
			case GateKind::and_gate:
			case GateKind::or_gate:
			case GateKind::xor_gate:
				if(gate.num_fanins != 2)
					throw std::runtime_error{"Invalid number of inputs: " + std::to_string(gate.num_fanins) + ", expected 2 (id=" + std::to_string(id) + ")"};
				break;
			case GateKind::not_gate:
				if(gate.num_fanins != 1)
					throw std::runtime_error{"Invalid number of inputs: " + std::to_string(gate.num_fanins) + ", expected 1 (id=" + std::to_string(id) + ")"};
				break;
		}
	}

	for(size_t id = 0; id < circ.outputs.size(); ++id)
	{
		if(!circ.outputs[id])
			throw std::runtime_error{"Output(" + std::to_string(id) + ") has no fanin"};
	}
}




// Topological traversal
//--------------------------------------------------------------------------
enum class SortingMark
{
	none,
	temp,
	perm,
};

inline SortingMark& get_mark(std::unordered_map<ElementID, SortingMark> &marks, ElementID id)
{
	auto pair = marks.emplace(id, SortingMark::none);
	return pair.first->second;
}

template<typename Func>
void visit(Circuit const &circ, ElementID cur_id, std::unordered_map<ElementID, SortingMark> &marks, Func &&func)
{
	// TODO Make iterative.

	auto &mark = get_mark(marks, cur_id);
	if(mark == SortingMark::none)
	{
		mark = SortingMark::temp;
		FaninList fanins = circ.get_fanins(cur_id);
		for(int i = 0; i < fanins.count; ++i)
			visit(circ, fanins.ids[i], marks, std::forward<Func>(func));
		mark = SortingMark::perm;

		func(cur_id);
	}
	else if(mark == SortingMark::temp)
		throw std::runtime_error{"Cycle in circuit detected"};
}

template<typename Func>
void topological_traversal(Circuit const &circ, Func &&func)
{
	std::unordered_map<ElementID, SortingMark> marks;
	for(uint64_t output_id = 0; output_id < circ.outputs.size(); ++output_id)
	{
		ElementID id{OutputID{output_id}};
		if(get_mark(marks, id) == SortingMark::none)
			visit(circ, id, marks, std::forward<Func>(func));
	}
}

template<typename Func>
void topological_traversal_from_output(Circuit const &circ, OutputID oid, Func &&func)
{
	std::unordered_map<ElementID, SortingMark> marks;
	visit(circ, ElementID{oid}, marks, std::forward<Func>(func));
}

// Sub-circuit creation
//--------------------------------------------------------------------------
/*inline Circuit circuit_for_output(Circuit const &circ, OutputID root_id)
{
	Circuit subcirc;

	std::unordered_map<ElementID, ElementID> old_to_new;
	ConstantID cid{0};
	GateID gid{0};
	InputID iid{0};
	OutputID oid{0};


	topological_traversal_from_output(circ, root_id, [&](ElementID eid)
	{
		switch(eid.kind())
		{
			case ElementID::Kind::constant:
				subcirc.add_constant(cid, circ.get_constant(ConstantID{eid.id()}));
				old_to_new[eid] = cid;
				cid.value++;
				break;
			case ElementID::Kind::gate:
			{
				subcirc.set_gate(gid, circ.get_gate(GateID{eid.id()}).kind);
				old_to_new[eid] = gid;

				auto input_wires_range = circ.wires.equal_range(eid);
				for(auto it = input_wires_range.first; it != input_wires_range.second; it++)
					subcirc.add_wire(old_to_new.at(it->second), gid);

				gid.value++;
			} break;
			case ElementID::Kind::input:
			{
				auto input = circ.get_input(InputID{eid.id()});
				subcirc.set_input(iid, input.party, input.value);
				old_to_new[eid] = iid;

				auto old_var = circ.find_variable_of_input(InputID{eid.id()});
				auto &subcirc_var = subcirc.name_to_inputs[old_var->name];
				subcirc_var.name = old_var->name;
				subcirc_var.type = old_var->type;
				subcirc_var.inputs.push_back(iid);

				iid.value++;
			} break;
			case ElementID::Kind::output:
			{
				subcirc.set_output(oid);
				old_to_new[eid] = oid;

				auto input_wires_range = circ.wires.equal_range(eid);
				for(auto it = input_wires_range.first; it != input_wires_range.second; it++)
					subcirc.add_wire(old_to_new.at(it->second), oid);

				oid.value++;
			} break;
		}
	});

	subcirc.add_output_variable("OUTPUT_res", {OutputID{0}});

	return subcirc;
}*/

// Circuit simulation
//--------------------------------------------------------------------------

}


#endif
