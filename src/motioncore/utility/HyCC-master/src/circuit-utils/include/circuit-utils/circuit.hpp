#ifndef CBMC_CIRCUIT_H
#define CBMC_CIRCUIT_H

#include <cassert>
#include <fstream>
#include <sstream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <unordered_map>

#include <libcircuit/utils.h>
#include <libcircuit/type.h>


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
	one_gate,

	add_gate,
	sub_gate,
	neg_gate,
	mul_gate,
	const_gate,

	combine_gate,
	split_gate,
};

inline bool is_arithmetic(GateKind kind)
{
	switch(kind)
	{
		case GateKind::add_gate:
		case GateKind::sub_gate:
		case GateKind::neg_gate:
		case GateKind::mul_gate:
		case GateKind::const_gate:
			return true;
		default:
			return false;
	};
}

inline bool is_boolean(GateKind kind)
{
	switch(kind)
	{
		case GateKind::not_gate:
		case GateKind::and_gate:
		case GateKind::or_gate:
		case GateKind::xor_gate:
		case GateKind::one_gate:
			return true;
		default:
			return false;
	};
}

inline bool is_non_linear_gate(GateKind kind)
{
	switch(kind)
	{
		case GateKind::and_gate:
		case GateKind::or_gate:
		case GateKind::mul_gate:
			return true;
		default:
			return false;
	};
}

inline std::string to_string(GateKind kind)
{
	switch(kind)
	{
		case GateKind::not_gate: return "NOT";
		case GateKind::and_gate: return "AND";
		case GateKind::or_gate: return "OR";
		case GateKind::xor_gate: return "XOR";
		case GateKind::one_gate: return "ONE";

		case GateKind::add_gate: return "ADD";
		case GateKind::sub_gate: return "SUB";
		case GateKind::neg_gate: return "NEG";
		case GateKind::mul_gate: return "MUL";
		case GateKind::const_gate: return "CONST";

		case GateKind::combine_gate: return "COMBINE";
		case GateKind::split_gate: return "SPLIT";
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
class ElementID
{
public:
	using value_type = uint64_t;

	enum class Kind : uint64_t
	{
		gate = 1ull << 63,
		input = 1ull << 62,
		output = 3ull << 62,
	};

	ElementID() = default;

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

	InputID as_input_id() const
	{
		assert(kind() == Kind::input);
		return InputID{id()};
	}

private:
	uint64_t m_id;
};

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
	}

	return os;
}

inline std::string str(ElementID id)
{
	std::stringstream ss;
	ss << id;
	return ss.str();
}


struct WireEndpoint
{
	WireEndpoint() = default;

	WireEndpoint(ElementID id, uint8_t pin) :
		id{id},
		pin{pin} {}

	ElementID id;
	uint8_t pin;
};

inline bool operator == (WireEndpoint const &a, WireEndpoint const &b)
{
	return a.id == b.id && a.pin == b.pin;
}

inline WireEndpoint primary_endpoint(ElementID id)
{
	return {id, 0};
}

inline WireEndpoint next_endpoint(ElementID id)
{
	return {id, uint8_t(-1)};
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

template<>
struct hash<::circ::WireEndpoint>
{
	using argument_type = ::circ::WireEndpoint;
	using result_type = size_t;

	result_type operator () (argument_type const &v) const
	{
		auto h = hash<::circ::ElementID>{}(v.id);
		::hash_combine(h, v.pin);
		return h;
	}
};

}


namespace circ {

struct Gate
{
	Gate() :
		num_fanins{0} {}

	explicit Gate(GateKind kind, uint8_t max_fanins, uint8_t width, uint64_t const_value = 0) :
		kind{kind},
		width{width},
		fanins(max_fanins),
		num_fanins{0},
        const_value{const_value}
	{
		// We need something like LLVM's SmallVector
		fanouts.reserve(8);
	}

	GateKind kind;
	uint8_t width;
	std::vector<WireEndpoint> fanins;
	std::vector<WireEndpoint> fanouts;
	// Necessary because we may not always know the inputs yet when creating a gate.
	uint8_t num_fanins;

    // Constant value used in arithmetic circuit
    uint64_t const_value;
};

inline bool all_fanins_specified(Gate const &gate)
{
	return gate.num_fanins == gate.fanins.size();
}

struct Input
{
	Input() = default;
	Input(Party party, uint8_t width) :
		party{party},
		width{width} {}

	// TODO Don't store the party for each input. Store it instead in Input/OutputVariable.
	Party party;
	uint8_t width;
	std::vector<WireEndpoint> fanouts;
};

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


// Circuit
//--------------------------------------------------------------------------
class Circuit
{
public:
	Gate& operator [] (GateID id) { assert(id.value < gates.size()); return gates[id.value]; }
	Gate const& operator [] (GateID id) const { assert(id.value < gates.size()); return gates[id.value]; }

	Party& operator [] (InputID id) { assert(id.value < inputs.size()); return inputs[id.value].party; }
	Party operator [] (InputID id) const { assert(id.value < inputs.size()); return inputs[id.value].party; }

	optional<WireEndpoint>& operator [] (OutputID id) { assert(id.value < outputs.size()); return outputs[id.value]; }
	optional<WireEndpoint> const& operator [] (OutputID id) const { assert(id.value < outputs.size()); return outputs[id.value]; }

	uint8_t get_width(ElementID id) const
	{
		switch(id.kind())
		{
			case ElementID::Kind::input: return inputs[id.id()].width;
			case ElementID::Kind::gate: return gates[id.id()].width;
			case ElementID::Kind::output: return get_width(outputs[id.id()].value().id);
		}
	}

	void add_wire(WireEndpoint from, WireEndpoint to)
	{
		if(from.id.kind() == ElementID::Kind::output)
			throw std::runtime_error{"Output(" + std::to_string(from.id.id()) + ") can't be used as fanin"};

		switch(to.id.kind())
		{
			case ElementID::Kind::gate:
			{
				assert(to.id.id() < gates.size());
				Gate &gate = gates[to.id.id()];

				if(gate.num_fanins == gate.fanins.size())
					throw std::runtime_error{"GateID(" + std::to_string(to.id.id()) + ") already has max number of fanins"};

				to.pin = to.pin == uint8_t(-1) ? gate.num_fanins : to.pin;
				assert(to.pin < gate.fanins.size());
				gate.fanins[to.pin] = from;
				gate.num_fanins++;
				add_fanout(from.id, to);
			} break;

			case ElementID::Kind::output:
				if(outputs[to.id.id()])
					throw std::runtime_error{"Fanin of output is already specified"};

				to.pin = to.pin == uint8_t(-1) ? 0 : to.pin;
				assert(to.pin == 0);
				outputs[to.id.id()] = from;
				add_fanout(from.id, to);
				break;

			default:
				throw std::runtime_error{"Invalid element target for wire"};
		}
	}

	IteratorRange<WireEndpoint const*> get_fanins(ElementID id) const
	{
		switch(id.kind())
		{
			case ElementID::Kind::gate:
			{
				Gate const &gate = gates[id.id()];
				return {gate.fanins.data(), gate.fanins.data() + gate.fanins.size()};
			};

			case ElementID::Kind::output:
				if(outputs[id.id()])
				{
					WireEndpoint const *fanin = &*outputs[id.id()];
					return {fanin, fanin + 1};
				}
				else
					return {};

			default:
				return {};
		}
	}

	IteratorRange<WireEndpoint const*> get_fanouts(ElementID id) const
	{
		switch(id.kind())
		{
			case ElementID::Kind::gate:
			{
				Gate const &gate = gates[id.id()];
				return {gate.fanouts.data(), gate.fanouts.data() + gate.fanouts.size()};
			}

			case ElementID::Kind::input:
			{
				Input const &input = inputs[id.id()];
				return {input.fanouts.data(), input.fanouts.data() + input.fanouts.size()};
			}

			default:
				return {};
		}
	}


	OutputID add_output(WireEndpoint fanin)
	{
		OutputID oid{outputs.size()};
		outputs.push_back({});
		add_wire(fanin, primary_endpoint(oid));

		return oid;
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

		return inputs[it->second.inputs[0].value].party;
	}

	void add_input_variable(Party party, std::string const &name, std::vector<InputID> &&inputs)
	{
		assert(inputs.size());

		int width = inputs.size();
		auto ret = name_to_inputs.insert({name, {party, name, std::move(inputs), Type{BitsType{width}}}});
		ordered_inputs.push_back(&ret.first->second);

		// TODO Make sure all inputs belong to the same party
	}

	void add_input_variable(Party party, std::string const &name, InputID first, uint64_t width)
	{
		std::vector<InputID> inputs(width);
		iota_n(inputs.begin(), width, first);
		auto ret = name_to_inputs.insert({name, {party, name, std::move(inputs), Type{BitsType{(int)width}}}});
		ordered_inputs.push_back(&ret.first->second);

		// TODO Make sure all inputs belong to the same party
	}

	void add_input_variable(Party party, std::string const &name, std::vector<InputID> const &inputs, Type const &type)
	{
		auto ret = name_to_inputs.insert({name, {party, name, inputs, type}});
		ordered_inputs.push_back(&ret.first->second);

		// TODO Make sure all inputs belong to the same party
	}


	// OutputVariable ------------------------
	void add_output_variable(std::string const &name, std::vector<OutputID> &&outputs)
	{
		int width = outputs.size();
		auto ret = name_to_outputs.insert({name, {name, std::move(outputs), Type{BitsType{width}}}});
		ordered_outputs.push_back(&ret.first->second);
	}

	void add_output_variable(std::string const &name, std::vector<OutputID> const &outputs, Type const &type)
	{
		auto ret = name_to_outputs.insert({name, {name, outputs, type}});
		ordered_outputs.push_back(&ret.first->second);
	}

	void add_output_variable(std::string const &name, OutputID first, uint64_t width)
	{
		std::vector<OutputID> outputs(width);
		iota_n(outputs.begin(), width, first);
		auto ret = name_to_outputs.insert({name, {name, std::move(outputs), Type{BitsType{(int)width}}}});
		ordered_outputs.push_back(&ret.first->second);
	}

	size_t get_output_variable_width(std::string const &name)
	{
		auto it = name_to_outputs.find(name);
		if(it == name_to_outputs.end())
			throw std::runtime_error{"Invalid variable name: " + name};

		return it->second.outputs.size();
	}

private:
	void add_fanout(ElementID element, WireEndpoint fanout)
	{
		if(element.kind() == ElementID::Kind::output)
			throw std::runtime_error{"Output(" + std::to_string(element.id()) + ") can't have fanouts"};

		switch(element.kind())
		{
			case ElementID::Kind::gate:
			{
				assert(element.id() < gates.size());
				gates[element.id()].fanouts.push_back(fanout);
			} break;

			case ElementID::Kind::input:
				assert(element.id() < inputs.size());
				inputs[element.id()].fanouts.push_back(fanout);
				break;

			default:
				throw std::runtime_error{"Invalid element source for wire: " + str(element)};
		}
	}

public:


	// GateID -> Gate
	std::vector<Gate> gates;
	// OutputID -> input
	std::vector<optional<WireEndpoint>> outputs;
	// InputID -> Input
	std::vector<Input> inputs;

	std::vector<ElementID> zero_fanin_elements;
	std::unordered_map<std::string, InputVariable> name_to_inputs;
	std::unordered_map<std::string, OutputVariable> name_to_outputs;

	std::vector<InputVariable*> ordered_inputs;
	std::vector<OutputVariable*> ordered_outputs;

	struct FunctionCall
	{
		struct Arg { std::string name; Type type; std::vector<OutputID> outputs; };
		struct Return { std::string name; Type type; std::vector<InputID> inputs; };

		std::string name;
		std::vector<Arg> args;
		std::vector<Return> returns;
	};

	std::vector<FunctionCall> function_calls;

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

		// Make sure all gates have the correct number of fanins.
		switch(gate.kind)
		{
			case GateKind::one_gate:
			case GateKind::const_gate:
				if(gate.num_fanins != 0)
					throw std::runtime_error{"Invalid number of inputs: " + std::to_string(gate.num_fanins) + ", expected 0 (id=" + std::to_string(id) + ")"};
				break;

			case GateKind::and_gate:
			case GateKind::or_gate:
			case GateKind::xor_gate:
			case GateKind::add_gate:
			case GateKind::sub_gate:
			case GateKind::mul_gate:
				if(gate.num_fanins != 2)
					throw std::runtime_error{"Invalid number of inputs: " + std::to_string(gate.num_fanins) + ", expected 2 (id=" + std::to_string(id) + ")"};
				break;
			case GateKind::not_gate:
			case GateKind::neg_gate:
				if(gate.num_fanins != 1)
					throw std::runtime_error{"Invalid number of inputs: " + std::to_string(gate.num_fanins) + ", expected 1 (id=" + std::to_string(id) + ")"};
				break;
			case GateKind::combine_gate:
			case GateKind::split_gate:
				if(gate.num_fanins != gate.fanins.size())
					throw std::runtime_error{"Invalid number of inputs: " + std::to_string(gate.num_fanins) + " (id=" + std::to_string(id) + ")"};
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

using TraversalMarkMap = std::unordered_map<ElementID, SortingMark>;

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
		for(auto fanin: circ.get_fanins(cur_id))
			visit(circ, fanin.id, marks, std::forward<Func>(func));
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
void topological_traversal_from_element(Circuit const &circ, ElementID id, Func &&func)
{
	std::unordered_map<ElementID, SortingMark> marks;
	visit(circ, id, marks, std::forward<Func>(func));
}

}


#endif
