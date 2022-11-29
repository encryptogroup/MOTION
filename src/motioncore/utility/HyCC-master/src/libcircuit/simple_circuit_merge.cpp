#include "simple_circuit.h"
#include "utils.h"


namespace {

using GateRange = IteratorRange<simple_circuitt::gatet* const*>;

GateRange gate_range(std::vector<simple_circuitt::gatet*> const &gates)
{
	return {gates.data(), gates.data() + gates.size()};
}

simple_circuitt::gatet* find_combiner_fanout(simple_circuitt::gatet *gate)
{
	for(auto *fanout: gate->get_fanouts())
	{
		auto *fanout_gate = fanout->second.gate;
		if(fanout_gate->get_operation() == simple_circuitt::COMBINE)
			return fanout_gate;
	}

	return nullptr;
}

simple_circuitt::gatet* can_reuse_combiner(GateRange &outputs, int combiner_width)
{
	if(outputs.empty())
		return nullptr;

	auto local_outs = outputs;
	simple_circuitt::gatet *combiner = find_combiner_fanout((*local_outs.b)->fanin_range()[0].gate);
	if(!combiner)
		return nullptr;

	combiner_width -= (*local_outs.b)->get_width();
	++local_outs.b;
	while(!local_outs.empty() && combiner_width > 0)
	{
		if(find_combiner_fanout((*local_outs.b)->fanin_range()[0].gate) != combiner)
			return nullptr;

		combiner_width -= (*local_outs.b)->get_width();
		++local_outs.b;
	}
	assert(combiner_width == 0);

	while(outputs.b != local_outs.b)
	{
		(*outputs.b)->remove_fanin(0);
		++outputs.b;
	}

	return combiner;
}

simple_circuitt::gatet* create_combiner_for_outputs(simple_circuitt &circuit, GateRange &outputs, int width)
{
	if(auto combiner = can_reuse_combiner(outputs, width))
		return combiner;

	simple_circuitt::gatet *combiner = circuit.get_or_create_gate(simple_circuitt::COMBINE, width);
	int cur_width = 0;
	for(int i = 0; cur_width < width; ++i)
	{
		assert(!outputs.empty());

		assert(cur_width + (*outputs.b)->get_width() <= width);
		cur_width += (*outputs.b)->get_width();

		combiner->add_fanin((*outputs.b)->fanins[0], i);
		(*outputs.b)->remove_fanin(0);

		++outputs.b;
	}
	assert(cur_width == width);

	return combiner;
}

void connect_output_to_input(simple_circuitt &circuit, GateRange &outputs, GateRange &inputs)
{
	assert(!outputs.empty());
	assert(!inputs.empty());

	auto cur_output = *outputs.b;
	auto cur_input = *inputs.b;

	assert(cur_output->get_operation() == simple_circuitt::OUTPUT);
	assert(cur_input->get_operation() == simple_circuitt::INPUT);


	// If the width of the output is smaller than the width of the input we need to put a combining
	// gate between them.
	if(cur_output->get_width() < cur_input->get_width())
	{
		simple_circuitt::gatet *combiner = create_combiner_for_outputs(circuit, outputs, cur_input->get_width());
		cur_input->replace_by(combiner);
		inputs.b++;
	}
	// If the width of the output is greater than the width of the input we need to put a splitting
	// gate between them.
	else if(cur_output->get_width() > cur_input->get_width())
	{
		assert(cur_input->get_width() == 1);

		// TODO Reuse SPLIT gate if one is already present (like we do for COMBINE gates above)

		int output_width = cur_output->get_width();
		simple_circuitt::gatet *splitter = circuit.get_or_create_gate(simple_circuitt::SPLIT, cur_output->get_width());
		splitter->add_fanin(cur_output->fanins[0], 0);
		cur_output->remove_fanin(0);
		outputs.b++;

		for(int i = 0; i < output_width; ++i)
		{
			assert(!inputs.empty());
			cur_input = *inputs.b;

			cur_input->replace_pin_by(0, simple_circuitt::gatet::wire_endpointt{splitter, (unsigned)i});
			++inputs.b;
		}

	}
	// Otherwise, we can directly connect the output to the input.
	else
	{
		auto output_fanin = cur_output->fanins[0];
		cur_output->remove_fanin(0);
		cur_input->replace_by(output_fanin);

		outputs.b++;
		inputs.b++;
	}
}

int total_width(std::vector<simple_circuitt::gatet*> const &gates)
{
	int width = 0;
	for(auto g: gates)
		width += g->get_width();

	return width;
}

}

#include <fstream>
simple_circuitt::function_call_iterator simple_circuitt::merge_circuit(
	function_call_iterator call,
	simple_circuitt &&other)
{
	assert(call->args.size() + call->returns.size() == other.m_variables.size());

	other.ZERO_GATE->remove_fanin(0);
	other.ONE_GATE->replace_by(ONE_GATE);
	other.ZERO_GATE->replace_by(ZERO_GATE);

	// Connect the other's inputs with our corresponding outputs.
	for(auto const &output_var: call->args)
	{
		variablet const &other_var = other.m_variables.at(output_var.name);
		assert(other_var.owner != variable_ownert::output);
		assert(total_width(output_var.gates) == total_width(other_var.gates));

		auto output_gates = gate_range(output_var.gates);
		auto input_gates = gate_range(other_var.gates);
		while(output_gates.size() && input_gates.size())
			connect_output_to_input(*this, output_gates, input_gates);

		assert(output_gates.empty() && input_gates.empty());

		// Remove our now unused outputs
		for(auto gate: output_var.gates)
			remove_gate_from_list(gate);
	}

	// Connect the other's outputs with our corresponding inputs.
	for(auto const &input_var: call->returns)
	{
		variablet const &other_var = other.m_variables.at(input_var.name);
		assert(other_var.owner == variable_ownert::output);
		assert(total_width(input_var.gates) == total_width(other_var.gates));

		auto output_gates = gate_range(other_var.gates);
		auto input_gates = gate_range(input_var.gates);
		while(output_gates.size() && input_gates.size())
			connect_output_to_input(*this, output_gates, input_gates);

		assert(output_gates.empty() && input_gates.empty());

		// Remove our now unused inputs
		for(auto gate: input_var.gates)
			remove_gate_from_list(gate);
	}


	// Take the other's gates
	if(other.gates_HEAD)
	{
		if(gates_TAIL)
		{
			other.gates_HEAD->previous = gates_TAIL;
			gates_TAIL->next = other.gates_HEAD;
            gates_TAIL = other.gates_TAIL;
		}
		else
		{
			gates_HEAD = other.gates_HEAD;
			gates_TAIL = other.gates_TAIL;
		}

		gates_SIZE += other.gates_SIZE;
	}

    for(auto other_root_gate: other.m_root_gates)
    {
      if(other_root_gate->operation != INPUT && other_root_gate->operation != ONE)
        m_root_gates.insert(other_root_gate);
    }

	other.gates_HEAD = nullptr;
	other.gates_TAIL = nullptr;
	other.gates_SIZE = 0;

	return m_function_calls.erase(call);
}

namespace {

struct is_call_to
{
  is_call_to(cstring_ref name) :
    name{name} {}

  bool operator () (simple_circuitt::function_callt const &call) const
  {
    return name == call.name;
  }

  cstring_ref name;
};

}

bool simple_circuitt::merge_circuit_if_called(simple_circuitt &&other)
{
	int num_calls = count_if(m_function_calls, is_call_to{other.m_name});

	if(num_calls == 1)
    {
      m_logger->info() << "Merging " << other.m_name << eom;
      merge_circuit(find_if(m_function_calls, is_call_to{other.m_name}), std::move(other));

      return true;
    }
    else if(num_calls > 1)
    {
      auto cur = m_function_calls.cbegin();
      int counter = 0;
      while(cur != m_function_calls.cend() && counter < num_calls - 1)
      {
        if(cur->name == other.m_name)
        {
          m_logger->info() << "Merging " << other.m_name << " (" << (counter+1) << "/" << num_calls << ")" << eom;
          cur = merge_circuit(cur, simple_circuitt{other});
          ++counter;
        }
        else
          ++cur;
      }

      m_logger->info() << "Merging " << other.m_name << " (" << (counter+1) << "/" << num_calls << ")" << eom;
      merge_circuit(std::find_if(cur, m_function_calls.cend(), is_call_to{other.m_name}), std::move(other));

      return true;
    }

    return false;
}

void simple_circuitt::merge_circuit(simple_circuitt &&other)
{
  if(!merge_circuit_if_called(std::move(other)))
    throw std::runtime_error{"merging circuits failed: circuit does not call \"" + other.m_name + "\""};
}
