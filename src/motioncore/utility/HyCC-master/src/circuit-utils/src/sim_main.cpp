#include <circuit-utils/circuit.hpp>
#include <circuit-utils/circuit_io.hpp>
#include <circuit-utils/circuit_simulation.hpp>

#include <iostream>
#include <sstream>
#include <fstream>


struct Options
{
	std::string circuit_path = ".";
	circ::CircuitFileFormat circuit_format = circ::CircuitFileFormat::cbmc_gc;

	optional<std::string> spec_inline;
	optional<std::string> spec_file;
	bool debug_output = false;
};

std::string drain_stream(std::istream &is)
{
	std::stringstream ss;
	is >> ss.rdbuf();
	return ss.str();
}

std::vector<Spec> create_specs(circ::Circuit const &c, Options const &opts)
{
	SymbolTable table = create_symbol_table(c);
	std::vector<Spec> specs;
	if(opts.spec_inline)
	{
		ParseState parser{opts.spec_inline->c_str(), "<command-line-spec>"};
		auto inline_specs = parse_spec_list(parser, table);

		for(auto &s: inline_specs)
			specs.push_back(std::move(s));
	}

	if(opts.spec_file)
	{
		std::ifstream f{*opts.spec_file};
		if(!f.is_open())
			throw std::runtime_error{"Filed to open spec file"};
		
		auto source = drain_stream(f);
		ParseState parser{source.c_str(), *opts.spec_file};
		auto file_specs = parse_spec_list(parser, table);

		for(auto &s: file_specs)
			specs.push_back(std::move(s));
	}

	return specs;
}

Options parse_options(int argc, char *argv[])
{
	Options opts;
	for(int i = 1; i < argc; ++i)
	{
		if(std::strcmp(argv[i], "--spec") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected circuit specification"};

			opts.spec_inline = argv[i];
		}
		else if(std::strcmp(argv[i], "--spec-file") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected circuit specification file"};

			opts.spec_file = argv[i];
		}
		else if(std::strcmp(argv[i], "--debug") == 0)
			opts.debug_output = true;
		else if(std::strcmp(argv[i], "--bristol") == 0)
			opts.circuit_format = circ::CircuitFileFormat::bristol;
		else
		{
			if(argv[i][0] == '-')
				throw std::runtime_error{std::string{"Invalid option: "} + argv[i]};

			opts.circuit_path = argv[i];
		}
	}

	return opts;
}

bool inputs_are_specified(EvaluationContext &ctx)
{
	int num_inputs = 0;
	int num_inputs_set = 0;

	ctx.for_each_variable([&](std::string const &name, optional<TypedValue> const &val)
	{
		if(name.compare(0, 6, "INPUT_") == 0)
		{
			num_inputs++;
			if(val)
			num_inputs_set++;
		}
	});

	if(num_inputs_set)
	{
		if(num_inputs_set != num_inputs)
			throw std::runtime_error{"Not all inputs are set."};

		return true;
	}

	return false;
}


int main(int argc, char *argv[])
{
	try
	{
		auto opts = parse_options(argc, argv);
		auto circuit = circ::read_circuit(opts.circuit_path, opts.circuit_format);

		auto ctx = create_context(circuit);
		auto specs = create_specs(circuit, opts);
		for(auto &spec: specs)
		{
			for(auto &stmt: spec.before)
				stmt->evaluate(ctx);

			// TODO If OUTPUT depends solely on constants then no inputs are specified but we still want to
			// run the simulation.
			//if(inputs_are_specified(ctx))
			{
				// Set inputs
				std::unordered_map<std::string, TypedValue> input_values;
				for(auto const &input: circuit.name_to_inputs)
					input_values[input.first] = *ctx.get(input.first);

				// Run circuit and and write result to OUTPUT variables
				auto bit_values = circ::simulate(circuit, input_values);
				for(auto const &output: circuit.name_to_outputs)
				{
					auto &output_spec = ctx.get(output.first).value();
					auto bit_width_in_circuit = get_bit_width(output.second.type);
					auto bit_width_of_var = get_bit_width(output_spec.type);
					if(bit_width_in_circuit != bit_width_of_var)
					{
						throw std::runtime_error{
							"Number of output bits (" + std::to_string(bit_width_in_circuit) + ") different from type"
								" bit width (" + std::to_string(bit_width_of_var) + ")"};
					}
					assign(output_spec, circ::extract_output_value(output.second, bit_values));
				}


				/*if(opts.debug_output)
				{
					for(auto const &msg: circuit.debug_messages)
					{
						std::cout << "Debug: " << msg.message << ": ";
						circ::TypedValue val{msg.type, circ::extract_value(msg.data, bit_values)};
						std::cout << val << ':' << val.type;
						val.type = circ::Type{circ::BitsType{get_bit_width(val.type)}};
						std::cout << " = 0b" << val << std::endl;
					}
				}*/
			}


			for(auto &stmt: spec.after)
				stmt->evaluate(ctx);
		}
	}
	catch(std::exception const &e)
	{
		std::cerr << e.what() << std::endl;
		return 1;
	}
}

