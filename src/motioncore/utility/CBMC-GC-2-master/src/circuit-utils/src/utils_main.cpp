#include <circuit-utils/circuit.hpp>
#include <circuit-utils/circuit_io.hpp>

#include <iostream>
#include <fstream>


using circ::optional;
using circ::nullopt;


//==================================================================================================
namespace circ {

std::string unique_var()
{
	static int counter = 0;
	return "t" + std::to_string(counter++);
}


//------------------------------------------------------------------------------
void generate_random_assignment(std::ostream &os, Type const &type, std::string const &path)
{
	switch(type.kind())
	{
		case TypeKind::bits:
			throw std::runtime_error{"Random assignment of bits not yet supported"};
			break;

		case TypeKind::integer:
		{
			os << path << " = random_int<" << type << "_t>(rd);\n";
		} break;

		case TypeKind::array:
		{
			auto array_type = get_array_type(type);
			auto loop_var = unique_var();
			os << "for(size_t " << loop_var << " = 0; " << loop_var << " < " << array_type->length << "; ++" << loop_var << ") {\n";
			generate_random_assignment(os, *array_type->sub, path + "[" + loop_var + "]");
			os << "}\n";
		} break;

		case TypeKind::structure:
		{
			auto struct_type = get_struct_type(type);
			for(auto &m: struct_type->members)
				generate_random_assignment(os, *m.second, path + "." + m.first);
		} break;
	}
}

void generate_random_assignment_function(std::ostream &os, Party p, Type const &type)
{
	std::string type_name = p == Party::alice ? "InputA" : "InputB";
	os << type_name << " ";

	os << "generate_" << type_name << "(std::mt19937 &rd)\n{\n" << type_name << " in;\n";
	generate_random_assignment(os, type, "in");
	os << "return in;\n}\n";
}


//------------------------------------------------------------------------------
void generate_output_comparer(std::ostream &os, Type const &type, std::string const &path)
{
	switch(type.kind())
	{
		case TypeKind::bits:
			throw std::runtime_error{"Comparison of bits not yet supported"};
			break;

		case TypeKind::integer:
		{
			os << "if((*a)" << path << " != (*b)" << path << ") return false;\n";
		} break;

		case TypeKind::array:
		{
			auto array_type = get_array_type(type);
			auto loop_var = unique_var();
			os << "for(size_t " << loop_var << " = 0; " << loop_var << " < " << array_type->length << "; ++" << loop_var << ") {\n";
			generate_output_comparer(os, *array_type->sub, path + "[" + loop_var + "]");
			os << "}\n";
		} break;

		case TypeKind::structure:
		{
			auto struct_type = get_struct_type(type);
			for(auto &m: struct_type->members)
				generate_output_comparer(os, *m.second, path + "." + m.first);
		} break;
	}
}

void generate_output_comparer_function(std::ostream &os, Type const &type)
{
	os << "bool outputs_equal(Output const *a, Output const *b)\n{\n";
	generate_output_comparer(os, type, "");
	os << "\treturn true;\n}\n";
}


//------------------------------------------------------------------------------
void generate_printer_for_type(std::ostream &os, Type const &type, std::string const &path)
{
	switch(type.kind())
	{
		case TypeKind::bits:
			throw std::runtime_error{"Random assignment of bits not yet supported"};
			break;

		case TypeKind::integer:
		{
			os << "std::cout << \"" << path << " = \" << " << path << " << '\\n';";
		} break;

		case TypeKind::array:
		{
			auto array_type = get_array_type(type);
			auto loop_var = unique_var();
			os << "for(size_t " << loop_var << " = 0; " << loop_var << " < " << array_type->length << "; ++" << loop_var << ") {\n";
			generate_printer_for_type(os, *array_type->sub, path + "[" + loop_var + "]");
			os << "}\n";
		} break;

		case TypeKind::structure:
		{
			auto struct_type = get_struct_type(type);
			for(auto &m: struct_type->members)
				generate_printer_for_type(os, *m.second, path + "." + m.first);
		} break;
	}
}

enum class VariableType
{
	input_a,
	input_b,
	output,
};

void generate_printer(std::ostream &os, VariableType vt, Type const &type)
{
	std::string type_name = vt == VariableType::input_a ? "InputA" : vt == VariableType::input_b ? "InputB" : "Output";
	std::string var_name = vt == VariableType::input_a ? "input_a" : vt == VariableType::input_b ? "input_b" : "output";

	os << "void print_" << type_name << "(" << type_name << " " << var_name << ")\n{\n";
	generate_printer_for_type(os, type, var_name);
	os << "\n}\n";
}

}


//==================================================================================================
struct ConversionTarget
{
	std::string filename;
	circ::CircuitFileFormat format;
};

struct Options
{
	std::string circuit_path = ".";
	circ::CircuitFileFormat circuit_format = circ::CircuitFileFormat::cbmc_gc;
  bool make_or_free = false;

	optional<std::string> verifier_output_file;
	optional<std::string> tester_output_file;

	optional<std::string> reference_file;
	optional<std::string> input_constraints_file;

  

	optional<ConversionTarget> convert;
};

Options parse_options(int argc, char *argv[])
{
	Options opts;
	for(int i = 1; i < argc; ++i)
	{
		if(std::strcmp(argv[i], "-f") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected circuit path"};

			opts.circuit_path = argv[i];
		}
		else if(std::strcmp(argv[i], "--create-verifier") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected output filename"};

			opts.verifier_output_file = argv[i];
		}
		else if(std::strcmp(argv[i], "--create-tester") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected output filename"};

			opts.tester_output_file = argv[i];
		}
		else if(std::strcmp(argv[i], "--reference") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected input filename"};

			opts.reference_file = argv[i];
		}
		else if(std::strcmp(argv[i], "--input-constraints") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected input filename"};

			opts.input_constraints_file = argv[i];
		}
		else if(std::strcmp(argv[i], "--remove-or-gates") == 0)
		{
			opts.make_or_free = true;
		}		
		else if(std::strcmp(argv[i], "--bristol") == 0)
			opts.circuit_format = circ::CircuitFileFormat::bristol;
		else if(std::strcmp(argv[i], "--as-bristol") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected output filename"};

			opts.convert = {argv[i], circ::CircuitFileFormat::bristol};
		}
		else if(std::strcmp(argv[i], "--as-shdl") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected output filename"};

			opts.convert = {argv[i], circ::CircuitFileFormat::shdl};
		}
		else if(std::strcmp(argv[i], "--as-scd") == 0)
		{
			if(++i == argc)
				throw std::runtime_error{"Expected output filename"};

			opts.convert = {argv[i], circ::CircuitFileFormat::scd};
		}
		else
			throw std::runtime_error{std::string{"Invalid option: "} + argv[i]};
	}

	return opts;
}

void create_verifier(Options const &opts)
{
	auto circuit = circ::read_circuit(opts.circuit_path, opts.circuit_format);

	if(!opts.reference_file)
		throw std::runtime_error{"Reference implementation required"};

	std::ofstream file{*opts.verifier_output_file};
	file << "#include <inttypes.h>\n#include <string.h>\n\n";
	file << "#include \"" << *opts.reference_file << "\"\n";
	if(opts.input_constraints_file)
		file << "#include \"" << *opts.input_constraints_file << "\"\n";
	file << '\n';
	circ::to_c_code(file, circuit, "run_circuit");

	file << R"EOC(

int main()
{
	InputA alice;
	InputB bob;

)EOC";

	if(opts.input_constraints_file)
		file << "\t__CPROVER_assume(is_valid_input(alice, bob));\n";

	file << R"EOC(
	__CPROVER_assert(
		run_circuit(alice, bob) == mpc_main(alice, bob),
		"verifying circuit"
	);
}
)EOC";
}

void create_tester(Options const &opts)
{
	auto circuit = circ::read_circuit(opts.circuit_path, opts.circuit_format);

	if(!opts.reference_file)
		throw std::runtime_error{"Reference implementation required"};

	std::ofstream file{*opts.tester_output_file};
	file << "#include <inttypes.h>\n#include <string.h>\n#include <iostream>\n#include <random>\n#include <limits>\n";
	file << "\ntypedef bool _Bool;\n";
	file << "#include \"" << *opts.reference_file << "\"\n";
	if(opts.input_constraints_file)
		file << "#include \"" << *opts.input_constraints_file << "\"\n";
	circ::to_c_code(file, circuit, "run_circuit");

	file << R"EOC(
template<typename T>
T random_int(std::mt19937 &rd)
{
	std::uniform_int_distribution<T> dist{std::numeric_limits<T>::min(), std::numeric_limits<T>::max()};
	return dist(rd);
}
)EOC";

	circ::InputVarIterator alice_it, bob_it;
	std::tie(alice_it, bob_it) = circ::get_alice_and_bob(circuit);
	generate_random_assignment_function(file, circ::Party::alice, alice_it->second.type);
	generate_random_assignment_function(file, circ::Party::bob, bob_it->second.type);

	generate_printer(file, circ::VariableType::input_a, alice_it->second.type);
	generate_printer(file, circ::VariableType::input_b, bob_it->second.type);

	circ::OutputVariable out_var = circ::get_single_output(circuit);
	generate_printer(file, circ::VariableType::output, out_var.type);
	generate_output_comparer_function(file, out_var.type);

	file << R"EOC(

std::pair<InputA, InputB> generate_inputs(std::mt19937 &rd)
{
	while(true)
	{
		InputA alice = generate_InputA(rd);
		InputB bob = generate_InputB(rd);
		
)EOC";

	if(opts.input_constraints_file)
		file << "		if(is_valid_input(alice, bob)) return {alice, bob};\n";
	else
		file << "		return {alice, bob};\n";

	file << "	}\n}\n\n";

	file << R"EOC(
int main()
{
	std::random_device rd;
	std::mt19937 mt{rd()};
	int num_iterations = 10000;
	int num_errors = 0;

	for(int i = 0; i < num_iterations; ++i)
	{
		std::pair<InputA, InputB> inputs = generate_inputs(mt);
		Output expected = mpc_main(inputs.first, inputs.second);
		Output actual = run_circuit(inputs.first, inputs.second);
		if(!outputs_equal(&actual, &expected))
		{
			num_errors++;
			print_InputA(inputs.first);
			print_InputB(inputs.second);
			std::cout << "Expected: "; print_Output(expected); std::cout << std::endl;
			std::cout << "Actual: "; print_Output(actual); std::cout << std::endl;
		}
	}

	std::cout << num_iterations << " runs, " << num_errors << " errors." << std::endl;

	return num_errors != 0;
}
)EOC";
}


//==================================================================================================
int main(int argc, char *argv[])
{
	try
	{
		auto opts = parse_options(argc, argv);

		if(opts.verifier_output_file)
			create_verifier(opts);
		if(opts.tester_output_file)
			create_tester(opts);
		if(opts.convert)
		{
			auto circuit = circ::read_circuit(opts.circuit_path, opts.circuit_format);
			
			// Remove all OR gates, as not all frameworks support OR gate
			if(opts.make_or_free) {
				circ::remove_or_gates(circuit);
			}
			
			switch(opts.convert->format)
			{
				case circ::CircuitFileFormat::bristol:
					circ::write_bristol_circuit(circuit, opts.convert->filename);
					break;
				case circ::CircuitFileFormat::shdl:
					circ::write_shdl_circuit(circuit, opts.convert->filename);
					break;
				case circ::CircuitFileFormat::scd:
					circ::write_scd_circuit(circuit, opts.convert->filename);
					break;
				default:
					throw std::runtime_error{"Invalid conversion target format"};
			}
		}
	}
	catch(std::exception const &e)
	{
		std::cerr << e.what() << std::endl;
		return 1;
	}
}

