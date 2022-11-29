#include <iostream>
#include <fstream>
#include <unordered_map>
#include <unordered_set>
#include <stack>

#include <unistd.h>

#include <libcircuit/simple_circuit.h>
#include <libcircuit/parallel_execution_graph.h>


bool file_exists(std::string const &filename)
{
	return ::access(filename.c_str(), F_OK) != -1;
}

std::pair<std::string, std::string> split_path_filename(std::string const &filepath)
{
	std::string::size_type last_slash = filepath.rfind("/");
	if(last_slash == std::string::npos)
		return {".", filepath};

	return {filepath.substr(0, last_slash), filepath.substr(last_slash + 1)};
}

template<typename T>
void repeat(std::ostream &os, T const &v, int n, char const *sep = ",")
{
	if(n > 0)
	{
		os << v;
		while(--n)
			os << sep << v;
	}
}


enum CircuitKind
{
	BOOL_SIZE = 0,
	BOOL_DEPTH,
	ARITH
};

char const *cstr_human(CircuitKind kind)
{
	switch(kind)
	{
		case CircuitKind::BOOL_SIZE: return "boolean (size optimized)";
		case CircuitKind::BOOL_DEPTH: return "boolean (depth optimized)";
		case CircuitKind::ARITH: return "arithmetic";
	}
}

struct Stats
{
	simple_circuitt::statst stats;

	// Stores for each level of the circuit the number of non-linear gates
	std::vector<int> non_linear_gates_per_level;
};

struct CircuitInfo
{
	std::string name;

	size_t input_bit_width = 0;
	size_t output_bit_width = 0;

	// Stats for BOOL_SIZE, BOOL_DEPTH and/or ARITH
	std::vector<std::pair<CircuitKind, Stats>> stats;
	
	// Stores the names of the sub-circuits and how often they are called
	std::vector<std::pair<std::string, int>> sub_circuits;
};

Stats const* find_stats(std::vector<std::pair<CircuitKind, Stats>> const &stats, CircuitKind kind)
{
	for(auto const &pair: stats)
	{
		if(pair.first == kind)
			return &pair.second;
	}

	return nullptr;
}

Stats create_stats(simple_circuitt const &circuit)
{
	Stats stats;
	simple_circuitt::simple_circuit_level_sett level_set;
	stats.stats = circuit.query_stats(&level_set);

	for(auto const &pair: level_set)
		stats.non_linear_gates_per_level.push_back(pair.second.num_mul_gates + pair.second.num_and_gates);

	return stats;
}

bool fill_info_for_kind(CircuitInfo &info, std::string const &base_name, CircuitKind kind, loggert &log)
{
	static char const* kind_to_ext[] = {
		"@bool_size",
		"@bool_depth",
		"@arith",
	};

	std::string filename = base_name + kind_to_ext[kind] + ".circ";
	if(!file_exists(filename))
		return false;

	std::cout << "Loading " << filename << std::endl;
	simple_circuitt circuit = read_circuit(filename, log);
	info.stats.push_back({kind, create_stats(circuit)});

	parallel_execution_grapht call_graph = build_parallel_execution_graph(circuit);
	to_dot(std::ofstream{base_name + kind_to_ext[kind] + ".dot"}, call_graph);


	// The first call of fill_info_for_kind() for specific CircuitInfo fills in some extra info
	if(info.name.empty())
	{
		info.name = circuit.name();

		std::unordered_map<std::string, int> call_counts;
		for(simple_circuitt::function_callt const &call: circuit.function_calls())
			call_counts[call.name] += 1;

		info.sub_circuits.assign(call_counts.begin(), call_counts.end());

		for(simple_circuitt::variablet const &var: circuit.variables())
		{
			if(var.owner == variable_ownert::output)
				info.output_bit_width += get_bit_width(var.type);
			else
				info.input_bit_width += get_bit_width(var.type);
		}
	}

	return true;
}

CircuitInfo get_info(std::string const &base_path, std::string const &circuit_name, loggert &log)
{
	CircuitInfo info;

	std::string const &base_name = base_path + "/" + circuit_name;
	bool exists = fill_info_for_kind(info, base_name, CircuitKind::BOOL_SIZE, log);
	exists |= fill_info_for_kind(info, base_name, CircuitKind::BOOL_DEPTH, log);
	exists |= fill_info_for_kind(info, base_name, CircuitKind::ARITH, log);

	if(!exists)
		throw std::runtime_error{"Circuit file not found for " + circuit_name};

	return info;
}


std::string get_circuit_name(std::string filename)
{
	// Remove ".circ" file extension
	if(ends_with(filename, ".circ"))
		filename = filename.substr(0, filename.size() - 5);

	std::string::size_type at = filename.rfind("@");
	if(at != std::string::npos)
		filename = filename.substr(0, at);

	return filename;
}


void output_human(std::ostream &os, std::unordered_map<std::string, CircuitInfo> const &circuit_info_by_name)
{
	for(auto const &pair: circuit_info_by_name)
	{
		CircuitInfo const &info = pair.second;
		os  << "Circuit '" << info.name << "':\n"
			<< "  - input width: " << info.input_bit_width << " bits\n"
			<< "  - output width: " << info.output_bit_width << " bits\n"
			<< "  - stats:\n";


		for(auto const &pair: info.stats)
		{
			CircuitKind kind = pair.first;
			simple_circuitt::statst const &stats = pair.second.stats;
			os << "    - " << cstr_human(kind) << ": ";

			if(kind == CircuitKind::ARITH)
				os << "mul gates = " << stats.num_mul_gates << ", mul depth = " << stats.mul_depth << '\n';
			else
				os << "non-XOR gates = " << stats.num_non_xor_gates << ", non-XOR depth = " << stats.non_xor_depth << '\n';
		}

		if(info.sub_circuits.size())
		{
			os << "  - sub-circuits:\n";
			for(auto const &pair: info.sub_circuits)
				os << "    - " << pair.second << "x '" << pair.first << "'\n";
		}

		os << '\n';
	}
}


void output_csv(std::ostream &os, std::unordered_map<std::string, CircuitInfo> const &circuit_info_by_name)
{
	// Each line contains the following information:
	//
	// "func_name", input_width, output_width, yao_size, bool_size, bool_depth, arith_size, arith_depth,
	// "called_func_1;called_func_2;...", layer_0_num_AND_gates;layer_1_num_AND_gates;..., layer_0_num_MUL_gates;layer_1_num_MUL_gates;...
	//
	// (Function names are in quotes because they may contain commas if they are specialized)

	for(auto const &pair: circuit_info_by_name)
	{
		CircuitInfo const &info = pair.second;
		os  << '"' << info.name << "\"," << info.input_bit_width << "," << info.output_bit_width;

		int size_opt_size = 0;
		if(Stats const *s = find_stats(info.stats, CircuitKind::BOOL_SIZE))
			size_opt_size = s->stats.num_non_xor_gates;

		int depth_opt_size = 0;
		int depth_opt_depth = 0;
		std::vector<int> const *depth_opt_layers = nullptr;
		if(Stats const *s = find_stats(info.stats, CircuitKind::BOOL_DEPTH))
		{
			depth_opt_size = s->stats.num_non_xor_gates;
			depth_opt_depth = s->stats.non_xor_depth;
			depth_opt_layers = &s->non_linear_gates_per_level;
		}

		int arith_size = 0;
		int arith_depth = 0;
		std::vector<int> const *arith_layers = nullptr;
		if(Stats const *s = find_stats(info.stats, CircuitKind::ARITH))
		{
			arith_size = s->stats.num_mul_gates;
			arith_depth = s->stats.mul_depth;
			arith_layers = &s->non_linear_gates_per_level;
		}

		os  << "," << size_opt_size << "," << depth_opt_size << "," << depth_opt_depth
			<< "," << arith_size << "," << arith_depth;


		// Output called functions
		os << ",\"";
		if(info.sub_circuits.size())
		{
			repeat(os, info.sub_circuits[0].first, info.sub_circuits[0].second, ";");
			for(size_t i = 1; i < info.sub_circuits.size(); ++i)
			{
				os << ";";
				repeat(os, info.sub_circuits[i].first, info.sub_circuits[i].second, ";");
			}
		}
		os << '"';


		// Output non-linear gates of each layer
		os << ",";
		if(depth_opt_layers && depth_opt_layers->size())
		{
			os << (*depth_opt_layers)[0];
			for(size_t i = 1; i < depth_opt_layers->size(); ++i)
			os << ";" << (*depth_opt_layers)[i];
		}

		os << ",";
		if(arith_layers && arith_layers->size())
		{
			os << (*arith_layers)[0];
			for(size_t i = 1; i < arith_layers->size(); ++i)
			os << ";" << (*arith_layers)[i];
		}


		os << '\n';
	}
}


int main(int argc, char *argv[])
{
	if(argc != 2)
	{
		std::cerr << "Usage: callstack <main-circuit-file>" << std::endl;
		return 1;
	}

	loggert log;
	log.add_target<default_log_targett>();

	std::string base_path;
	std::string main_circuit_file;
	std::tie(base_path, main_circuit_file) = split_path_filename(argv[1]);
	std::string main_circuit_name = get_circuit_name(main_circuit_file);

	std::unordered_map<std::string, CircuitInfo> circuit_info_by_name;

	std::stack<std::string> work_list;
	work_list.push(main_circuit_name);

	while(!work_list.empty())
	{
		auto circuit_name = work_list.top(); work_list.pop();

		CircuitInfo info = get_info(base_path, circuit_name, log);
		circuit_info_by_name[circuit_name] = info;

		for(auto const &pair: info.sub_circuits)
			work_list.push(pair.first);
	}


	//output_human(std::cout, circuit_info_by_name);
	output_csv(std::cout, circuit_info_by_name);
}
