#include <catch/catch.hpp>

#include <util/symbol_table.h>

#include <cbmc-gc/simple_lexer.h>
#include <cbmc-gc/ir/dominators.h>

#include <unordered_map>
#include <unordered_set>


//==================================================================================================
namespace {

std::vector<cstring_ref> parse_node_list(lex_statet &lexer)
{
	std::vector<cstring_ref> nodes{read_identifier_skip_ws(lexer)};
	while(match_skip_ws(lexer, ","))
		nodes.push_back(read_identifier_skip_ws(lexer));

	return nodes;
}


using Graph = std::unordered_map<std::string, std::vector<std::string>>;
using NodeSet = std::unordered_set<std::string>;

void parse_edge(lex_statet &lexer, Graph &graph, NodeSet &nodes)
{
	std::vector<cstring_ref> nodes_from = parse_node_list(lexer);
	accept_skip_ws(lexer, "->");
	std::vector<cstring_ref> nodes_to = parse_node_list(lexer);
	accept_skip_ws(lexer, ";");

	for(cstring_ref const &from: nodes_from)
	{
		std::string from_str = str(from);
		nodes.insert(from_str);
		for(cstring_ref const &to: nodes_to)
		{
			std::string to_str = str(to);
			nodes.insert(to_str);
			graph[from_str].push_back(to_str);
		}
	}
}

void parse_graph(lex_statet &lexer, Graph &graph, NodeSet &nodes)
{
	while(has_more_skip_sw(lexer))
		parse_edge(lexer, graph, nodes);
}

using NameToBBMap = std::unordered_map<std::string, ir::BasicBlock*>;
std::pair<std::unique_ptr<ir::Function>, NameToBBMap> create_function(lex_statet &lexer, namespacet const &ns)
{
	Graph graph;
	NodeSet nodes;
	parse_graph(lexer, graph, nodes);

	std::unique_ptr<ir::Function> func{new ir::Function{"FUNC", nullptr, ns}};
	NameToBBMap name_to_bb{
		{"A", func->start_block()},
	};

	for(std::string const &name: nodes)
	{
		if(name != "A")
			name_to_bb[name] = func->create_block();
	}

	for(auto const &pair: graph)
	{
		ir::BasicBlock *bb = name_to_bb.at(pair.first);
		std::vector<std::string> const &bb_targets = pair.second;
		assert(bb_targets.size() <= 2);

		if(bb_targets.size() == 1)
			bb->create_jump(name_to_bb.at(bb_targets[0]));
		else if(bb_targets.size() == 2)
			bb->create_branch(func->get_constant(0, bool_typet{}), name_to_bb.at(bb_targets[0]), name_to_bb.at(bb_targets[1]));
	}

	func->update_blocks();
	return {std::move(func), std::move(name_to_bb)};
}


struct BasicBlockPostIDom
{
	ir::BasicBlock const *bb;
	ir::BasicBlock const *idom;
	std::vector<std::string> *bb_to_name;
};

bool operator == (BasicBlockPostIDom const &a, BasicBlockPostIDom const &b)
{
	return a.bb == b.bb && a.idom == b.idom;
}

std::ostream& operator << (std::ostream &os, BasicBlockPostIDom const &bp)
{
	return os << "PostIDom(\"" << bp.bb_to_name->at(bp.bb->id()) << "\") = \"" << bp.bb_to_name->at(bp.idom->id()) << "\"";
}

using IDomMap = std::unordered_map<std::string, std::string>;

void run_post_idom_test(cstring_ref graph_desc, IDomMap expected_post_idoms)
{
	symbol_tablet st;
	lex_statet lexer{graph_desc};
	std::unique_ptr<ir::Function> func;
	NameToBBMap name_to_bb;
	std::tie(func, name_to_bb) = create_function(lexer, namespacet{st});

	std::vector<std::string> bb_to_name(name_to_bb.size());
	for(auto const &pair: name_to_bb)
		bb_to_name[pair.second->id()] = pair.first;

	ir::DominatorTree dom_tree = compute_idoms(*func, ir::PostDominatorFuncs{});
	for(auto const &pair: expected_post_idoms)
	{
		ir::BasicBlock *bb = name_to_bb.at(pair.first);
		ir::BasicBlock *post_idom = name_to_bb.at(pair.second);

		BasicBlockPostIDom actual{bb, dom_tree.get_idom(bb), &bb_to_name};
		BasicBlockPostIDom expected{bb, post_idom, &bb_to_name};
		CHECK(actual == expected);
	}
}

}


TEST_CASE("IDom")
{
	run_post_idom_test(
	// CFG with a simple while loop
	R"#(
		A -> B;
		B -> C, D;
		C -> B;
	)#",
	// Immediate post-dominators
	{
		{"A", "B"},
		{"B", "D"},
		{"C", "B"},
	});


	run_post_idom_test(
	// CFG with a irreducible loop
	R"#(
		A -> B, C;
		B -> C;
		C -> B;
		C -> D;
	)#",
	// Immediate post-dominators
	{
		{"A", "C"},
		{"B", "C"},
		{"C", "D"},
	});
}
