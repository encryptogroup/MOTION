#include <libcircuit/parallel_execution_graph.h>
#include <cbmc-gc/dot/dot_reader.h>
#include <cbmc-gc/goto_conversion_invocation.h>
#include <cbmc-gc/ssa_to_circuit/ssa_to_circuit.h>

#include <cbmc/src/util/cmdline.h>

#include <catch/catch.hpp>

#include <fstream>


namespace {

class pe_graph_readert : public dot_readert
{
public:
  virtual void graph_begin(dot_graph_kindt kind, cstring_ref /*name*/, bool /*strict*/) override
  {
    assert(kind == dot_graph_kindt::directed);
  }

  virtual void node(cstring_ref name, attr_listt const &attrs) override
  {
    // Function call block
    if(attrs.count("func_name"))
    {
      int id = atoi(name.b);

      int closest_input_depth = stoi(attrs.at("gate_depth"));
      int call_id = stoi(attrs.at("call_id"));
      m_dot_id_to_block[id] = m_graph.add_call_block(
        closest_input_depth, call_id, attrs.at("func_name"),
        {} // TODO Add block_inputst
      );
    }
    // Gate block
    else
    {
      int closest_input_depth = stoi(attrs.at("input_depth"));
      int non_linear_height = stoi(attrs.at("non_linear_height"));

      if(name == "root")
        m_graph.root()->set_non_linear_height(non_linear_height);
      else if(name == "leaf")
        m_graph.leaf()->set_non_linear_height(non_linear_height);
      else
      {
        depth_sett output_depths;
        for_each_piece(attrs.at("output_depths"), ',', [&](cstring_ref depth)
        {
          output_depths.insert(atoi(depth.b));
        });

        int id = atoi(name.b);

        auto *block = m_graph.get_gate_block(closest_input_depth, output_depths);
        block->set_non_linear_height(non_linear_height);

        m_dot_id_to_block[id] = block;
      }
    }
  }

  virtual void edge(cstring_ref from, cstring_ref to, attr_listt const &/*attrs*/) override
  {
    m_edges.push_back({str(from), str(to)});
  }


  parallel_execution_grapht finalize()
  {
    for(auto const &edge: m_edges)
    {
      auto *from = id_to_block(edge.first);
      auto *to = id_to_block(edge.second);

      to->add_fanin(from);
    }

    m_dot_id_to_block.clear();
    m_edges.clear();

    auto tmp = std::move(m_graph);
    m_graph = {};

    return tmp;
  }

private:
  parallel_execution_grapht m_graph;
  std::unordered_map<int, execution_blockt*> m_dot_id_to_block;
  std::vector<std::pair<std::string, std::string>> m_edges;

  execution_blockt* id_to_block(std::string const &id)
  {
    if(id == "root")
      return m_graph.root();

    if(id == "leaf")
      return m_graph.leaf();

    return m_dot_id_to_block.at(stoi(id));
  }
};


simple_circuitt compile_circuit(
  std::string const &filename,
  std::initializer_list<std::string> external_calls = {})
{
  cmdlinet args;
  args.args.push_back(filename);

  ui_message_handlert msg_handler{args, "test"};
  msg_handler.set_verbosity(messaget::M_ERROR);

  goto_modulet module = invoke_goto_compilation(args, msg_handler);
  for(auto const &func_name: external_calls)
    module.make_external_call(func_name);

  module.options().set_option("minimize-circuit", false);

  messaget msg{msg_handler};

  return compile_function(
    circuit_target_kindt::boolean,
    module.main_function(),
    module,
    msg);
}

parallel_execution_grapht create_graph_from_dot(std::string const &filename)
{
  pe_graph_readert reader;
  read_dot(std::ifstream{filename}, reader);
  return reader.finalize();
}

void run_test(std::string const &dir, std::initializer_list<std::string> external_calls)
{
  auto expected_graph = create_graph_from_dot(dir + "/expected_graph.dot");

  simple_circuitt circuit = compile_circuit(dir + "/main.c", external_calls);
  auto actual_graph = build_parallel_execution_graph(circuit);

  to_dot(std::ofstream{dir + "/actual_graph.dot"}, actual_graph);
  CHECK(equivalent(expected_graph, actual_graph));
}

}


//==================================================================================================
TEST_CASE("parallel execution graph")
{
  register_languages();

  run_test("parallel_execution_graph_1", {"add", "mul"});
  run_test("parallel_execution_graph_2", {"mul"});
  run_test("parallel_execution_graph_3", {"mul"});
  run_test("parallel_execution_graph_4", {"add", "mul"});
  run_test("parallel_execution_graph_5", {"mul"});
}
