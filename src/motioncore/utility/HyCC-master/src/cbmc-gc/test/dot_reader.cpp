#include "cbmc-gc/dot/dot_reader.h"

#include <catch/catch.hpp>


namespace {

using namespace internal;

using tokenst = std::vector<tokent>;

tokenst tokenize(lex_statet &lexer)
{
  std::vector<tokent> tokens;
  while(true)
  {
    tokens.push_back(next_token(lexer));
    if(tokens.back().kind == token_kindt::end)
      break;
  }

  return tokens;
}

std::vector<tokent> make_tokens(std::initializer_list<tokent> toks)
{
  return toks;
}


}


TEST_CASE("dot: parsing")
{
  lex_statet l1{R"END(
digraph 
{
  "\" a! \"" -> b;
  c -> b;
}
)END"};

  CHECK(tokenize(l1) == make_tokens({
    {token_kindt::digraph, "digraph", 2},
    {token_kindt::lbrace, "{", 3},
    {token_kindt::identifier, "\\\" a! \\\"", 4},
    {token_kindt::directed_edge_op, "->", 4},
    {token_kindt::identifier, "b", 4},
    {token_kindt::semicolon, ";", 4},
    {token_kindt::identifier, "c", 5},
    {token_kindt::directed_edge_op, "->", 5},
    {token_kindt::identifier, "b", 5},
    {token_kindt::semicolon, ";", 5},
    {token_kindt::rbrace, "}", 6},
    {token_kindt::end, "<END>", 7},
  }));
}


TEST_CASE("dot: attributes")
{
  parse_statet parser{R"%([label="hi du" shape = box] [color=black;color=red])%"};
  attr_listt expected{
    {"label", "hi du"},
    {"shape", "box"},
    {"color", "red"},
  };

  CHECK(parse_attr_list(parser) == expected);
}
