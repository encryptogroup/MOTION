#include "dot_reader.h"

#include <unordered_set>


//==================================================================================================
namespace internal {

void skip_irrelevant(lex_statet &lexer)
{
  while(true)
  {
    skip_whitespaces(lexer);
    if(match(lexer, "//"))
    {
      while(lexer && lexer.get() != '\n')
        lexer.next();

      lexer.next();
    }
    else
      break;
  }
}


//==================================================================================================
char const* cstr(token_kindt kind)
{
  switch(kind)
  {
    case token_kindt::identifier: return "IDENTIFIER";
    case token_kindt::strict: return "STRICT";
    case token_kindt::graph: return "GRAPH";
    case token_kindt::digraph: return "DIGRAPH";
    case token_kindt::subgraph: return "SUBGRAPH";
    case token_kindt::node: return "NODE";
    case token_kindt::edge: return "EDGE";
    case token_kindt::lbrace: return "LBRACE";
    case token_kindt::rbrace: return "RBRACE";
    case token_kindt::lbracket: return "LBRACKET";
    case token_kindt::rbracket: return "RBRACKET";
    case token_kindt::assign: return "ASSIGN";
    case token_kindt::comma: return "COMMA";
    case token_kindt::semicolon: return "SEMICOLON";
    case token_kindt::directed_edge_op: return "DIRECTED_EDGE_OP";
    case token_kindt::undirected_edge_op: return "UNDIRECTED_EDGE_OP";
    case token_kindt::end: return "END";
  }

  return "<never-happens>";
}

std::unordered_map<std::string, token_kindt> const g_keywords = {
  {"strict", token_kindt::strict},
  {"graph", token_kindt::graph},
  {"digraph", token_kindt::digraph},
  {"subgraph", token_kindt::subgraph},
  {"node", token_kindt::node},
  {"edge", token_kindt::edge},
};

std::pair<cstring_ref, token_kindt> const g_tokens[] = {
  {"->", token_kindt::directed_edge_op},
  {"--", token_kindt::undirected_edge_op},
  {"{", token_kindt::lbrace},
  {"}", token_kindt::rbrace},
  {"[", token_kindt::lbracket},
  {"]", token_kindt::rbracket},
  {"=", token_kindt::assign},
  {",", token_kindt::comma},
  {";", token_kindt::semicolon},
};

optional<tokent> lookup_token(lex_statet &lexer)
{
  int line = lexer.line();
  for(auto const &pair: g_tokens)
  {
    if(match(lexer, pair.first))
      return tokent{pair.second, pair.first, line};
  }

  return emptyopt;
}

tokent next_token(lex_statet &lexer)
{
  skip_irrelevant(lexer);

  if(!lexer)
    return tokent{token_kindt::end, "<END>", lexer.line()};

  if(auto tok = lookup_token(lexer))
    return *tok;

  int line = lexer.line();

  if(lexer.get() == '"')
    return tokent{token_kindt::identifier, read_string(lexer), line};

  if(lexer.get() == '-' || lexer.get() == '.' || std::isdigit(lexer.get()))
    return tokent{token_kindt::identifier, read_decimal(lexer), line};

  auto id = read_identifier(lexer);
  auto it = g_keywords.find(str(id));
  if(it != g_keywords.end())
    return tokent{it->second, it->first, line};

  return tokent{token_kindt::identifier, id, line};
}


//==================================================================================================
dot_graph_kindt to_graph_kind(token_kindt kind)
{
  if(kind == token_kindt::directed_edge_op)
    return dot_graph_kindt::directed;
  else if(kind == token_kindt::undirected_edge_op)
    return dot_graph_kindt::undirected;

  assert(!"should. not. happen.");
}

[[noreturn]] void throw_invalid_token(tokent const &actual, std::initializer_list<token_kindt> expected)
{
  assert(expected.size());

  std::stringstream ss;
  ss << "Expected " << cstr(*expected.begin());

  for(auto it = expected.begin() + 1; it != expected.end(); ++it)
    ss << ", " << cstr(*it);

  ss << ", got " << cstr(actual.kind) << " in line " << actual.line;

  throw parsing_error{ss.str()};
}

tokent accept(parse_statet &parser, token_kindt kind)
{
  auto tok = parser.get();
  if(tok.kind != kind)
    throw_invalid_token(tok, {kind});

  parser.next();
  return tok;
}

bool accept_if(parse_statet &parser, token_kindt kind)
{
  if(parser.get().kind != kind)
    return false;

  parser.next();
  return true;
}


attr_listt parse_attr_list(parse_statet &parser)
{
  attr_listt attrs;
  while(accept_if(parser, token_kindt::lbracket))
  {
    while(!accept_if(parser, token_kindt::rbracket))
    {
      cstring_ref lhs = accept(parser, token_kindt::identifier).text;
      accept(parser, token_kindt::assign);
      cstring_ref rhs = accept(parser, token_kindt::identifier).text;

      attrs[str(lhs)] = str(rhs);

      if(!accept_if(parser, token_kindt::semicolon))
        accept_if(parser, token_kindt::comma);
    }
  }

  return attrs;
}

void parse_subgraph(parse_statet &parser, dot_readert &reader);

void parse_stmt(parse_statet &parser, dot_readert &reader)
{
  if(parser.get().kind == token_kindt::subgraph)
    parse_subgraph(parser, reader);
  else
  {
    cstring_ref lhs = accept(parser, token_kindt::identifier).text;
    if(accept_if(parser, token_kindt::assign))
      reader.attribute(lhs, accept(parser, token_kindt::identifier).text);
    else if(parser.get().kind == token_kindt::directed_edge_op || parser.get().kind == token_kindt::undirected_edge_op)
    {
      if(parser.graph_kind() != to_graph_kind(parser.get().kind))
        throw parsing_error{"Edge op does not match graph kind in line " + std::to_string(parser.get().line)};

      parser.next();
      cstring_ref rhs = accept(parser, token_kindt::identifier).text;

      reader.edge(lhs, rhs, parse_attr_list(parser));
    }
    else
      reader.node(lhs, parse_attr_list(parser));
  }
}

void parse_subgraph(parse_statet &parser, dot_readert &reader)
{
  accept(parser, token_kindt::subgraph);

  cstring_ref subgraph_id;
  if(parser.get().kind == token_kindt::identifier)
  {
    subgraph_id = parser.get().text;
    parser.next();
  }

  reader.subgraph_begin(subgraph_id);

  accept(parser, token_kindt::lbrace);
  while(parser.get().kind != token_kindt::rbrace)
  {
    parse_stmt(parser, reader);
    accept_if(parser, token_kindt::semicolon);
  }
  accept(parser, token_kindt::rbrace);

  reader.subgraph_end();
}

void parse_graph(parse_statet &parser, dot_readert &reader)
{
  if(parser.get().kind == token_kindt::strict)
  {
    parser.set_strict(true);
    parser.next();
  }

  if(parser.get().kind == token_kindt::graph)
  {
    parser.set_graph_kind(dot_graph_kindt::undirected);
    parser.next();
  }
  else if(parser.get().kind == token_kindt::digraph)
  {
    parser.set_graph_kind(dot_graph_kindt::directed);
    parser.next();
  }
  else
    throw_invalid_token(parser.get(), {token_kindt::graph, token_kindt::digraph});


  cstring_ref graph_id;
  if(parser.get().kind == token_kindt::identifier)
  {
    graph_id = parser.get().text;
    parser.next();
  }

  reader.graph_begin(parser.graph_kind(), graph_id, parser.is_strict());

  accept(parser, token_kindt::lbrace);
  while(parser.get().kind != token_kindt::rbrace)
  {
    parse_stmt(parser, reader);
    accept_if(parser, token_kindt::semicolon);
  }
  accept(parser, token_kindt::rbrace);

  reader.graph_end();
}

}


//==================================================================================================
void read_dot(cstring_ref dot_graph, dot_readert &reader)
{
  internal::parse_statet parser{dot_graph};
  internal::parse_graph(parser, reader);
}

void read_dot(std::istream &is, dot_readert &reader)
{
  std::string contents{std::istreambuf_iterator<char>{is}, std::istreambuf_iterator<char>{}};
  read_dot(contents, reader);
}
