#pragma once

#include "../simple_lexer.h"
#include <libcircuit/utils.h>

#include <unordered_map>


enum class dot_graph_kindt
{
  directed,
  undirected,
};


using attr_listt = std::unordered_map<std::string, std::string>;


class dot_readert
{
public:
  virtual ~dot_readert() {}

  virtual void graph_begin(dot_graph_kindt /*kind*/, cstring_ref /*name*/, bool /*strict*/) {}
  virtual void graph_end() {}

  virtual void subgraph_begin(cstring_ref /*name*/) {}
  virtual void subgraph_end() {}

  virtual void attribute(cstring_ref /*name*/, cstring_ref /*value*/) {}
  virtual void node(cstring_ref /*name*/, attr_listt const &/*attrs*/) {}
  virtual void edge(cstring_ref /*from*/, cstring_ref /*to*/, attr_listt const &/*attrs*/) {}
};


void read_dot(cstring_ref dot_graph, dot_readert &reader);
void read_dot(std::istream &is, dot_readert &reader);

inline void read_dot(std::istream &&is, dot_readert &reader)
{
  read_dot(is, reader);
}


namespace internal {


//==================================================================================================
enum class token_kindt
{
  identifier,

  // Keywords
  strict,
  graph,
  digraph,
  subgraph,
  node,
  edge,

  lbrace,
  rbrace,
  lbracket,
  rbracket,

  assign,
  comma,
  semicolon,

  directed_edge_op,
  undirected_edge_op,

  end,
};

char const* cstr(token_kindt kind);

struct tokent
{
  tokent() = default;

  tokent(token_kindt kind, cstring_ref text, int line) :
    kind{kind},
    text{text},
    line{line} {}

  token_kindt kind;
  cstring_ref text;
  int line;
};

inline bool operator == (tokent const &a, tokent const &b)
{
  return a.kind == b.kind && a.text == b.text && a.line == b.line;
}

inline std::ostream& operator << (std::ostream &os, tokent const &tok)
{
  return os << "{" << (int)tok.kind << ",\"" << tok.text << "\"," << tok.line << "}";
}


tokent next_token(lex_statet &lexer);


class parse_statet
{
public:
  explicit parse_statet(cstring_ref source) :
    m_lexer{source},
    m_tok{next_token(m_lexer)},
    m_graph_kind{dot_graph_kindt::undirected},
    m_is_strict{false} {}

  void next() { m_tok = next_token(m_lexer); }
  tokent const& get() const { return m_tok; }

  void set_graph_kind(dot_graph_kindt kind) { m_graph_kind = kind; }
  void set_strict(bool strict) { m_is_strict = strict; }

  dot_graph_kindt graph_kind() const { return m_graph_kind; }
  bool is_strict() const { return m_is_strict; }

private:
  lex_statet m_lexer;
  tokent m_tok;
  dot_graph_kindt m_graph_kind;
  bool m_is_strict;
};


attr_listt parse_attr_list(parse_statet &parser);

}
