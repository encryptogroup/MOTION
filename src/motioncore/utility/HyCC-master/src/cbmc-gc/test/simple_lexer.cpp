#include "cbmc-gc/simple_lexer.h"

#include <catch/catch.hpp>


TEST_CASE("lex_statet")
{
  SECTION("read_string")
  {
    lex_statet l1{"\"asd\""};
    CHECK(read_string(l1) == "asd");

    lex_statet l2{"\"\\\"a\\\"sd\n  \""};
    CHECK(read_string(l2) == "\\\"a\\\"sd\n  ");

    lex_statet l3{"\"a\\\"sd"};
    CHECK_THROWS_AS(read_string(l3), parsing_error const&);

    lex_statet l4{"asd"};
    CHECK_THROWS_AS(read_string(l4), parsing_error const&);

    lex_statet l5{"\"\""};
    CHECK(read_string(l5) == "");
  }

  SECTION("read_identifier")
  {
    lex_statet l1{"asd23"};
    CHECK(read_identifier(l1) == "asd23");

    lex_statet l2{"_1asd, dsa"};
    CHECK(read_identifier(l2) == "_1asd");

    lex_statet l3{"9asd"};
    CHECK_THROWS_AS(read_identifier(l3), parsing_error const&);
  }
}
