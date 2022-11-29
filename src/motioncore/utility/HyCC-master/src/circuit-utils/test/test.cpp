#include "circuit-utils/circuit.hpp"
#include "circuit-utils/spec.hpp"

#include <iostream>
#include <bitset>


using namespace circ;


/*void test_correct_type(std::string const &type)
{
	circ::ParseState p{type.c_str()};
	try {
		auto parsed_type = to_str(parse_type(p));
		if(parsed_type == type)
			std::cout << "[success] Correctly parsed " << parsed_type << std::endl;
		else
			std::cout << "[ ERROR ] Expected " << type << ", got " << parsed_type << std::endl;
	}
	catch(std::exception &e) {
		std::cout << "[ ERROR ] Parsing failed: " << e.what() << std::endl;
	}
}

void test_wrong_type(std::string const &type)
{
	circ::ParseState p{type.c_str()};
	try {
		auto parsed_type = to_str(parse_type(p));
		std::cout << "[ ERROR ] Expected error, got " << parsed_type << std::endl;
	}
	catch(std::exception &e) {
		std::cout << "[success] Parsing for " << type << " failed as expected with \""
		          << e.what() << "\"" << std::endl;
	}
}

void testcase_parse_type()
{
	std::cout << "<< Parsing types >>\n";

	test_correct_type("int8");
	test_correct_type("uint8");
	test_correct_type("uint32");
	test_correct_type("int64");
	test_correct_type("int64[2][34]");
	test_correct_type("int8[100]");
	test_correct_type("int8[100][23][11][9990]");

	test_wrong_type("int647");
	test_wrong_type("uiint64");
	test_wrong_type("uint64a");
	test_wrong_type("uint64[23");
}


template<typename T>
void test_sign_extend(T val, int width, T expected)
{
	using bitset = std::bitset<sizeof(T) * 8>;

	T actual = circ::sign_extend(val, width);
	if(actual == expected)
	{
		std::cout << "[success] = sign_extend(" << bitset(val) << ", " << width << ") = "
		          << bitset(actual) << '\n';
	}
	else
	{
		std::cout << "[ ERROR ] = sign_extend(" << bitset(val) << ", " << width << ") = "
		          << bitset(expected) << ", got " << bitset(actual) << '\n';
	}
}

void testcase_sign_extend()
{
	std::cout << "<< Sign extension >>\n";

	test_sign_extend<char>(5, 3, 0b11111101);
	test_sign_extend<unsigned char>(5, 3, 0b11111101);
	test_sign_extend<char>(3, 3, 0b00000011);
	test_sign_extend<unsigned char>(3, 3, 0b00000011);
}


template<typename T>
void test_is_representable(circ::IntegerType t, T v, bool expected)
{
	bool actual = circ::is_representable(t, {v < 0, circ::UMaxScalar(v)});
	if(actual == expected)
		std::cout << "[success] is_representable(" << circ::Type{t} << ", " << v << ") == " << expected << '\n';
	else
	{
		std::cout << "[ ERROR ] is_representable(" << circ::Type{t} << ", " << v << ") == " << expected
		          << ", got " << actual << '\n';
	}
}

void testcase_is_representable()
{
	std::cout << "<< is_representable >>\n";

	test_is_representable<int>({true, 8}, 100, true);
	test_is_representable<int>({true, 8}, 127, true);
	test_is_representable<int>({true, 8}, 129, false);
	test_is_representable<int>({true, 8}, -128, true);
	test_is_representable<int>({true, 8}, -129, false);

	test_is_representable<unsigned int>({true, 8}, 128, false);

	test_is_representable<int>({false, 8}, -1, false);

	test_is_representable<uint64_t>({true, 64}, std::numeric_limits<int64_t>::max(), true);
	test_is_representable<uint64_t>({true, 64}, std::numeric_limits<int64_t>::max() + 1, false);

	test_is_representable<uint64_t>({false, 64}, std::numeric_limits<int64_t>::max() + 1, true);
	test_is_representable<uint64_t>({false, 64}, std::numeric_limits<uint64_t>::max(), true);
}


void test_common_type(circ::IntegerType a, circ::IntegerType b, circ::IntegerType expected)
{
	try
	{
		auto actual = circ::common_int_type(a, b);
		if(!actual)
			throw std::runtime_error{"no common type"};

		if(circ::Type{*actual} == circ::Type{expected})
		{
			std::cout << "[success] common_int_type(" << circ::Type{a} << ", " << circ::Type{b}
			          << ") = " << circ::Type{expected} << '\n';
		}
		else
		{
			std::cout << "[ ERROR ] common_int_type(" << circ::Type{a} << ", " << circ::Type{b}
			          << ") = " << circ::Type{expected} << ", got " << circ::Type{*actual} << '\n';
		}
	}
	catch(std::exception const &e)
	{
		std::cout << "[ ERROR ] common_int_type(" << circ::Type{a} << ", " << circ::Type{b}
				  << ") = " << circ::Type{expected} << ", got exception: " << e.what() << '\n';
	}
}

void testcase_common_type()
{
	std::cout << "<< common_int_type >>\n";

	test_common_type({true, 8}, {true, 8}, {true, 8});
	test_common_type({false, 8}, {true, 8}, {true, 16});
	test_common_type({true, 8}, {false, 8}, {true, 16});
	test_common_type({true, 8}, {false, 16}, {true, 32});
	test_common_type({false, 16}, {true, 8}, {true, 32});
}


template<typename T>
void insert(circ::RawValue &dest, T val)
{
	uint8_t const *p = (uint8_t const*)&val;
	for(size_t i = 0; i < sizeof(T); ++i)
		dest.push_back(p[i]);
}

template<typename T>
circ::TypedValue val_scalar(T v)
{
	circ::RawValue val;
	insert(val, v);

	return circ::TypedValue{circ::Type{circ::IntegerType{std::is_signed<T>::value, sizeof(T) * 8}}, std::move(val)};
}

template<typename T>
circ::TypedValue val_1d(std::vector<T> v)
{
	auto int_type = circ::Type{circ::IntegerType{std::is_signed<T>::value, sizeof(T) * 8}};
	auto arr_type = circ::make_array_type(std::move(int_type), v.size());

	circ::RawValue val;
	for(auto i: v)
		insert(val, i);

	return circ::TypedValue{std::move(arr_type), std::move(val)};
}

template<typename T>
circ::TypedValue val_2d(std::vector<std::vector<T>> const &v)
{
	auto int_type = circ::Type{circ::IntegerType{std::is_signed<T>::value, sizeof(T) * 8}};
	auto arr_type = circ::make_array_type(circ::make_array_type(std::move(int_type), v[0].size()), v.size());

	circ::RawValue val;
	for(auto const &vec: v)
		for(auto i: vec)
			insert(val, i);

	return circ::TypedValue{std::move(arr_type), std::move(val)};
}

circ::TypedValue val_struct(std::vector<std::pair<std::string, circ::TypedValue>> const &v)
{
	circ::RawValue val;
	circ::StructType type;
	for(auto m: v)
	{
		val.insert(val.end(), m.second.value.begin(), m.second.value.end());
		type.members.emplace_back(m.first, std::unique_ptr<circ::Type>{new circ::Type{m.second.type}});
	}

	return circ::TypedValue{std::move(type), std::move(val)};
}

void test_parse_value(std::string const &str, circ::TypedValue const &expected)
{
	circ::ParseState parser{str.c_str()};
	circ::Context ctx;
	circ::SymbolTable table;
	auto actual = circ::parse_cast_expr(parser)->to_domain_expr(table, nullopt)->evaluate(ctx);

	if(actual == expected)
		std::cout << "[success] parsed value: " << expected.type << ":" << expected << '\n';
	else
		std::cout << "[ ERROR ] expected " << expected.type << ":" << expected << ", got " << actual.type << ":" << actual << '\n';
}

void test_parse_invalid_value(std::string const &str)
{
	circ::ParseState parser{str.c_str()};

	try
	{
		circ::Context ctx;
		circ::SymbolTable table;
		auto actual = circ::parse_cast_expr(parser)->to_domain_expr(table, nullopt)->evaluate(ctx);
		std::cout << "[ ERROR ] expected error, got " << actual.type << ":" << actual << '\n';
	}
	catch(std::exception const &e)
	{
		std::cout << "[success] Parsing " << str << " failed succesfully with \"" << e.what() << "\"\n";
	}
}

void testcase_parse_value()
{
	std::cout << "<< parse_value >>\n";

	test_parse_value("123", val_scalar<int8_t>(123));
	test_parse_value("-128", val_scalar<int8_t>(-128));
	test_parse_value("128", val_scalar<uint8_t>(128));
	test_parse_value("256", val_scalar<int16_t>(256));

	test_parse_value("[[1, 2], [3, 4]]:int8[2][2]", val_2d<int8_t>({{1, 2}, {3, 4}}));
	test_parse_value("[[130, 2], [3, 4]]:uint8[2][2]", val_2d<uint8_t>({{130, 2}, {3, 4}}));
	test_parse_value("[3, 9223372036854775808]:uint64[2]", val_1d<uint64_t>({3, 9223372036854775808ull}));

	test_parse_invalid_value("[-9223372036854775808, 9223372036854775808]:uint64[2]");
	test_parse_invalid_value("[-1, 9223372036854775808]:int64[2]");
	test_parse_invalid_value("[[130, 2], [3, 4]]:int8[2]");
	test_parse_invalid_value("[[130, 2], [3, 4]]:int8[2][3]");

	test_parse_value(
		"{x:4; y:123;}:{x:int8; y:int8;}",
		val_struct({
			{"x", val_scalar<int8_t>(4)},
			{"y", val_scalar<int8_t>(123)},
		})
	);

	test_parse_value(
		"{size:20; data:[1, 2, 3, 4, 5];}:{size:int8; data:int8[5];}",
		val_struct({
			{"size", val_scalar<int8_t>(20)},
			{"data", val_1d<int8_t>({1, 2, 3, 4, 5})},
		})
	);
}*/

/*circ::TypedValue parse_value(std::string const &str)
{
	circ::ParseState parser{str.c_str()};
	return circ::parse_value(parser);
}

void testcase_convert()
{
	using namespace circ;

	std::cout << "<< convert >>\n";

	auto value = convert(Type{IntegerType{true, 32}}, parse_value("-29233"));
	std::cout << *(int32_t*)value.value.data() << std::endl;
}*/


int main()
{
	/*using namespace circ;

	std::vector<uint8_t> data{0b01100101, 0b01100101, 0b01100101};
	uint16_t val = 0b01100101;
	std::cout << "hallo = " << extract_bits(data, 0, 3) << std::endl;
	std::cout << "hallo = " << extract_bits(data, 6, 5) << std::endl;
	std::cout << "hallo = " << extract_bits(data, 6, 17) << std::endl;
	std::cout << "hallo = " << extract_bits(val, 0, 0) << std::endl;

	std::cout << num(123, {true, 32}) << std::endl;
	std::cout << num(-123, {true, 32}) << std::endl;
	std::cout << num(-1, {false, 32}) << std::endl;

	std::vector<uint8_t> data2{0, 2};
	std::cout << "ciao = " << extract_bits(data2, 0, 10) << std::endl;

	testcase_parse_type();
	std::cout << '\n';
	testcase_sign_extend();
	std::cout << '\n';
	testcase_is_representable();
	std::cout << '\n';
	testcase_common_type();
	std::cout << '\n';
	testcase_parse_value();
	std::cout << '\n';
	//testcase_convert();*/
}
