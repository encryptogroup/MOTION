#include "building_blocks.h"
#include "utils.h"


// Utilities
//==================================================================================================
std::pair<literalt, literalt> half_adder(propt &prop, literalt a, literalt b)
{
  return {prop.lxor(a, b), prop.land(a, b)};
}

std::pair<literalt, literalt> full_adder(propt &prop, literalt a, literalt b, literalt c)
{
  literalt xor1_out = prop.lxor(a, c);
  literalt xor2_out = prop.lxor(b, c);

  literalt and_out = prop.land(xor1_out, xor2_out);

  literalt sum = prop.lxor(a, xor2_out);
  literalt carry_out = prop.lxor(and_out, c);

  return {sum, carry_out};
}


literalt pointer_xor(literalt a, literalt b, propt* obj)
{
	return obj->lxor(a, b);
}

literalt pointer_and(literalt a, literalt b, propt* obj)
{
	return obj->land(a, b);
}

// try to build pairs of two, if we have not enough, fill up with zero-gates
void combine2 (std::list<literalt> &current_list, literalt (*func1)(literalt first, literalt second, propt* obj), propt *obj) {
  std::list<literalt> new_list;
	literalt first, second;

	while (current_list.size() != 0) {
		first = current_list.front();
		current_list.pop_front();

		if (current_list.size() != 0) {
			second = current_list.front();
			current_list.pop_front();
		}
		else {
			if (func1 == &pointer_and)
				second = const_literal(true);

			else second = const_literal(false);
		}

		new_list.push_back(func1(first, second, obj));
	}
	current_list = new_list;
	new_list.clear();
}


// Standard building blocks: optimized for low non-XOR gate count
//==================================================================================================
std::pair<bvt, literalt> basic_adder(propt &prop, bvt const &a, bvt const &b, literalt carry_in)
{
  assert(a.size() == b.size());
  
  bvt sum(a.size());
  for (unsigned i = 0; i < a.size(); i++)
    std::tie(sum[i], carry_in) = full_adder(prop, a[i], b[i], carry_in);

  return {sum, carry_in};
}

std::pair<bvt, literalt> adder(propt &prop, bvt const &a, bvt const &b)
{
  return basic_adder(prop, a, b, const_literal(false));
}

std::pair<bvt, literalt> subtractor(propt &prop, bvt const &a, bvt const &b)
{
  return basic_adder(prop, a, inverter(b), const_literal(true));
}

bvt negator(propt &prop, bvt const &a)
{
  bv_utilst utils{prop};
  return utils.negate(a);
}


//------------------------------------------------------------------------------
bvt multiplier(propt &prop, bvt const &_op0, const bvt &_op1)
{
  bvt op0=_op0, op1=_op1;

  if(is_constant(op1))
    std::swap(op0, op1);

  bvt product;
  product.resize(op0.size());

  for(std::size_t i=0; i<product.size(); i++)
    product[i]=const_literal(false);

  for(std::size_t sum=0; sum<op0.size(); sum++)
    if(op0[sum]!=const_literal(false))
    {
      bvt tmpop;

      tmpop.reserve(op0.size());

      for(std::size_t idx=0; idx<sum; idx++)
        tmpop.push_back(const_literal(false));

      for(std::size_t idx=sum; idx<op0.size(); idx++)
        tmpop.push_back(prop.land(op1[idx-sum], op0[sum]));

      product=adder(prop, product, tmpop).first;
    }

  return product;
}


// Divider
//------------------------------------------------------------------------------
static bvt cond_negate(propt &prop, const bvt &bv, const literalt cond)
{
  bvt neg_bv=negator(prop, bv);

  bvt result;
  result.resize(bv.size());

  for(std::size_t i=0; i<bv.size(); i++)
    result[i]=prop.lselect(cond, neg_bv[i], bv[i]);

  return result;
}

using CondNegateFunc = bvt (*)(propt&, const bvt&, literalt);

std::pair<bvt, bvt> basic_unsigned_divider(propt &prop, const bvt &op0, const bvt &op1)
{
  assert(op0.size() == op1.size());

  bvt res, rem;
  
  unsigned width=op0.size();
  res.resize(width);
  rem.resize(width);

  /* P := N
     D := D << n              -- P and D need twice the word width of N and Q
     for i = n−1..0 do        -- for example 31..0 for 32 bits
     P := 2P − D            -- trial subtraction from shifted value
     if P >= 0 then
     q(i) := 1            -- result-bit 1
     else
     q(i) := 0            -- result-bit 0
     P := P + D           -- new partial remainder is (restored) shifted value
     end
     end
  */
    

  for(unsigned i=0; i<width; i++)
  {
    res[i]=const_literal(false);
    rem[i]=const_literal(false);
  }
  
  
  bvt bits_set(op1);
  for(int i = width - 2; i >= 0; i--) {
    bits_set[i]=prop.lor(bits_set[i+1], bits_set[i]);
  }
  
  for(int i = width - 1; i >= 0; i--) {
    unsigned sub_bits = width - i; // Bitwidth for the subtract
    
    // Left shift of remainder
    if(i < width - 1) { // shift not needed in first round
      for(int j = (width)-1 ; j > 0; j--) {
        rem[j]=rem[j-1];
      }
    }
    rem[0] = op0[i];
    
    /*
      if R >= D then
        R := R − D
        Q(i) := 1
      end
     */
    
    // Resize, such that only necessary bits are used
    bvt remtemp(rem);
    bvt div(op1);
    remtemp.resize(sub_bits);
    div.resize(sub_bits);
    
    // Note that it seems like lselect and bv_if return a[0] on s=true and a[1] on s=false
    
    // overflow in unsigned subtract A-B indicates that B>A
    literalt carry_out;
    std::tie(remtemp, carry_out) = basic_adder(prop, remtemp, inverter(div), const_literal(true));
    // is overflow, or is divider larger than remainder
    if(i>0) {
      res[i] = !prop.lor(!carry_out, bits_set[sub_bits]);
      for(int j = 0; j < sub_bits; j++) {
        rem[j] = prop.lselect(res[i], remtemp[j], rem[j]);
      }
    } else {
      res[i] = carry_out;
      rem = bv_if(prop, res[i], remtemp, rem);
    }
    //rem = bv_if(res[i], remtemp, rem);
  }
  
  return {res, rem};
}

std::pair<bvt, bvt> unsigned_divider(propt &prop, const bvt &a, const bvt &b)
{
  return basic_unsigned_divider(prop, a, b);
}

std::pair<bvt, bvt> basic_signed_divider(propt &prop, CondNegateFunc cond_negate_func, const bvt &op0, const bvt &op1)
{
  if (op0.size() == 0 || op1.size() == 0)
    return {};

  literalt sign_op0 = op0[op0.size() - 1];
  literalt sign_op1 = op1[op1.size() - 1];

  bvt op0_inv = cond_negate_func(prop, op0, sign_op0);
  bvt op1_inv = cond_negate_func(prop, op1, sign_op1);

  bvt res, rem;
  std::tie(res, rem) = unsigned_divider(prop, op0_inv, op1_inv);

  literalt result_sign = prop.lxor(sign_op0, sign_op1);
  res = cond_negate_func(prop, res, result_sign);
  rem = cond_negate_func(prop, rem, sign_op0);

  return {res, rem};
}

std::pair<bvt, bvt> signed_divider(propt &prop, const bvt &op0, const bvt &op1)
{
  return basic_signed_divider(prop, cond_negate, op0, op1);
}


//------------------------------------------------------------------------------
bvt shifter(propt &prop, bvt const &in, bv_utilst::shiftt shift, const bvt &dist) {
    bvt op = in;
	unsigned d = 1, width = op.size();

	for (unsigned stage = 0; stage < dist.size(); stage++) {
		if (d >= width)
			break;

		if (dist[stage] != const_literal(false)) {
			bvt tmp(op);

			for (unsigned i = 0; i < width; i++) {
				literalt other;

				if (shift == bv_utilst::LEFT)
					other = (d <= i ? tmp[i - d] : const_literal(false));
				else if (shift == bv_utilst::ARIGHT)
					other = (i + d < width ? tmp[i + d] : tmp[width - 1]); // sign bit
				else if (shift == bv_utilst::LRIGHT)
					other = (i + d < width ? tmp[i + d] : const_literal(false));

				op[i] = prop.lselect(dist[stage], other, tmp[i]);
			}
		}
		d = d << 1;
	}

    return op;
}


// Multiplexer
//------------------------------------------------------------------------------
// Creates a multiplexer for each input vector in `columns`.
//
// Circuit size/depth of a single multiplexer with n input bits:
// NonXORSize(n) = n - 1
// NonXORDepth(n) = log_2(n)
bvt multiplexer(propt &prop, bvt const &selector, std::vector<bvt> const &columns)
{
  assert(columns.size());

  bvt outputs;
  outputs.reserve(columns.size());

  for(size_t i = 0; i < columns.size(); ++i)
  {
    // Build a tree of 2-1 multiplexers
    auto inputs = columns[i];
    literalt selected = build_tree(inputs, [&](literalt a, literalt b, int level)
    {
      return prop.lselect(selector.at(level), b, a);
    });

    outputs.push_back(selected);
  }

  return outputs;
}


// Less than comparer
//------------------------------------------------------------------------------
literalt basic_less_than(AddSubConverterFunc subtractor_func, propt &prop, const bvt &bv0, const bvt &bv1, bool is_signed)
{
  bvt diff;
  literalt carry_out;
  std::tie(diff, carry_out) = subtractor_func(prop, bv0, bv1);

  literalt result;
  if(is_signed)
  {
    literalt top0 = bv0[bv0.size()-1];
    literalt top1 = bv1[bv1.size()-1];
    result = prop.lxor(prop.lequal(top0, top1), carry_out);
  }
  else
    result = !carry_out;

  return result;
}

literalt less_than(propt &prop, const bvt &bv0, const bvt &bv1, bool is_signed)
{
  return basic_less_than(subtractor, prop, bv0, bv1, is_signed);
}


// Low-depth optimized building blocks: optimized for low non-XOR circuit depth
//==================================================================================================

/*******************************************************************
 Function: sklansky_PPA

 Inputs: reference to vector rBV containing a result, three vectors that can be used for functionalities like calculating generate and propagate bits
 	 	 two function pointers to the belonging functions of our intended use (for example calculating the sum bits for an adder -> sklansky_sum())

 Outputs: reference to an output literal that could for example contain the carry_out of an adder or equality comparator

 Purpose: Sklansky prefix network that can be used to summarize bits in some kind of a tree structure
 	 	  It is designed to be interchangeable by other prefix networks as we use function pointers

 \*******************************************************************/
literalt sklansky_PPA(propt &prop, bvt& rBV, bvt& bvIJ0, bvt& bvIJ1, bvt& bvI,
		literalt (*func1)(unsigned i, unsigned k, bvt& bvIJ0, bvt& bvIJ1, propt &prop),
		literalt (*func2)(unsigned i, bvt& rBV, bvt& bvIJ0, bvt& bvI, propt &prop)) {

	// for each stage (logarithmic depth)
	for (unsigned int j = 1; (unsigned int) (1<<j) <= rBV.size(); j++) {

		// we do not need to begin with first bit in every stage so calculate the offset
		unsigned int offset = 1 << (j-1);

		// for each node of our stage
		for (unsigned int i = offset; i < rBV.size(); i += offset) {

			// for each node of the block that is connected with the same parent on the right
			for (unsigned int k = 1; k <= offset; k++) {
				bvIJ0.at(i) = func1(i, k, bvIJ0, bvIJ1, prop);

				// if this is not the first block for this iteration
				// at the moment this is only used by the adder, so we don't need to use a function pointer here
				if (i >= (offset << 1))
					bvIJ1.at(i) = prop.land(bvIJ1.at(i), bvIJ1.at(i-k));
				
				else rBV[i] = func2(i, rBV, bvIJ0, bvI, prop);
				i++;
			}
		}
	}
	// needed for addition as we have to consider the carry_in bit
	if (bvIJ0.size() > rBV.size())
		return func1(rBV.size(), 1, bvIJ0, bvI, prop);

	return bvIJ0.back();
}

/*******************************************************************
 Function: sklansky_carry

 Inputs: two unsigned integers used for the indices and two references to the input vectors,
 	 	 an object we can call land on as it is a member function

 Outputs: resulting literal of the conjunction

 Purpose: calculates the generate bit for position i through combination with position i-k

 \*******************************************************************/
literalt sklansky_carry(unsigned i, unsigned k, bvt& bvIJ0, bvt& bvIJ1, propt &prop) {
	literalt tmp = prop.land(bvIJ1.at(i), bvIJ0.at(i-k));
	return prop.lxor(bvIJ0.at(i), tmp);
}

/*******************************************************************
 Function: sklansky_sum

 Inputs: a index i and three references to the two input vectors and a dummyVec,
 	 	 an object we can call lxor on as it is a member function

 Outputs: resulting literal of the XOR conjunction

 Purpose: calls lxor on bvIJ0.at(i) and bvI.at(i+1) (sum used for adder)

 \*******************************************************************/
literalt sklansky_sum(unsigned i, bvt& dummyVec, bvt& bvIJ0, bvt& bvI, propt &prop) {
	(void)dummyVec;
	return prop.lxor(bvI.at(i+1), bvIJ0.at(i));
}

/*******************************************************************
 Function: sklansky_land

 Inputs: two unsigned integers used for the indices and two references to the input vector and a dummyVec,
 	 	 an object we can call land on as it is a member function

 Outputs: resulting literal of the AND conjunction

 Purpose: calls land on bvIJ0.at(i) and bvIJ0.at(i-k).

 \*******************************************************************/
literalt sklansky_land (unsigned i, unsigned k, bvt& bvIJ0, bvt& dummyVec, propt &prop) {
  (void)dummyVec;
  return prop.land(bvIJ0.at(i), bvIJ0.at(i-k));
}

/*******************************************************************
 Function: sklansky_lor

 Inputs: two unsigned integers used for the indices and two references to the input vector and a dummyVec,
 	 	 an object we can call lor on as it is a member function

 Outputs: resulting literal of the OR conjunction

 Purpose: calls lor on bvIJ0.at(i) and bvIJ0.at(i-k).

 \*******************************************************************/
literalt sklansky_lor (unsigned i, unsigned k, bvt& bvIJ0, bvt& dummyVec, propt &obj) {
  (void)dummyVec;
  return obj.lor(bvIJ0.at(i), bvIJ0.at(i-k));
}

/*******************************************************************
 Function: sklansky_dummyFunc2

 Inputs: two arbitrary unsigned numbers, two arbitrary vectors and an arbitrary object (just to fulfill the needed signature)

 Outputs: a new literal

 Purpose: just a dummy function that we use for our prefix network as not every intended use needs a second function

 \*******************************************************************/
literalt sklansky_dummyFunc2(unsigned, bvt&, bvt&, bvt&, propt&) {
	return const_literal(false);
}

/*******************************************************************
 Function: sklansky_increment

 Inputs: a index i and three references to the two input vectors and a dummyVec,
 	 	 an object we can call lxor on as it is a member function

 Outputs: resulting literal of the XOR conjunction

 Purpose: calls lxor on rBV.at(i) and bvIJ0.at(i-1) (sum used for incrementer)

 \*******************************************************************/
literalt sklansky_increment (unsigned i, bvt& rBV, bvt& bvIJ0, bvt& dummyVec, propt &prop) {
  (void)dummyVec;
  return prop.lxor(bvIJ0.at(i-1), rBV[i]);
}

/*******************************************************************
 Function: bv_utilst::compress_csa_summands

 Inputs: maximum height we want to achieve in this iteration, operand with, array of summands

 Outputs: void

 Purpose: compresses the summand array by using (3,2) and (2,2) compressors

 \*******************************************************************/
typedef std::vector<std::pair<literalt, int>> bvt_pair;

void compress_csa_summands(propt &prop, unsigned height, unsigned size, std::vector<bvt_pair> &summands) {
	literalt tmpSum, tmpCout;
	int new_height;

	for(unsigned i = 0; i < size; i++) {

		bvt_pair* column = &summands.at(i);
		unsigned colHeight = column->size();

		//if (colHeight > height)
		//	sort_csa_summands(column, height);

		while (colHeight > height) {

			if (column->at(0).second > column->at(1).second)
				new_height = column->at(0).second;

			else new_height = column->at(1).second;

			if (colHeight == height+1) // decrements the height
				std::tie(tmpSum, tmpCout) = half_adder(prop, column->at(0).first, column->at(1).first);

			else { // reduces the height by factor 2
				std::tie(tmpSum, tmpCout) = full_adder(prop, column->at(0).first, column->at(1).first, column->at(2).first);
				column->erase(column->begin());

				if (column->at(1).second >= new_height)
					new_height = column->at(1).second;
			}
			// remove the 2 processed summands and push the sum in our column and the carry in the column on our left
			column->erase(column->begin());
			column->erase(column->begin());
			std::pair <literalt, int> p1, p2;
			p1.first = tmpSum;
			p1.second = new_height;
			p2.first = tmpCout;
			p2.second = new_height + 1;
			column->push_back(p1);
			summands.at(i+1).push_back(p2);
			colHeight = column->size();
		}
	}
}

void carry_save_add(propt &prop, bvt &sum, unsigned size, unsigned height, std::vector<bvt_pair> &summands) {

	unsigned new_height = height;

	while (new_height >= 3) {
		// calculate next height

		unsigned Dj = 2;
		while (Dj < height) {
			new_height = Dj;
			Dj *= 1.5;
		}
		// compress our array of summands to achieve our new calculated height
		compress_csa_summands(prop, new_height, sum.size(), summands);
		height = new_height;
	}

	// add the 2 remaining rows (if there is nothing left over fill it up with ZERO-Gates)
	bvt op1, op2;
	for (unsigned i = 0; i < size; i++) {
		if (summands.at(i).size() != 0)
			op1.push_back(summands.at(i).at(0).first);
		else op1.push_back(const_literal(false));

		if (summands.at(i).size() == 2)
			op2.push_back(summands.at(i).back().first);

		else op2.push_back(const_literal(false));
	}
	op1 = adder_lowdepth(prop, op1, op2).first;

	// we only need n bit of our result
	for(unsigned i = 0; i < sum.size(); i++)
		sum.at(i) = op1.at(i);
}

/*******************************************************************
 Function: partial_product_array

 Inputs: references to vectors containing the multiplicant and the multiplicator and a reference to the resulting partial products vector

 Outputs: void

 Purpose: generates a vector (length 2n) of vectors containing (0 up to n) 1-bit multiplicators of the same significance

 \*******************************************************************/
void partial_product_array(propt &prop, bvt const &multiplier, const bvt &multiplicant, std::vector<bvt_pair> &pProducts) {
	unsigned row = 0, n = multiplicant.size();
	int column = 0;

	// we have 2n-1 columns. The middle one has n entries
	// column is index of the multiplicant, row of the multiplier
	for(unsigned i = 0; i < (n << 1)-1; i++) {
		bvt_pair tmp;

		if (i >= n)
			column = n-1;
		else column = i;

		row = i - column;


		if (pProducts.size() <= i)
			pProducts.push_back(tmp);
		// we place partial products of the same significance among each other
		// so we will have 2n-1 vectors of (0 up to n) partial products at the end
		while (column >= 0 && row < n)  {
			std::pair<literalt, int> p;
			p.first = prop.land(multiplier[row++], multiplicant[column--]);
			p.second = 1;
			pProducts.at(i).push_back(p);
		}
	}
	// add another vector for a upcoming carry_out
	if (pProducts.size() < (n<<1)) {
		bvt_pair cout;
		pProducts.push_back(cout);
	}
}

/*******************************************************************
 Function: mpc_circuit_abct::l_adder_ld

 Inputs:   references to two inputs vectors, literal for carry_in and reference to carry_out

 Outputs:  void (sum by call by reference)

 Purpose:  adds two vectors, first contains the sum (low depth version)

 \*******************************************************************/
std::pair<bvt, literalt> basic_adder_lowdepth(propt &prop, bvt const& bv0, const bvt& bv1, literalt carry_in) {
	// Adder requested for input bitvectors with different size!
	assert(bv0.size() == bv1.size());

	bvt sum = bv0;
	bvt propI, genIJ, propIJ;

	// carry in
	genIJ.push_back(carry_in);
	propI.push_back(const_literal(false));
	propIJ.push_back(propI.at(0));

	// create initial generate and propagate signals
	for (unsigned i = 0; i < bv1.size(); i++) {
		genIJ.push_back(prop.land(sum[i], bv1[i]));
		propI.push_back(prop.lxor(sum[i], bv1[i]));
		propIJ.push_back(propI.at(i+1));
	}

	// first sum
	sum[0] = prop.lxor(propI.at(1), genIJ.at(0));

	literalt carry_out = sklansky_PPA(prop, sum, genIJ, propIJ, propI, &sklansky_carry, &sklansky_sum);
	return {sum, carry_out};
}

std::pair<bvt, literalt> adder_lowdepth(propt &prop, bvt const &a, bvt const &b)
{
  return basic_adder_lowdepth(prop, a, b, const_literal(false));
}

std::pair<bvt, literalt> subtractor_lowdepth(propt &prop, bvt const &a, bvt const &b)
{
  return basic_adder_lowdepth(prop, a, inverter(b), const_literal(true));
}

static bvt incrementer_lowdepth(propt &prop, bvt const &a)
{
  bvt bv = a;
  //
  // generate initial propagate signal and calculate first bit
  literalt carry_in = const_literal(true);
  bvt propI(bv);
  propI.at(0) = prop.land(propI.at(0), carry_in);
  bv[0] = prop.lxor(bv[0], carry_in);

  bvt dummyVec(bv);
  literalt carry_out = sklansky_PPA(prop, bv, propI, dummyVec, dummyVec, sklansky_land, sklansky_increment);
  (void)carry_out;

  return bv;
}

bvt negator_lowdepth(propt &prop, bvt const &a)
{
  return incrementer_lowdepth(prop, inverter(a));
}

/*******************************************************************
 Function: bv_utilst::multiplier

 Inputs: references to input vectors, product will contain the product, boolean if we have signed vectors

 Outputs: void (multiply by using call by reference)

 Purpose: multiplies two vectors (signed or unsigned)

 \*******************************************************************/
bvt multiplier_lowdepth(propt &prop, bvt const &op0, const bvt &op1)
{
	bvt product = op0;
	std::vector<bvt_pair> pProducts;

	// create initial array of partial products
	partial_product_array(prop, product, op1, pProducts);

	// add partial products by using a carry save adder
	carry_save_add(prop, product, product.size(), op1.size(), pProducts);

	return product;
}

static bvt const_bv(int width, int64_t val)
{
  assert(width <= 64);

  bvt data(width);
  for(size_t i = 0; i < data.size(); ++i)
    data[i] = const_literal((val >> i) & 1);

  return data;
}

// This function first computes the partial sums of all multiplications and then uses a carry-save
// adder to sum up the partial sums and the summands specified in `summands`.
// A summand is a pair consisting of a bit-vector and a boolean indicating wether the summand is to
// be subtracted (true) or added (false).
// To compute the two's-complement we need to invert the summand and add 1. The addition is performed
// by creating a new summand that is equal to the number of subtractions.
bvt multiplier_adder_lowdepth(propt &prop, std::vector<std::pair<bool, bvt>> &&summands, std::vector<std::vector<bvt>> const &mults)
{
  assert(mults.size() > 0 || summands.size() > 0);
  std::vector<bvt_pair> pSummands;

  unsigned width = mults.size() ? mults.front().front().size() : summands.front().second.size();

  int number_of_subtractions = 0;
  for(size_t i = 0; i < summands.size(); ++i)
    number_of_subtractions += summands[i].first;

  if(mults.size())
  {
    for(auto const &mult: mults)
    {
      assert(mult.size() >= 2);

      bvt product = mult.front();
      for (unsigned i = 1; i < mult.size() - 1; i++)
        product = multiplier_lowdepth(prop, product, mult[i]);

      // The partial products of the last multiplication can be added together with all other
      // summands using carry_save_add() (see bottom of this function).
      partial_product_array(prop, product, mult[mult.size()-1], pSummands);
    }
  }
  else
  {
    // We need one more entry for the carry out.
    pSummands.resize(width + 1);
  }

  // Add one for each subtraction for two's-complements.
  // TODO Is the any better way to implement subtraction using a carry-save adder?
  if(number_of_subtractions)
    summands.push_back({false, const_bv(width, number_of_subtractions)});

  // add other summands
  for(unsigned i = 0; i < width; i++)
  {
    for(std::vector<std::pair<bool, bvt>>::const_iterator it = summands.begin(); it != summands.end(); ++it)
    {
      std::pair<literalt, int> p;
      bool subtract = it->first;
      p.first = subtract ? !it->second.at(i) : it->second.at(i);
      p.second = 1;
      pSummands.at(i).push_back(p);
    }
  }

  // add summands by using a carry save adder
  bvt sum(width);
  carry_save_add(prop, sum, width, pSummands.at(width-1).size(), pSummands);

  return sum;
}


// Divider
//------------------------------------------------------------------------------
static bvt cond_negate_lowdepth(propt &prop, const bvt &bv, const literalt cond)
{
  bvt neg_bv=negator_lowdepth(prop, bv);

  bvt result;
  result.resize(bv.size());

  for(std::size_t i=0; i<bv.size(); i++)
    result[i]=prop.lselect(cond, neg_bv[i], bv[i]);

  return result;
}

std::pair<bvt, bvt> signed_divider_lowdepth(propt &prop, const bvt &op0, const bvt &op1)
{
  return basic_signed_divider(prop, cond_negate_lowdepth, op0, op1);
}


// Shifter
//------------------------------------------------------------------------------
static literalt convert_index_mux_lowdepth(propt &prop, const bvt &exp_bvt, std::list<literalt> &data_list) {

	std::list<literalt> current_list, new_list;
	std::list<std::list<literalt> > test_list;
	unsigned size;

	for (size = 1; (1 << size) <= data_list.size(); size++);

	for (unsigned i = 0; i < size; i++) {
		unsigned j = 1 << i;
		bool not_gate = true;
		for (unsigned k = 0; k < data_list.size(); k++) {
			if (j == 0) {
				not_gate = !not_gate;
				j = (1 << i)-1;
			}
			else j--;

			if (!not_gate)
				new_list.push_back(exp_bvt[i]);

			else new_list.push_back(!exp_bvt[i]);
		}
		test_list.push_back(new_list);
		new_list.clear();
	}

	while (!test_list.empty()) {
		for (std::list<std::list<literalt> >::iterator it = test_list.begin(); it != test_list.end(); ++it) {
			current_list.push_back(*((*it).begin()));
			(*it).pop_front();
		}
		if (test_list.front().empty())
			test_list.clear();

		current_list.push_back(data_list.front());

		if (data_list.size() != 1)
			data_list.pop_front();
		else data_list.clear();

		while (current_list.size() != 1)
			combine2(current_list, &pointer_and, &prop);

		new_list.push_back(current_list.front());
		current_list.clear();
	}

	current_list = new_list;
	while (current_list.size() != 1)
		combine2(current_list, &pointer_xor, &prop);

	return current_list.front();
}

bvt shifter_lowdepth(propt &prop, bvt const &in, const bv_utilst::shiftt shift, const bvt &dist) {
    bvt op = in;
	std::list<literalt> digits, temp;
	bvt s_dist;

	for (size_t size = 0; size < op.size(); size++) {
		if ((1 << size) < op.size())
			s_dist.push_back(dist[size]);
		else s_dist.push_back(const_literal(false));
	}

	if(shift == bv_utilst::LRIGHT) {
		for (size_t i = 0; i < op.size(); i++)
			digits.push_back(op[i]);

		for (size_t i = 0; i < op.size(); i++) {
			temp = digits;
			op[i] = convert_index_mux_lowdepth(prop, s_dist, temp);
			digits.pop_front();
			digits.push_back(const_literal(false));
		}
	}
	else if(shift == bv_utilst::LEFT) {
		digits.push_back(op[0]);
		for (size_t i = 1; i < op.size(); i++)
			digits.push_back(const_literal(false));

		for (size_t i = 0; i < op.size(); i++) {
			temp = digits;
			op[i] = convert_index_mux_lowdepth(prop, s_dist, temp);
			digits.pop_back();
			digits.push_front(op[i+1]);
		}
	}
	else if(shift == bv_utilst::ARIGHT) {
		for (size_t i = 0; i < op.size(); i++)
			digits.push_back(op[i]);

		for (size_t i = 0; i < op.size(); i++) {
			temp = digits;
			op[i] = convert_index_mux_lowdepth(prop, s_dist, temp);
			digits.pop_front();
			digits.push_back(op.at(op.size()-1));
		}
	}

    return op;
}

// Multiplexer
//------------------------------------------------------------------------------
static void next_permutation(bvt &bv)
{
  for(auto &lit: bv)
  {
      lit = !lit;
      if(!lit.sign())
        break;
  }
}

static bvt build_selector_term(propt &prop, bvt const &selector, int selector_bits, int partial_selector_bits)
{
    bvt cur_sel{selector.begin(), selector.begin() + partial_selector_bits};

    bvt sel_term;
    // Build a AND-tree of the first `partial_selector_bits`-bits of the selector.
    sel_term.push_back(build_tree(cur_sel, [&](literalt a, literalt b, int) { return prop.land(a, b); }));
    // Add the rest of the selector bits.
    sel_term.insert(sel_term.end(), selector.begin() + partial_selector_bits, selector.begin() + selector_bits);

    return sel_term;
}

static std::vector<bvt> multiplexer_build_selector_terms(propt &prop, bvt selector, size_t num_inputs)
{
  // `selector_bits` is the number of bits we need to select any input.
  int selector_bits = log2_ceil(num_inputs);
  // `partial_selector_bits` is the number of bits for which we will build a AND-tree.
  int partial_selector_bits = previous_power_of_two(selector_bits);

  // To select the first input all literals need to be negated.
  selector = inverter(selector);

  std::vector<bvt> selector_terms;
  for(size_t i = 0; i < num_inputs; ++i)
  {
    auto term = build_selector_term(prop, selector, selector_bits, partial_selector_bits);
    selector_terms.push_back(std::move(term));

    next_permutation(selector);
  }

  return selector_terms;
}

// Creates a multiplexer for each input vector in `columns`.
bvt multiplexer_lowdepth(propt &prop, bvt const &selector, std::vector<bvt> const &columns)
{
  auto selector_terms = multiplexer_build_selector_terms(prop, selector, columns[0].size());

  bvt output; output.reserve(columns.size());
  for(auto const &inputs: columns)
  {
    bvt selections;
    for(size_t i = 0; i < inputs.size(); ++i)
    {
      literalt cur = inputs[i];
      auto const &sel_term = selector_terms[i];
      for(int k = sel_term.size() - 1; k >= 0; k--)
        cur = prop.land(cur, sel_term[k]);

      selections.push_back(cur);
    }

    literalt res = build_tree(selections, [&](literalt a, literalt b, int /*level*/)
    {
      return prop.lxor(a, b);
    });

    output.push_back(res);
  }

  return output;
}


//------------------------------------------------------------------------------
literalt equal_lowdepth(propt &prop, bvt const& bv0, const bvt& bv1) {

	// Comparator requested for input bitvectors with different size
    if (bv0.size() != bv1.size())
        exit(-1);

    bvt compIJ;

   	// create initial equality signals (compIJ.at(i) is true if there is a position on which they differ)
   	for (unsigned i = 0; i < bv1.size(); i++)
   		compIJ.push_back(prop.lxor(bv0[i], bv1[i]));

   	bvt dummyVec(bv1);
    return !sklansky_PPA(prop, dummyVec, compIJ, dummyVec, dummyVec, &sklansky_lor, sklansky_dummyFunc2);
}


//------------------------------------------------------------------------------
literalt less_than_lowdepth(propt &prop, const bvt &bv0, const bvt &bv1, bool is_signed)
{
  return basic_less_than(subtractor_lowdepth, prop, bv0, bv1, is_signed);
}
