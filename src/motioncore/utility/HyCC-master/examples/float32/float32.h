#include <inttypes.h>

#ifdef ENABLE_DEBUG_OUTPUT
#include <stdio.h>
#endif


// Utility functions
//==================================================================================================
#define xor_swap(a, b) (a = a ^ b, b = a ^ b, a = a ^ b)
#define is_neg(x) (x & 0x80000000)

#define f32_get_e(f) ((f & 0x7F800000) >> 23)
#define f32_get_m(f) (f & 0x007FFFFF)
#define f32_get_s(f) (f >> 31)

#define f32_build(sign, exp, frac) ((sign << 31) | (exp << 23) | frac)
#define f32_build_qnan() f32_build(0, 255, 0x00400000)
#define f32_build_inf(sign) f32_build(sign, 255, 0)
#define f32_build_zero(sign) f32_build(sign, 0, 0)

// A number with a implicitly leading one.
// Zero is not a normal number.
#define f32_is_normal_number(f) (f32_get_e(f) != 0 && f32_get_e(f) != 255)

// A number with a implicitly leading zero.
// Zero is not a denormal number.
#define f32_is_denormal_number(f) (f32_get_e(f) == 0 && f32_get_m(f) != 0)

#define f32_is_nan(f) (f32_get_e(f) == 0xff && f32_get_m(f) != 0)
#define f32_is_inf(f) (f32_get_e(f) == 255 && f32_get_m(f) == 0)
#define f32_is_zero(f) (f32_get_e(f) == 0 && f32_get_m(f) == 0)


// Rounding
//==================================================================================================
#define shift_mantissa_right_32(mant, count, sticky_bit) \
	do { \
		if(count < 31) \
		{ \
			sticky_bit |= ((mant<<(-(count) & 31)) != 0) && (count); \
			mant >>= count; \
		} \
		else \
		{ \
			sticky_bit = mant != 0; \
			mant = 0; \
		} \
	} while(0)

#define shift_mantissa_right_64(mant, count, sticky_bit) \
	do { \
		if(count < 63) \
		{ \
			sticky_bit |= ((mant<<(-(count) & 63)) != 0) && (count); \
			mant >>= count; \
		} \
		else \
		{ \
			sticky_bit = mant != 0; \
			mant = 0; \
		} \
	} while(0)


#define round_to_nearest(sign, exp, mant, sticky_bit) \
	do { \
		if(!is_err && mant & 0x2 && (mant & 0x1 || sticky_bit || mant & 0x4)) \
		{ \
			mant = (mant>>2)+1; \
			if((1 << 24) & mant \
			  /* If this is a denormal number and the 24th bit is set it becomes a normal number */ \
			  || (exp == 0 && (1 << 23) & mant)) \
			{ \
				if(exp == 255) \
				{ \
					err_res = f32_build_inf(sign); \
					is_err = 1; \
				} \
				else \
					exp++; \
			} \
		} \
		else \
			mant >>= 2; \
	 \
	 \
		if(is_err) \
			res = err_res; \
		else \
			res = f32_build(sign, exp, 0x7FFFFF & mant); \
	 \
	} while(0) \


// Addition
//==================================================================================================
#define leading_zeroes_26_add(value, leading_zeroes, step, i, store) \
	do { \
		for(i = 0; i < 26; ++i) \
			store[i] = !((value >> (25-i)) & 1); \
 \
		step = 1; \
		while(step < 26) \
		{ \
			for(i = 0; i + step < 26; i += step * 2) \
				store[i] = store[i] == step ? store[i] + store[i+step] : store[i]; \
 \
			step *= 2; \
		} \
 \
		leading_zeroes = store[0]; \
	} while(0)

int float32_add(int a, int b)
{
	int d = 0;
	int exp = 0;

	int mant_a = 0;
	int exp_a = 0;
	int mant_b = 0;
	int exp_b = 0;
	int mant_res = 0;

	char store[26] = {0};
	int step = 0;


	// Used by round_to_nearest
	_Bool sticky_bit = 0;
	int err_res = 0;
	int is_err = 0;
	int leading_zeroes = 0;
	int left_shifts = 0;
	int i = 0;
	int res = 0;


	// Handle NaN.
	if(f32_is_nan(a))
		return a;
	if(f32_is_nan(b))
		return b;


	// Handle inf.
	if(f32_is_inf(a) && f32_is_inf(b))
	{
		if(f32_get_s(a) == f32_get_s(b))
			return a;

		return f32_build_qnan();
	}
	else if(f32_is_inf(a))
		return a;
	else if(f32_is_inf(b))
		return b;


	mant_a = f32_get_m(a) << 2;
	exp_a = f32_get_e(a);
	// If `a` is a non-zero number we need to add the implicit leading one.
	if(f32_is_normal_number(a))
		mant_a |= 1 << 25;
	else if(f32_is_denormal_number(a))
		exp_a = 1;


	mant_b = f32_get_m(b) << 2;
	exp_b = f32_get_e(b);
	// If `b` is a non-zero number we need to add the implicit leading one.
	if(f32_is_normal_number(b))
		mant_b |= 1 << 25;
	else if(f32_is_denormal_number(b))
		exp_b = 1;


	d = exp_b - exp_a;
	if(is_neg(d) || (d == 0 && mant_b < mant_a))
	{
		xor_swap(a, b);
		xor_swap(mant_a, mant_b);
		exp = exp_a;
		d = -d;
	}
	else
		exp = exp_b;



	// Since we increased the exponent of `a` we need to adjust its mantissa, too.
	shift_mantissa_right_32(mant_a, d, sticky_bit);


	// Now do the actual addition.
	if(f32_get_s(a) == f32_get_s(b))
		mant_res = mant_a + mant_b;
	else
	{
		// TODO `mant_res = mant_b - mant_a - sticky_bit` doesn't work. (somehow mant_b + mant_a is
		//      computed?)
		mant_res = mant_b - mant_a;
		mant_res -= sticky_bit;
	}


	// Normalize result.
	if(mant_res == 0)
	{
		/* According to IEEE 754 zero is encoded as e = m = 0. Since the mantissa is zero we
		   need to set the exponent to zero, too. */
		exp = 0;
	}
	else if((1 << 26) & mant_res)
	{
		/* The 25th bit is set so there has been an overflow during addition. */

		if(exp == 254)
		{
			/* Shifting right would cause the exponent to overflow. Return infinity. */
			err_res = f32_build_inf(f32_get_s(b));
			is_err = 1;
		}

		shift_mantissa_right_32(mant_res, 1, sticky_bit);
		exp += 1;
	}
	else
	{
		/* Check if the 24th bit is set and if not, by how much we have to shift the mantissa to the
		 * left. */

		leading_zeroes_26_add(mant_res, left_shifts, step, i, store);

		if(left_shifts >= exp)
		{
			left_shifts = exp - 1;
			exp = 0;
		}
		else
			exp -= left_shifts;


		mant_res = mant_res << left_shifts;
	}

	round_to_nearest(f32_get_s(b), exp, mant_res, sticky_bit);


	return res;
}


// Floating-point multiplication.
//==================================================================================================
// Depth = 5
#define leading_zeroes_24_add(value, leading_zeroes, step, i, store) \
	do { \
		for(i = 0; i < 24; ++i) \
			store[i] = !((value >> (23-i)) & 1); \
 \
		step = 1; \
		while(step < 24) \
		{ \
			for(i = 0; i + step < 24; i += step * 2) \
				store[i] = store[i] == step ? store[i] + store[i+step] : store[i]; \
 \
			step *= 2; \
		} \
 \
		leading_zeroes = store[0]; \
	} while(0)


int float32_mul(int a, int b)
{
	int sign = f32_get_s(a) ^ f32_get_s(b);

	int mant_a = 0;
	int exp_a = 0;

	int mant_b = 0;
	int exp_b = 0;

	uint64_t mant_res_64 = 0;
	int mant_res = 0;
	int exp_res = 0;


	int ia = 0;
	char store_a[24] = {0};
	int step_a = 0;
	int left_shifts_a = 0;

	int ib = 0;
	char store_b[24] = {0};
	int step_b = 0;
	int left_shifts_b = 0;


	// Used by round_to_nearest
	_Bool sticky_bit = 0;
	int err_res = 0;
	int is_err = 0;
	int res = 0;


	// Handle NaN.
	if(f32_is_nan(a))
		return a;
	if(f32_is_nan(b))
		return b;

	// Handle zero.
	if(f32_is_zero(a) || f32_is_zero(b))
	{
		// 0 * inf == inf * 0 ==  NaN
		if(f32_is_inf(a) || f32_is_inf(b))
			return f32_build_qnan();

		return f32_build_zero(sign);
	}

	// Handle inf.
	if(f32_is_inf(a) || f32_is_inf(b))
		return f32_build_inf(sign);


	mant_a = f32_get_m(a);
	exp_a = f32_get_e(a);
	// If `a` is a non-zero number we need to add the implicit leading one.
	if(f32_is_normal_number(a))
		mant_a |= 1 << 23;
	if(f32_is_denormal_number(a))
	{
		// Normalize
		leading_zeroes_24_add(mant_a, left_shifts_a, step_a, ia, store_a);

		exp_a = 1 - left_shifts_a;
		mant_a <<= left_shifts_a;
	}


	mant_b = f32_get_m(b);
	exp_b = f32_get_e(b);
	// If `b` is a non-zero number we need to add the implicit leading one.
	if(f32_is_normal_number(b))
		mant_b |= 1 << 23;
	if(f32_is_denormal_number(b))
	{
		// Normalize
		leading_zeroes_24_add(mant_b, left_shifts_b, step_b, ib, store_b);

		exp_b = 1 - left_shifts_b;
		mant_b <<= left_shifts_b;
	}


	// Now the actual multiplication!
	mant_res_64 = ((uint64_t)mant_a * mant_b) << 2;
	exp_res = exp_a + exp_b - 127;


	if(mant_res_64 & (1ull << 49))
	{
		exp_res += 1;
		shift_mantissa_right_64(mant_res_64, 24, sticky_bit);
	}
	else
		shift_mantissa_right_64(mant_res_64, 23, sticky_bit);


	mant_res = mant_res_64;


	// Infinity
	if(exp_res > 254)
		return f32_build_inf(sign);

	// Check if result is denormal.
	if(exp_res < 1)
	{
		shift_mantissa_right_32(mant_res, -exp_res+1, sticky_bit);
		exp_res = 0;
	}


	round_to_nearest(sign, exp_res, mant_res, sticky_bit);

	return res;
}

