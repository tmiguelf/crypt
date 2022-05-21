//======== ======== ======== ======== ======== ======== ======== ========
///	\file
///
///	\copyright
///		Copyright (c) Tiago Miguel Oliveira Freire
///
///		Permission is hereby granted, free of charge, to any person obtaining a copy
///		of this software and associated documentation files (the "Software"), to deal
///		in the Software without restriction, including without limitation the rights
///		to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
///		copies of the Software, and to permit persons to whom the Software is
///		furnished to do so, subject to the following conditions:
///
///		The above copyright notice and this permission notice shall be included in all
///		copies or substantial portions of the Software.
///
///		THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
///		IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
///		FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
///		AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
///		LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
///		OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
///		SOFTWARE.
//======== ======== ======== ======== ======== ======== ======== ========

#include <Crypt/codec/ECC.hpp>

#include <string.h>

#include <CoreLib/Core_Type.hpp>

#include "extended_precision.hpp"


#if !defined(_M_AMD64) && !defined(__amd64__)
#	error "Unsuported Architecture"
#endif

namespace crypto
{
	using namespace core::literals;

	namespace
	{

	struct Curve_E521
	{
		///	\brief 
		///		Edwards 521
		///		a * x^2 + y^2 = 1 + d * x^2 * y^2 (mod P)
		///		a = 1
		///		d = -376014
		///		P = 2^521-1

		using coord_t = Ed521::coord_t;
		using point_t = Ed521::point_t;
		using block_t = std::array<uint64_t, 9>;

		struct projective_point_t
		{
			block_t m_x;
			block_t m_y;
			block_t m_z;
		};

		static constexpr uint64_t prime_base = std::numeric_limits<uint64_t>::max();
		static constexpr uint64_t prime_base_l = 0x1FF;


		static constexpr block_t order
		{
			0x40EA2435F5180D6B_ui64,
			0xFBD8C4569A8F1F45_ui64,
			0x36B8AF5E7EC53F04_ui64,
			0x15B6C64746FC85F7_ui64,
			0xFFFFFFFFFFFFFFFD_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0x000000000000007F_ui64,
		};

		static constexpr block_t D
		{
			0xFFFFFFFFFFFA4331_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0x000000000001FFFF_ui64,
		};

		static constexpr coord_t X
		{
			0x302A940A2F19BA6C_ui64,
			0x59D0FB13364838AA_ui64,
			0xAE949D568FC99C60_ui64,
			0xF6ECC5CCC72434B1_ui64,
			0x8BF3C9C0C6203913_ui64,
			0xBFD9F42FC6C818EC_ui64,
			0xF90CB2296B2878A3_ui64,
			0x2CB45C48648B189D_ui64,
			0x0000000000000075_ui64,
		};

		static constexpr coord_t Y
		{
			0x000000000000000C_ui64,
			0x0000000000000000_ui64,
			0x0000000000000000_ui64,
			0x0000000000000000_ui64,
			0x0000000000000000_ui64,
			0x0000000000000000_ui64,
			0x0000000000000000_ui64,
			0x0000000000000000_ui64,
			0x0000000000000000_ui64,
		};


		static constexpr point_t generator{X, Y};





















		static bool compare_equal(const block_t& p_1, const block_t& p_2)
		{
			return memcmp(p_1.data(), p_2.data(), sizeof(block_t)) == 0;
		}

		static void mod_increment(block_t& p_out, const block_t& p_in)
		{
			if
			(
				(p_in[0] == prime_base - 1) &&
				(p_in[1] == prime_base) &&
				(p_in[2] == prime_base) &&
				(p_in[3] == prime_base) &&
				(p_in[4] == prime_base) &&
				(p_in[5] == prime_base) &&
				(p_in[6] == prime_base) &&
				(p_in[7] == prime_base) &&
				(p_in[8] == prime_base_l)
			)
			{
				memset(p_out.data(), 0, sizeof(block_t));
			}
			else
			{
				const block_t& v_1 = reinterpret_cast<const block_t&>(p_in);

				uint8_t carry;
				carry = addcarry(1    , v_1[0], 0, p_out.data() + 0);
				carry = addcarry(carry, v_1[1], 0, p_out.data() + 1);
				carry = addcarry(carry, v_1[2], 0, p_out.data() + 2);
				carry = addcarry(carry, v_1[3], 0, p_out.data() + 3);
				carry = addcarry(carry, v_1[4], 0, p_out.data() + 4);
				carry = addcarry(carry, v_1[5], 0, p_out.data() + 5);
				carry = addcarry(carry, v_1[6], 0, p_out.data() + 6);
				carry = addcarry(carry, v_1[7], 0, p_out.data() + 7);
				        addcarry(carry, v_1[8], 0, p_out.data() + 8);
			}
		}

		static void mod_decrement(block_t& p_out, const block_t& p_in)
		{
			if
			(
				(p_in[0] == 0) &&
				(p_in[1] == 0) &&
				(p_in[2] == 0) &&
				(p_in[3] == 0) &&
				(p_in[4] == 0) &&
				(p_in[5] == 0) &&
				(p_in[6] == 0) &&
				(p_in[7] == 0) &&
				(p_in[8] == 0)
			)
			{
				p_out[0] = prime_base - 1;
				p_out[1] = prime_base;
				p_out[2] = prime_base;
				p_out[3] = prime_base;
				p_out[4] = prime_base;
				p_out[5] = prime_base;
				p_out[6] = prime_base;
				p_out[7] = prime_base;
				p_out[8] = prime_base_l;
			}
			else
			{
				uint8_t borrow;
				borrow = subborrow(1     , p_in[0], 0, p_out.data() + 0);
				borrow = subborrow(borrow, p_in[1], 0, p_out.data() + 1);
				borrow = subborrow(borrow, p_in[2], 0, p_out.data() + 2);
				borrow = subborrow(borrow, p_in[3], 0, p_out.data() + 3);
				borrow = subborrow(borrow, p_in[4], 0, p_out.data() + 4);
				borrow = subborrow(borrow, p_in[5], 0, p_out.data() + 5);
				borrow = subborrow(borrow, p_in[6], 0, p_out.data() + 6);
				borrow = subborrow(borrow, p_in[7], 0, p_out.data() + 7);
				         subborrow(borrow, p_in[8], 0, p_out.data() + 8);
			}
		}

		static void mod_add(block_t& p_out, const block_t& p_1, const block_t& p_2)
		{
			//add
			{
				uint8_t carry;
				carry = addcarry(0    , p_1[0], p_2[0], p_out.data() + 0);
				carry = addcarry(carry, p_1[1], p_2[1], p_out.data() + 1);
				carry = addcarry(carry, p_1[2], p_2[2], p_out.data() + 2);
				carry = addcarry(carry, p_1[3], p_2[3], p_out.data() + 3);
				carry = addcarry(carry, p_1[4], p_2[4], p_out.data() + 4);
				carry = addcarry(carry, p_1[5], p_2[5], p_out.data() + 5);
				carry = addcarry(carry, p_1[6], p_2[6], p_out.data() + 6);
				carry = addcarry(carry, p_1[7], p_2[7], p_out.data() + 7);
						addcarry(carry, p_1[8], p_2[8], p_out.data() + 8);
			}

			//mod
			if(p_out[8] & 0x100_ui64)
			{
				uint8_t borrow;
				borrow = subborrow(0     , p_out[0], prime_base  , p_out.data() + 0);
				borrow = subborrow(borrow, p_out[1], prime_base  , p_out.data() + 1);
				borrow = subborrow(borrow, p_out[2], prime_base  , p_out.data() + 2);
				borrow = subborrow(borrow, p_out[3], prime_base  , p_out.data() + 3);
				borrow = subborrow(borrow, p_out[4], prime_base  , p_out.data() + 4);
				borrow = subborrow(borrow, p_out[5], prime_base  , p_out.data() + 5);
				borrow = subborrow(borrow, p_out[6], prime_base  , p_out.data() + 6);
				borrow = subborrow(borrow, p_out[7], prime_base  , p_out.data() + 7);
				         subborrow(borrow, p_out[8], prime_base_l, p_out.data() + 8);
			}
			else if(
				p_out[0] == prime_base ||
				p_out[1] == prime_base ||
				p_out[2] == prime_base ||
				p_out[3] == prime_base ||
				p_out[4] == prime_base ||
				p_out[5] == prime_base ||
				p_out[6] == prime_base ||
				p_out[7] == prime_base ||
				p_out[8] == prime_base_l)
			{
				memset(p_out.data(), 0, sizeof(block_t));
			}
		}

		static void mod_negate(block_t& p_val)
		{
			if(
				p_val[0] == 0 &&
				p_val[1] == 0 &&
				p_val[2] == 0 &&
				p_val[3] == 0 &&
				p_val[4] == 0 &&
				p_val[5] == 0 &&
				p_val[6] == 0 &&
				p_val[7] == 0 &&
				p_val[8] == 0)
			{
				return;
			}
			uint8_t borrow;
			borrow = subborrow(0     , prime_base  , p_val[0], p_val.data() + 0);
			borrow = subborrow(borrow, prime_base  , p_val[1], p_val.data() + 1);
			borrow = subborrow(borrow, prime_base  , p_val[2], p_val.data() + 2);
			borrow = subborrow(borrow, prime_base  , p_val[3], p_val.data() + 3);
			borrow = subborrow(borrow, prime_base  , p_val[4], p_val.data() + 4);
			borrow = subborrow(borrow, prime_base  , p_val[5], p_val.data() + 5);
			borrow = subborrow(borrow, prime_base  , p_val[6], p_val.data() + 6);
			borrow = subborrow(borrow, prime_base  , p_val[7], p_val.data() + 7);
			         subborrow(borrow, prime_base_l, p_val[8], p_val.data() + 8);
		}

		static void mod_double(block_t& p_val)
		{
			mod_add(p_val, p_val, p_val);
		}

		static void order_reduce(block_t& p_val)
		{
			if(p_val[8] & 0xFF80)
			{
				const uint64_t div = p_val[8] / (order[8] + 1);

				uint64_t mul_carry;
				uint8_t borrow;
				uint8_t borrow2 = 0;
				uint64_t tmp;

				borrow = subborrow(0, p_val[0], umul(order[0], div, &mul_carry), p_val.data() + 0);

				for(uint8_t i = 1; i < 9; ++i)
				{
					borrow  = subborrow(borrow , p_val[i], mul_carry                      , &tmp);
					borrow2 = subborrow(borrow2, tmp     , umul(order[i], div, &mul_carry), p_val.data() + i);
				}

				if(p_val[8] & 0xFF80)
				{
					borrow2 = 0;
					borrow = subborrow(0, p_val[0], umul(order[0], div, &mul_carry), p_val.data() + 0);
					for(uint8_t i = 1; i < 9; ++i)
					{
						borrow  = subborrow(borrow , p_val[i], mul_carry                      , &tmp);
						borrow2 = subborrow(borrow2, tmp     , umul(order[i], div, &mul_carry), p_val.data() + i);
					}
				}
			}
			if
			(
				p_val[8] > order[8] ||
				(
					p_val[8] == order[8] &&
					p_val[7] == order[7] &&
					p_val[6] == order[6] &&
					p_val[5] == order[5] &&
					(
						p_val[4] > order[4] ||
						(
							p_val[4] == order[4] &&
							(
								p_val[3] > order[3] ||
								(
									p_val[3] == order[3] &&
									(
										p_val[2] > order[2] ||
										(
											p_val[2] == order[2] &&
											(
												p_val[1] > order[1] ||
												(
													p_val[1] == order[1] &&
													p_val[0] == order[0]
												)
											)
										)
									)
								)
							)
						)
					)
				)
			)
			{
				uint8_t borrow = 0;
				borrow = subborrow(0     , p_val[0], order[0], p_val.data() + 0);
				borrow = subborrow(borrow, p_val[1], order[1], p_val.data() + 1);
				borrow = subborrow(borrow, p_val[2], order[2], p_val.data() + 2);
				borrow = subborrow(borrow, p_val[3], order[3], p_val.data() + 3);
				borrow = subborrow(borrow, p_val[4], order[4], p_val.data() + 4);
				borrow = subborrow(borrow, p_val[5], order[5], p_val.data() + 5);
				borrow = subborrow(borrow, p_val[6], order[6], p_val.data() + 6);
				borrow = subborrow(borrow, p_val[7], order[7], p_val.data() + 7);
				         subborrow(borrow, p_val[8], order[8], p_val.data() + 8);
			}
		}


		static void mul_reduce(std::array<uint64_t, 17>& p_val)
		{
			if
			(
				p_val[ 8] & 0xFFFFFFFFFFFFFE00 || 
				p_val[ 9] ||
				p_val[10] ||
				p_val[11] ||
				p_val[12] ||
				p_val[13] ||
				p_val[14] ||
				p_val[15] ||
				p_val[16]
			)
			{
				uint8_t carry;
				carry = addcarry(0    , p_val[0], (p_val[ 8] >> 9) | (p_val[ 9] << 55), p_val.data() + 0);
				carry = addcarry(carry, p_val[1], (p_val[ 9] >> 9) | (p_val[10] << 55), p_val.data() + 1);
				carry = addcarry(carry, p_val[2], (p_val[10] >> 9) | (p_val[11] << 55), p_val.data() + 2);
				carry = addcarry(carry, p_val[3], (p_val[11] >> 9) | (p_val[12] << 55), p_val.data() + 3);
				carry = addcarry(carry, p_val[4], (p_val[12] >> 9) | (p_val[13] << 55), p_val.data() + 4);
				carry = addcarry(carry, p_val[5], (p_val[13] >> 9) | (p_val[14] << 55), p_val.data() + 5);
				carry = addcarry(carry, p_val[6], (p_val[14] >> 9) | (p_val[15] << 55), p_val.data() + 6);
				carry = addcarry(carry, p_val[7], (p_val[15] >> 9) | (p_val[16] << 55), p_val.data() + 7);
				        addcarry(carry, p_val[8] & 0x1FF, (p_val[16] >> 9)            , p_val.data() + 8);

				if(p_val[8] & 0x200)
				{
					carry = addcarry(1    , p_val[0]        , 0, p_val.data() + 0);
					carry = addcarry(carry, p_val[1]        , 0, p_val.data() + 1);
					carry = addcarry(carry, p_val[2]        , 0, p_val.data() + 2);
					carry = addcarry(carry, p_val[3]        , 0, p_val.data() + 3);
					carry = addcarry(carry, p_val[4]        , 0, p_val.data() + 4);
					carry = addcarry(carry, p_val[5]        , 0, p_val.data() + 5);
					carry = addcarry(carry, p_val[6]        , 0, p_val.data() + 6);
					carry = addcarry(carry, p_val[7]        , 0, p_val.data() + 7);
					        addcarry(carry, p_val[8] & 0x1FF, 0, p_val.data() + 8);
				}
			}
		}

		static void mod_multiply(block_t& p_out, const block_t& p_1, const block_t& p_2)
		{
			std::array<uint64_t, 17> temp;

			//======== Multiply ========
			{
				uint64_t mul_carry;
				uint64_t mul_carry_2;
				uint64_t acum;
				std::array<uint8_t, 9> lcarry;
				std::array<uint8_t, 7> Dcarry;

				//Block 0
				temp[0] = umul(p_1[0], p_2[0], &mul_carry);


				//Block 1
				lcarry[0] =
					addcarry(0,
						mul_carry,
						umul(p_1[0], p_2[1], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(0,
						acum,
						umul(p_1[1], p_2[0], &mul_carry),
						temp.data() + 1);

				//--
				Dcarry[0] =
					addcarry(0, mul_carry, mul_carry_2, &mul_carry);


				//Block 2
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[0], p_2[2], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[1], p_2[1], &mul_carry),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(0,
						acum,
						umul(p_1[2], p_2[0], &mul_carry_2),
						temp.data() + 2);

				//--
				Dcarry[1] =
					addcarry(0, mul_carry, mul_carry_2, &mul_carry);


				//Block 3
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[0], p_2[3], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[1], p_2[2], &mul_carry),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[2], p_2[1], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(0,
						acum,
						umul(p_1[3], p_2[0], &mul_carry_2),
						temp.data() + 3);

				//--
				Dcarry[2] =
					addcarry(0, mul_carry, mul_carry_2, &mul_carry);


				//Block 4
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[0], p_2[4], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[1], p_2[3], &mul_carry),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[2], p_2[2], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[3], p_2[1], &mul_carry_2),
						&acum);

				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);


				lcarry[4] =
					addcarry(0,
						acum,
						umul(p_1[4], p_2[0], &mul_carry_2),
						temp.data() + 4);

				//--
				Dcarry[3] =
					addcarry(0, mul_carry, mul_carry_2, &mul_carry);


				//Block 5
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[0], p_2[5], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[1], p_2[4], &mul_carry),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[2], p_2[3], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[3], p_2[2], &mul_carry_2),
						&acum);

				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);

				lcarry[4] =
					addcarry(lcarry[4],
						acum,
						umul(p_1[4], p_2[1], &mul_carry_2),
						&acum);

				Dcarry[3] =
					addcarry(Dcarry[3], mul_carry, mul_carry_2, &mul_carry);

				lcarry[5] =
					addcarry(0,
						acum,
						umul(p_1[5], p_2[0], &mul_carry_2),
						temp.data() + 5);

				//--
				Dcarry[4] =
					addcarry(0, mul_carry, mul_carry_2, &mul_carry);


				//Block 6
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[0], p_2[6], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[1], p_2[5], &mul_carry),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[2], p_2[4], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[3], p_2[3], &mul_carry_2),
						&acum);

				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);

				lcarry[4] =
					addcarry(lcarry[4],
						acum,
						umul(p_1[4], p_2[2], &mul_carry_2),
						&acum);

				Dcarry[3] =
					addcarry(Dcarry[3], mul_carry, mul_carry_2, &mul_carry);

				lcarry[5] =
					addcarry(lcarry[5],
						acum,
						umul(p_1[5], p_2[1], &mul_carry_2),
						&acum);

				Dcarry[4] =
					addcarry(Dcarry[4], mul_carry, mul_carry_2, &mul_carry);

				lcarry[6] =
					addcarry(0,
						acum,
						umul(p_1[6], p_2[0], &mul_carry_2),
						temp.data() + 6);

				//--
				Dcarry[5] =
					addcarry(0, mul_carry, mul_carry_2, &mul_carry);


				//Block 7
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[0], p_2[7], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[1], p_2[6], &mul_carry),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[2], p_2[5], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[3], p_2[4], &mul_carry_2),
						&acum);

				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);

				lcarry[4] =
					addcarry(lcarry[4],
						acum,
						umul(p_1[4], p_2[3], &mul_carry_2),
						&acum);

				Dcarry[3] =
					addcarry(Dcarry[3], mul_carry, mul_carry_2, &mul_carry);

				lcarry[5] =
					addcarry(lcarry[5],
						acum,
						umul(p_1[5], p_2[2], &mul_carry_2),
						&acum);

				Dcarry[4] =
					addcarry(Dcarry[4], mul_carry, mul_carry_2, &mul_carry);

				lcarry[6] =
					addcarry(lcarry[6],
						acum,
						umul(p_1[6], p_2[1], &mul_carry_2),
						&acum);

				Dcarry[5] =
					addcarry(Dcarry[5], mul_carry, mul_carry_2, &mul_carry);

				lcarry[7] =
					addcarry(0,
						acum,
						umul(p_1[7], p_2[0], &mul_carry_2),
						temp.data() + 7);

				//--
				Dcarry[6] =
					addcarry(0, mul_carry, mul_carry_2, &mul_carry);


				//Block 8
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[0], p_2[8], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[8], p_2[0], &mul_carry),
						&acum);

				addcarry(Dcarry[6], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[1], p_2[7], &mul_carry_2),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[2], p_2[6], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[4] =
					addcarry(lcarry[4],
						acum,
						umul(p_1[3], p_2[5], &mul_carry_2),
						&acum);

				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);

				lcarry[5] =
					addcarry(lcarry[5],
						acum,
						umul(p_1[4], p_2[4], &mul_carry_2),
						&acum);

				Dcarry[3] =
					addcarry(Dcarry[3], mul_carry, mul_carry_2, &mul_carry);

				lcarry[6] =
					addcarry(lcarry[6],
						acum,
						umul(p_1[5], p_2[3], &mul_carry_2),
						&acum);

				Dcarry[4] =
					addcarry(Dcarry[4], mul_carry, mul_carry_2, &mul_carry);

				lcarry[7] =
					addcarry(lcarry[7],
						acum,
						umul(p_1[6], p_2[2], &mul_carry_2),
						&acum);

				Dcarry[5] =
					addcarry(Dcarry[5], mul_carry, mul_carry_2, &mul_carry);

				lcarry[8] =
					addcarry(0,
						acum,
						umul(p_1[7], p_2[1], &mul_carry_2),
						temp.data() + 8);

				//--
				Dcarry[6] =
					addcarry(lcarry[8], mul_carry, mul_carry_2, &mul_carry);


				//Block 9
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[1], p_2[8], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[8], p_2[1], &mul_carry),
						&acum);

				addcarry(Dcarry[6], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[2], p_2[7], &mul_carry_2),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[3], p_2[6], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[4] =
					addcarry(lcarry[4],
						acum,
						umul(p_1[4], p_2[5], &mul_carry_2),
						&acum);

				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);

				lcarry[5] =
					addcarry(lcarry[5],
						acum,
						umul(p_1[5], p_2[4], &mul_carry_2),
						&acum);

				Dcarry[3] =
					addcarry(Dcarry[3], mul_carry, mul_carry_2, &mul_carry);

				lcarry[6] =
					addcarry(lcarry[6],
						acum,
						umul(p_1[6], p_2[3], &mul_carry_2),
						&acum);

				Dcarry[4] =
					addcarry(Dcarry[4], mul_carry, mul_carry_2, &mul_carry);


				lcarry[7] =
					addcarry(lcarry[7],
						acum,
						umul(p_1[7], p_2[2], &mul_carry_2),
						temp.data() + 9);

				//--
				Dcarry[5] =
					addcarry(Dcarry[5], mul_carry, mul_carry_2 + lcarry[7], &mul_carry);


				//Block 10
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[2], p_2[8], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[8], p_2[2], &mul_carry),
						&acum);

				addcarry(Dcarry[5], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[3], p_2[7], &mul_carry_2),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[4], p_2[6], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[4] =
					addcarry(lcarry[4],
						acum,
						umul(p_1[5], p_2[5], &mul_carry_2),
						&acum);

				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);

				lcarry[5] =
					addcarry(lcarry[5],
						acum,
						umul(p_1[6], p_2[4], &mul_carry_2),
						&acum);

				Dcarry[3] =
					addcarry(Dcarry[3], mul_carry, mul_carry_2, &mul_carry);

				lcarry[6] =
					addcarry(lcarry[6],
						acum,
						umul(p_1[7], p_2[3], &mul_carry_2),
						temp.data() + 10);

				//--
				Dcarry[4] =
					addcarry(Dcarry[4], mul_carry, mul_carry_2 + lcarry[6], &mul_carry);


				//Block 11
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[3], p_2[8], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[8], p_2[3], &mul_carry),
						&acum);

				addcarry(Dcarry[4], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[4], p_2[7], &mul_carry_2),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[5], p_2[6], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[4] =
					addcarry(lcarry[4],
						acum,
						umul(p_1[6], p_2[5], &mul_carry_2),
						&acum);

				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);

				lcarry[5] =
					addcarry(lcarry[5],
						acum,
						umul(p_1[7], p_2[4], &mul_carry_2),
						temp.data() + 11);

				//--
				Dcarry[3] =
					addcarry(Dcarry[3], mul_carry, mul_carry_2 + lcarry[5], &mul_carry);


				//Block 12
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[4], p_2[8], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[8], p_2[4], &mul_carry),
						&acum);

				addcarry(Dcarry[3], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[5], p_2[7], &mul_carry_2),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[6], p_2[6], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[4] =
					addcarry(lcarry[4],
						acum,
						umul(p_1[7], p_2[5], &mul_carry_2),
						temp.data() + 12);

				//--
				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2 + lcarry[4], &mul_carry);


				//Block 13
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[5], p_2[8], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[8], p_2[5], &mul_carry),
						&acum);

				addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[6], p_2[7], &mul_carry_2),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[7], p_2[6], &mul_carry_2),
						temp.data() + 13);

				//--
				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2 + lcarry[3], &mul_carry);


				//Block 14
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[6], p_2[8], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[8], p_2[6], &mul_carry),
						&acum);

				addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[7], p_2[7], &mul_carry_2),
						temp.data() + 14);

				//--
				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2 + lcarry[2], &mul_carry);

				//Block 15
				lcarry[0] =
					addcarry(lcarry[0],
						mul_carry,
						umul(p_1[7], p_2[8], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[1],
						acum,
						umul(p_1[8], p_2[7], &mul_carry),
						temp.data() + 15);

				//--
				addcarry(Dcarry[0], mul_carry, mul_carry_2 + lcarry[1], &mul_carry);

				//Block 16
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[8], p_2[8], &mul_carry_2),
					temp.data() + 16);
			}

			mul_reduce(temp);
			memcpy(p_out.data(), temp.data(), sizeof(block_t));
		}


		static void mod_square(block_t& p_out, const block_t& p_in)
		{
			std::array<uint64_t, 17> temp;
	
			//======== Square ========
			{
				uint64_t mul_carry;


				//double blocks
				{
					std::array<uint8_t, 4> lcarry;
					std::array<uint8_t, 3> Dcarry;
					//Block 0
					//Block 1
					temp[1] = umul(p_in[0], p_in[1], &(temp[2]));

					//Block 2
					lcarry[0] =
						addcarry(0,
							umul(p_in[0], p_in[2], &(temp[3])),
							temp[2],
							&(temp[2]));

					//Block 3
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[3], &(temp[4])),
							temp[3],
							&(temp[3]));

					lcarry[1] =
						addcarry(0,
							umul(p_in[1], p_in[2], &mul_carry),
							temp[3],
							&(temp[3]));

					//--
					Dcarry[0] =
						addcarry(0, temp[4], mul_carry, &(temp[4]));

					//Block 4
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[4], &(temp[5])),
							temp[4],
							&(temp[4]));

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[1], p_in[3], &mul_carry),
							temp[4],
							&(temp[4]));

					//--
					Dcarry[0] =
						addcarry(Dcarry[0], temp[5], mul_carry, &(temp[5]));

					//Block 5
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[5], &(temp[6])),
							temp[5],
							&(temp[5]));

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[1], p_in[4], &mul_carry),
							temp[5],
							&(temp[5]));

					Dcarry[0] =
						addcarry(Dcarry[0], temp[6], mul_carry, &(temp[6]));

					lcarry[2] =
						addcarry(0,
							umul(p_in[2], p_in[3], &mul_carry),
							temp[5],
							&(temp[5]));

					//--
					Dcarry[1] =
						addcarry(0, temp[6], mul_carry, &(temp[6]));

					//Block 6
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[6], &(temp[7])),
							temp[6],
							&(temp[6]));

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[1], p_in[5], &mul_carry),
							temp[6],
							&(temp[6]));

					Dcarry[0] =
						addcarry(Dcarry[0], temp[7], mul_carry, &(temp[7]));

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[2], p_in[4], &mul_carry),
							temp[6],
							&(temp[6]));

					//--
					Dcarry[1] =
						addcarry(Dcarry[1], temp[7], mul_carry, &(temp[7]));

					//Block 7
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[7], &(temp[8])),
							temp[7],
							&(temp[7]));

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[1], p_in[6], &mul_carry),
							temp[7],
							&(temp[7]));

					Dcarry[0] =
						addcarry(Dcarry[0], temp[8], mul_carry, &(temp[8]));

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[2], p_in[5], &mul_carry),
							temp[7],
							&(temp[7]));

					Dcarry[1] =
						addcarry(Dcarry[1], temp[8], mul_carry, &(temp[8]));

					lcarry[3] =
						addcarry(0,
							umul(p_in[3], p_in[4], &mul_carry),
							temp[7],
							&(temp[7]));

					//--
					Dcarry[2] =
						addcarry(0, temp[8], mul_carry, &(temp[8]));

					//Block 8
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[8], &(temp[9])),
							temp[8],
							&(temp[8]));

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[1], p_in[7], &mul_carry),
							temp[8],
							&(temp[8]));

					Dcarry[0] =
						addcarry(Dcarry[0], temp[9], mul_carry, &(temp[9]));

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[2], p_in[6], &mul_carry),
							temp[8],
							&(temp[8]));

					Dcarry[1] =
						addcarry(Dcarry[1], temp[9], mul_carry, &(temp[9]));

					lcarry[3] =
						addcarry(lcarry[3],
							umul(p_in[3], p_in[5], &mul_carry),
							temp[8],
							&(temp[8]));

					//--
					Dcarry[2] =
						addcarry(Dcarry[2], temp[9], mul_carry, &(temp[9]));

					//Block 9
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[1], p_in[8], &(temp[10])),
							temp[9],
							&(temp[9]));

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[2], p_in[7], &mul_carry),
							temp[9],
							&(temp[9]));

					Dcarry[0] =
						addcarry(Dcarry[0], temp[10], mul_carry, &(temp[10]));

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[3], p_in[6], &mul_carry),
							temp[9],
							&(temp[9]));

					Dcarry[1] =
						addcarry(Dcarry[1], temp[10], mul_carry, &(temp[10]));

					lcarry[3] =
						addcarry(lcarry[3],
							umul(p_in[4], p_in[5], &mul_carry),
							temp[9],
							&(temp[9]));

					//--
					Dcarry[2] =
						addcarry(Dcarry[2], temp[10], mul_carry + lcarry[3], &(temp[10]));

					//Block 10
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[2], p_in[8], &(temp[11])),
							temp[10],
							&(temp[10]));

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[3], p_in[7], &mul_carry),
							temp[10],
							&(temp[10]));

					Dcarry[0] =
						addcarry(Dcarry[0], temp[11], mul_carry, &(temp[11]));

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[4], p_in[6], &mul_carry),
							temp[10],
							&(temp[10]));

					//--
					Dcarry[1] =
						addcarry(Dcarry[1], temp[11], mul_carry + Dcarry[2], &(temp[11]));

					//Block 11
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[3], p_in[8], &(temp[12])),
							temp[11],
							&(temp[11]));

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[4], p_in[7], &mul_carry),
							temp[11],
							&(temp[11]));

					Dcarry[0] =
						addcarry(Dcarry[0], temp[12], mul_carry, &(temp[12]));

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[5], p_in[6], &mul_carry),
							temp[11],
							&(temp[11]));

					//--
					Dcarry[1] =
						addcarry(Dcarry[1], temp[12], mul_carry + lcarry[2], &(temp[12]));

					//Block 12
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[4], p_in[8], &(temp[13])),
							temp[12],
							&(temp[12]));

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[5], p_in[7], &mul_carry),
							temp[12],
							&(temp[12]));

					//--
					Dcarry[0] =
						addcarry(Dcarry[0], temp[13], mul_carry + Dcarry[1], &(temp[13]));

					//Block 13
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[5], p_in[8], &(temp[14])),
							temp[13],
							&(temp[13]));

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[6], p_in[7], &mul_carry),
							temp[13],
							&(temp[13]));

					//--
					Dcarry[0] =
						addcarry(Dcarry[0], temp[14], mul_carry + lcarry[1], &(temp[14]));

					//Block 14
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[6], p_in[8], &(temp[15])),
							temp[14],
							&(temp[14]));

					//Block 15
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[7], p_in[8], &(temp[16])),
							temp[15] + Dcarry[0],
							&(temp[15]));

					//Block 16
					temp[16] += lcarry[0];

					//Block 17
				}
				uint8_t lcarry;

				//== Doubling ==
				lcarry = addcarry(0     , temp[ 1], temp[ 1], &(temp[ 1]));
				lcarry = addcarry(lcarry, temp[ 2], temp[ 2], &(temp[ 2]));
				lcarry = addcarry(lcarry, temp[ 3], temp[ 3], &(temp[ 3]));
				lcarry = addcarry(lcarry, temp[ 4], temp[ 4], &(temp[ 4]));
				lcarry = addcarry(lcarry, temp[ 5], temp[ 5], &(temp[ 5]));
				lcarry = addcarry(lcarry, temp[ 6], temp[ 6], &(temp[ 6]));
				lcarry = addcarry(lcarry, temp[ 7], temp[ 7], &(temp[ 7]));
				lcarry = addcarry(lcarry, temp[ 8], temp[ 8], &(temp[ 8]));
				lcarry = addcarry(lcarry, temp[ 9], temp[ 9], &(temp[ 9]));
				lcarry = addcarry(lcarry, temp[10], temp[10], &(temp[10]));
				lcarry = addcarry(lcarry, temp[11], temp[11], &(temp[11]));
				lcarry = addcarry(lcarry, temp[12], temp[12], &(temp[12]));
				lcarry = addcarry(lcarry, temp[13], temp[13], &(temp[13]));
				lcarry = addcarry(lcarry, temp[14], temp[14], &(temp[14]));
				lcarry = addcarry(lcarry, temp[15], temp[15], &(temp[15]));
				lcarry = addcarry(lcarry, temp[16], temp[16], &(temp[16]));

				//single blocks
				//Block 0
				temp[0] = umul(p_in[0], p_in[0], &mul_carry);

				//Block 1
				lcarry = addcarry(0, temp[1], mul_carry, &(temp[1]));

				//Block 2
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[1], p_in[1], &mul_carry),
						temp[2],
						&(temp[2]));

				//Block 3
				lcarry = addcarry(lcarry, temp[3], mul_carry, &(temp[3]));

				//Block 4
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[2], p_in[2], &mul_carry),
						temp[4],
						&(temp[4]));

				//Block 5
				lcarry = addcarry(lcarry, temp[5], mul_carry, &(temp[5]));

				//Block 6
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[3], p_in[3], &mul_carry),
						temp[6],
						&(temp[6]));

				//Block 7
				lcarry = addcarry(lcarry, temp[7], mul_carry, &(temp[7]));

				//Block 8
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[4], p_in[4], &mul_carry),
						temp[8],
						&(temp[8]));

				//Block 9
				lcarry = addcarry(lcarry, temp[9], mul_carry, &(temp[9]));

				//Block 10
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[5], p_in[5], &mul_carry),
						temp[10],
						&(temp[10]));

				//Block 11
				lcarry = addcarry(lcarry, temp[11], mul_carry, &(temp[11]));

				//Block 12
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[6], p_in[6], &mul_carry),
						temp[12],
						&(temp[12]));

				//Block 13
				lcarry = addcarry(lcarry, temp[13], mul_carry, &(temp[13]));

				//Block 14
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[7], p_in[7], &mul_carry),
						temp[14],
						&(temp[14]));

				//Block 15
				lcarry = addcarry(lcarry, temp[15], mul_carry, &(temp[15]));

				//Block 16
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[8], p_in[8], &(temp[17])),
						temp[16],
						&(temp[16]));

				//Block 17
				temp[17] += lcarry;
			}
			mul_reduce(temp);
			memcpy(p_out.data(), temp.data(), sizeof(block_t));
		}

		//uses eulers theorem which for primes inv(a) = a^(p-2) mod p
		static void mod_inverse(block_t& p_val)
		{
			block_t k0;
			block_t k1;
			block_t accum;
	
			memcpy(accum.data(), p_val.data(), sizeof(block_t));

			mod_square(k0, accum);


			{
				block_t temp;
				mod_multiply(temp, k0, accum); //== 2 fill

				mod_square(k0, temp);
				mod_square(k0, k0);

				mod_multiply(k1, k0, temp); //== 4 fill

				mod_square(k0, k1);
				mod_square(k0, k0);

				mod_multiply(temp, k0, temp); //temp = 111111
				mod_square(temp, temp);
				mod_multiply(temp, temp, accum); //temp = 1111111

				mod_square(temp, temp);
				mod_multiply(k1, accum, temp); //== 8 fill
				mod_square(temp, temp);

				mod_multiply(accum, accum, temp); //accum = 1 1111 1101
			}


			mod_square(k0, k1);
			for(uint8_t i = 0; i < 7; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(k1, k1, k0); //== 16 fill

			mod_square(k0, k1);
			for(uint8_t i = 0; i < 15; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(k1, k1, k0); //== 32 fill

			mod_square(k0, k1);
			for(uint8_t i = 0; i < 31; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(k1, k1, k0); //== 64 fill

			mod_square(k0, k1);
			for(uint8_t i = 0; i < 63; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(k1, k1, k0); //== 128 fill

			mod_square(k0, k1);
			for(uint8_t i = 0; i < 127; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(k1, k1, k0); //== 256 fill

			mod_square(k0, k1);
			for(uint8_t i = 0; i < 255; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(k1, k1, k0); //== 512 fill

			mod_square(k0, k1);
			for(uint8_t i = 0; i < 8; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(p_val, accum, k0);

//should yield same result as
//			block_t k;
//			block_t accum;
//			memcpy(accum.data(), p_val.data(), sizeof(block_t));
//		
//			mod_square(k, accum);
//		
//			for(uint8_t i = 3; i < 520; ++i)
//			{
//				mod_square(k, k);
//				mod_multiply(accum, accum, k);
//			}
//			mod_square(k, k);
//			mod_multiply(p_val, accum, k);
		}


		static void ED_point_add(const projective_point_t& p_1, projective_point_t& p_out)
		{
			//	A = Z1*Z2;
			//	B = A^2;
			//	C = X1*X2;
			//	D = Y1*Y2;
			//	E = d*C*D;
			//	F = B - E;
			//	H = B + E;
			//	X3 = A*F*((X1 + Y1)*(X2 + Y2) - C - D);
			//	Y3 = A*H*(D - C);
			//	Z3 = F*H;

			block_t tA;
			block_t tC;
			block_t tD;
			block_t F;
			block_t H;

			{
				block_t tB;
				block_t E;

				mod_multiply(tA, p_1.m_z, p_out.m_z);
				mod_square(tB, tA);
				mod_multiply(tC, p_1.m_x, p_out.m_x);
				mod_multiply(tD, p_1.m_y, p_out.m_y);

				mod_multiply(E, tD, D);
				mod_multiply(E, E, tC);

				memcpy(F.data(), E.data(), sizeof(block_t));
				mod_negate(F);
				mod_add(F, F, tB);
				mod_add(H, tB, E);
			}
			block_t aux1;
			block_t aux2;

			mod_add(aux1, p_1.m_x, p_1.m_y);
			mod_add(aux2, p_out.m_x, p_out.m_y);
			mod_multiply(aux1, aux1, aux2);

			mod_add(aux1, aux1, tC);

			mod_add(aux2, tC, tD);

			mod_negate(tD);
			mod_add(aux1, aux1, tD);
			mod_multiply(aux1, aux1, tA);
			mod_multiply(p_out.m_x, aux1, F);

			mod_multiply(aux2, aux2, H);
			mod_multiply(p_out.m_y, aux2, tA);

			mod_multiply(p_out.m_z, F, H);
		}

		static void ED_point_double(projective_point_t& p_point)
		{
			//	B = (X1 + Y1)^2;
			//	C = X1^2;
			//	D = Y1^2;
			//	E = C + D;
			//	H = Z1^2;
			//	J = E - 2*H;
			//	X2 = (B - E)*J;
			//	Y2 = E*(C - D);
			//	Z2 = E*J;
	
			block_t tB;
			block_t tC;
			block_t tD;
			block_t E;
			block_t H;
			block_t J;

			mod_add(tB, p_point.m_x, p_point.m_y);
			mod_square(tB, tB);
			mod_square(tC, p_point.m_x);
			mod_square(tD, p_point.m_y);

			mod_add(E, tC, tD);
			mod_square(H, p_point.m_z);

			mod_add(H, H, H);
			mod_negate(H);

			mod_add(J, E, H);

			mod_negate(tD);
			mod_add(tD, tD, tC);
			mod_multiply(p_point.m_y, E, tD);
			mod_multiply(p_point.m_z, E, J);
			
			mod_negate(E);
			mod_add(tB, tB, E);
			mod_multiply(p_point.m_x, tB, J);
		}
	};

	} //namespace


	void Ed521::public_key(std::span<const uint8_t, key_lenght> p_private_key, point_t& p_public_key)
	{
		composite_key(p_private_key, Curve_E521::generator, p_public_key);
	}

	void Ed521::composite_key(std::span<const uint8_t, key_lenght> p_private_key, const point_t& p_public_key, point_t& p_shared_key)
	{
		using block_t = Curve_E521::block_t;
		//using projective coordinates
		//x = X/Z, y = Y/Z

		using projective_point_t = Curve_E521::projective_point_t;
		projective_point_t R0{.m_x{0, 0, 0, 0, 0, 0, 0, 0, 0}, .m_y{1, 0, 0, 0, 0, 0, 0, 0, 0}, .m_z{1, 0, 0, 0, 0, 0, 0, 0, 0}};
		projective_point_t R1;

		memcpy(R1.m_x.data(), p_public_key.m_x.data(), sizeof(block_t));
		memcpy(R1.m_y.data(), p_public_key.m_y.data(), sizeof(block_t));
		R1.m_z[0] = 1;
		R1.m_z[1] = 0;
		R1.m_z[2] = 0;
		R1.m_z[3] = 0;
		R1.m_z[4] = 0;
		R1.m_z[5] = 0;
		R1.m_z[6] = 0;
		R1.m_z[7] = 0;
		R1.m_z[8] = 0;

		block_t skey;
		memcpy(skey.data(), p_private_key.data(), p_private_key.size());

		skey[8] &= 0xFFFF_ui64;

		Curve_E521::order_reduce(skey);

		for(uint8_t j = 0; j < 8; ++j)
		{
			const uint64_t& tunit = skey[j];
			for(uint8_t i = 0; i < 64; ++i)
			{
				if(tunit & (1_ui64 << i))
				{
					Curve_E521::ED_point_add(R1, R0);
				}
				Curve_E521::ED_point_double(R1);
			}
		}

		{
			const uint64_t& tunit = skey[8];
			for(uint8_t i = 0; i < 6; ++i)
			{
				if(tunit & (1_ui64 << i))
				{
					Curve_E521::ED_point_add(R1, R0);
				}
				Curve_E521::ED_point_double(R1);
			}
			if(tunit & (1_ui64 << 6))
			{
				Curve_E521::ED_point_add(R1, R0);
			}
		}

		Curve_E521::mod_inverse(R0.m_z);
		Curve_E521::mod_multiply(reinterpret_cast<block_t&>(p_shared_key.m_x), R0.m_x, R0.m_z);
		Curve_E521::mod_multiply(reinterpret_cast<block_t&>(p_shared_key.m_y), R0.m_y, R0.m_z);
	}












} //namespace crypto
