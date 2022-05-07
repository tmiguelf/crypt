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
			block_t m_t;
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

	//	static constexpr block_t D
	//	{
	//	};

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
					uint8_t borrow2 = 0;
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
			//TODO
			std::array<uint64_t, 17> temp;

			//======== Multiply ========
			{
				uint64_t mul_carry;
				uint64_t mul_carry_2;
				uint64_t acum;
				std::array<uint8_t, 8> lcarry;
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
					addcarry(lcarry[0], mul_carry, mul_carry_2, &mul_carry);


				//Block 2
				lcarry[0] =
					addcarry(lcarry[1],
						mul_carry,
						umul(p_1[0], p_2[2], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(0,
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
					addcarry(lcarry[0], mul_carry, mul_carry_2, &mul_carry);


				//Block 3
				lcarry[0] =
					addcarry(lcarry[1],
						mul_carry,
						umul(p_1[0], p_2[3], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[1], p_2[2], &mul_carry),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(0,
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
					addcarry(lcarry[0], mul_carry, mul_carry_2, &mul_carry);


				//Block 4
				lcarry[0] =
					addcarry(lcarry[1],
						mul_carry,
						umul(p_1[0], p_2[4], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[1], p_2[3], &mul_carry),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[2], p_2[2], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(0,
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
					addcarry(lcarry[0], mul_carry, mul_carry_2, &mul_carry);


				//Block 5
				lcarry[0] =
					addcarry(lcarry[1],
						mul_carry,
						umul(p_1[0], p_2[5], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[1], p_2[4], &mul_carry),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[2], p_2[3], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[4],
						acum,
						umul(p_1[3], p_2[2], &mul_carry_2),
						&acum);

				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);

				lcarry[4] =
					addcarry(0,
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
					addcarry(lcarry[0], mul_carry, mul_carry_2, &mul_carry);


				//Block 6
				lcarry[0] =
					addcarry(lcarry[1],
						mul_carry,
						umul(p_1[0], p_2[6], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[1], p_2[5], &mul_carry),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[2], p_2[4], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[4],
						acum,
						umul(p_1[3], p_2[3], &mul_carry_2),
						&acum);

				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);

				lcarry[4] =
					addcarry(lcarry[5],
						acum,
						umul(p_1[4], p_2[2], &mul_carry_2),
						&acum);

				Dcarry[3] =
					addcarry(Dcarry[3], mul_carry, mul_carry_2, &mul_carry);

				lcarry[5] =
					addcarry(0,
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
					addcarry(lcarry[0], mul_carry, mul_carry_2, &mul_carry);


				//Block 7
				lcarry[0] =
					addcarry(lcarry[1],
						mul_carry,
						umul(p_1[0], p_2[7], &mul_carry_2),
						&acum);

				lcarry[1] =
					addcarry(lcarry[2],
						acum,
						umul(p_1[1], p_2[6], &mul_carry),
						&acum);

				Dcarry[0] =
					addcarry(Dcarry[0], mul_carry, mul_carry_2, &mul_carry);

				lcarry[2] =
					addcarry(lcarry[3],
						acum,
						umul(p_1[2], p_2[5], &mul_carry_2),
						&acum);

				Dcarry[1] =
					addcarry(Dcarry[1], mul_carry, mul_carry_2, &mul_carry);

				lcarry[3] =
					addcarry(lcarry[4],
						acum,
						umul(p_1[3], p_2[4], &mul_carry_2),
						&acum);

				Dcarry[2] =
					addcarry(Dcarry[2], mul_carry, mul_carry_2, &mul_carry);

				lcarry[4] =
					addcarry(lcarry[5],
						acum,
						umul(p_1[4], p_2[3], &mul_carry_2),
						&acum);

				Dcarry[3] =
					addcarry(Dcarry[3], mul_carry, mul_carry_2, &mul_carry);

				lcarry[5] =
					addcarry(lcarry[6],
						acum,
						umul(p_1[5], p_2[2], &mul_carry_2),
						&acum);

				Dcarry[4] =
					addcarry(Dcarry[4], mul_carry, mul_carry_2, &mul_carry);

				lcarry[6] =
					addcarry(0,
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
					addcarry(lcarry[0], mul_carry, mul_carry_2, &mul_carry);


				//Block 8










			}

		}

	//	static void mod_square(block_t& p_out, const block_t& p_in)
	//	{
	//		//TODO
	//
	//	}

	//	//uses eulers theorem which for primes inv(a) = a^(p-2) mod p
	//	static void mod_inverse(block_t& p_val)
	//	{
	//		//TODO
	//
	//	}

	//	static void ED_point_add(const projective_point_t& p_1, projective_point_t& p_out)
	//	{
	//		//TODO
	//
	//	}

	//	static void ED_point_double(projective_point_t& p_point)
	//	{
	//		//TODO
	//
	//	}



	};

	} //namespace
















} //namespace crypto
