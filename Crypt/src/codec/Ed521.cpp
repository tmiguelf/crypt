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
			0x302a940a2f19ba6c_ui64,
			0x59d0fb13364838aa_ui64,
			0xae949d568fc99c60_ui64,
			0xf6ecc5ccc72434b1_ui64,
			0x8bf3c9c0c6203913_ui64,
			0xbfd9f42fc6c818ec_ui64,
			0xf90cb2296b2878a3_ui64,
			0x2cb45c48648b189d_ui64,
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

	//	static void order_reduce(block_t& p_val)
	//	{
	//		//TODO
	//
	//
	//
	//
	//
	//	}


	};

	} //namespace
















} //namespace crypto
