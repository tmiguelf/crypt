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

#include <limits>
#include <tuple>
#include <bit>

#if defined(_M_AMD64) || defined(__amd64__)
#	ifdef _WIN32
#		include <intrin.h>
#	endif
//#	include <immintrin.h>
#else
#	error "Unsuported Architecture"
#endif

#include <CoreLib/Core_Type.hpp>
#include <CoreLib/Core_Endian.hpp>

#include <Crypt/hash/sha2.hpp>


namespace crypto
{
	using namespace core::literals;

#ifdef _WIN32
	static inline uint64_t umul(const uint64_t p_1, const uint64_t p_2, uint64_t* p_out_hi) { return _umul128(p_1, p_2, p_out_hi); };
	static inline uint64_t udiv(const uint64_t p_hi, const uint64_t p_low, const uint64_t p_denom, uint64_t* p_rem) { return _udiv128(p_hi, p_low, p_denom, p_rem); };
#else
	static inline uint64_t umul(uint64_t p_1, const uint64_t p_2, uint64_t* p_out_hi)
	{
		__asm__
		(
			"mul %2;"
			: "+a"(p_1), "=b"(*p_out_hi)
			: "Q"(p_2)
		);
		return p_1;
	}

	static inline uint64_t udiv(uint64_t p_hi, uint64_t p_low, const uint64_t p_denom, uint64_t* p_rem)
	{
		__asm__
		(
			"div %3;"
			: "+a"(p_low), "=d"(*p_rem)
			: "d"(p_hi), "Q"(p_denom)
		);
		return p_low;
	}
#endif

	struct Curve_25519
	{
		//ED: a * x^2 + y^2 = 1 + d * x^2 * y^2
		// a = -1
		// d = -121665/121666
		// P = 2^255-19

		using coord_t = Ed25519::coord_t;
		using point_t = Ed25519::point_t;
		using block_t = std::array<uint64_t, 4>;

		struct projective_point_t
		{
			block_t m_x;
			block_t m_y;
			block_t m_z;
			block_t m_t;
		};

		static constexpr block_t prime
		{
			0xffffffffffffffed,
			0xffffffffffffffff,
			0xffffffffffffffff,
			0x7fffffffffffffff,
		};

		static constexpr block_t order
		{
			0x5812631a5cf5d3ed,
			0x14def9dea2f79cd6,
			0x0000000000000000,
			0x1000000000000000,
		};

	//	static constexpr uint32_t cofactor {0x00000008};

		//Montgomery
	//	static constexpr coord_t U
	//	{
	//		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	//		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	//		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	//		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	//	};
	//
	//	static constexpr coord_t V
	//	{
	//		0x14, 0x2c, 0x31, 0x81, 0x5d, 0x3a, 0x16, 0xd6,
	//		0x4d, 0x9e, 0x83, 0x92, 0x81, 0xb2, 0xc2, 0x6d,
	//		0xb3, 0x2e, 0xb7, 0x88, 0xd3, 0x22, 0xe1, 0x1f,
	//		0x4b, 0x79, 0x5f, 0x47, 0x5e, 0xe6, 0x51, 0x5f,
	//	};
	//
	//	static constexpr uint32_t A{0x00076d06};

		//Edwards
		static constexpr coord_t X
		{
			0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9,
			0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7, 0x2c, 0x69,
			0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0,
			0xfe, 0x53, 0x6e, 0xcd, 0xd3, 0x36, 0x69, 0x21,
		};

		static constexpr coord_t Y
		{
			0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
			0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
			0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
			0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
		};

		static constexpr block_t D
		{
			0x75eb4dca135978a3,
			0x00700a4d4141d8ab,
			0x8cc740797779e898,
			0x52036cee2b6ffe73,
		};

		static constexpr point_t generator{X, Y};

		static bool compare_equal(const block_t& p_1, const block_t& p_2)
		{
			return
				(p_1[0] == p_2[0]) &&
				(p_1[1] == p_2[1]) &&
				(p_1[2] == p_2[2]) &&
				(p_1[3] == p_2[3]);
		}

		static void mod_increment(block_t& p_out, const block_t& p_in)
		{
			//increment
			{
				const block_t& v_1 = reinterpret_cast<const block_t&>(p_in);

				uint8_t carry;
				carry = _addcarry_u64(1    , v_1[0], 0, p_out.data() + 0);
				carry = _addcarry_u64(carry, v_1[1], 0, p_out.data() + 1);
				carry = _addcarry_u64(carry, v_1[2], 0, p_out.data() + 2);
				        _addcarry_u64(carry, v_1[3], 0, p_out.data() + 3);
			}

			//mod
			if
			(
				(p_out[3] == prime[3]) &&
				(p_out[2] == prime[2]) &&
				(p_out[1] == prime[1]) &&
				(p_out[0] >= prime[0])
			)
			{
				uint8_t borrow;
				borrow = _subborrow_u64(0     , p_out[0], prime[0], p_out.data() + 0);
				borrow = _subborrow_u64(borrow, p_out[1], prime[1], p_out.data() + 1);
				borrow = _subborrow_u64(borrow, p_out[2], prime[2], p_out.data() + 2);
				         _subborrow_u64(borrow, p_out[3], prime[3], p_out.data() + 3);
			}
		}

		static void mod_decrement(block_t& p_out, const block_t& p_in)
		{
			if
			(
				p_in[0] == 0 &&
				p_in[1] == 0 &&
				p_in[2] == 0 &&
				p_in[3] == 0
			)
			{
				p_out[0] = prime[0] - 1;
				p_out[1] = prime[1];
				p_out[2] = prime[2];
				p_out[3] = prime[3];
			}
			else
			{
				uint8_t borrow;
				borrow = _subborrow_u64(1     , p_in[0], 0, p_out.data() + 0);
				borrow = _subborrow_u64(borrow, p_in[1], 0, p_out.data() + 1);
				borrow = _subborrow_u64(borrow, p_in[2], 0, p_out.data() + 2);
				         _subborrow_u64(borrow, p_in[3], 0, p_out.data() + 3);
			}
		}

		static void mod_add(block_t& p_out, const block_t& p_1, const block_t& p_2)
		{
			//add
			{
				uint8_t carry;
				carry = _addcarry_u64(0    , p_1[0], p_2[0], p_out.data() + 0);
				carry = _addcarry_u64(carry, p_1[1], p_2[1], p_out.data() + 1);
				carry = _addcarry_u64(carry, p_1[2], p_2[2], p_out.data() + 2);
						_addcarry_u64(carry, p_1[3], p_2[3], p_out.data() + 3);
			}

			//mod
			if
			(
				(p_out[3] & 0x8000000000000000) ||
				(
					(p_out[3] == prime[3]) &&
					(p_out[2] == prime[2]) &&
					(p_out[1] == prime[1]) &&
					(p_out[0] >= prime[0])
				)
			)
			{
				uint8_t borrow;
				borrow = _subborrow_u64(0     , p_out[0], prime[0], p_out.data());
				borrow = _subborrow_u64(borrow, p_out[1], prime[1], p_out.data() + 1);
				borrow = _subborrow_u64(borrow, p_out[2], prime[2], p_out.data() + 2);
				         _subborrow_u64(borrow, p_out[3], prime[3], p_out.data() + 3);
			}
		}

		static void mod_negate(block_t& p_val)
		{
			if(
				p_val[0] == 0 &&
				p_val[1] == 0 &&
				p_val[2] == 0 &&
				p_val[3] == 0)
			{
				return;
			}
			uint8_t borrow;
			borrow = _subborrow_u64(0     , prime[0], p_val[0], p_val.data());
			borrow = _subborrow_u64(borrow, prime[1], p_val[1], p_val.data() + 1);
			borrow = _subborrow_u64(borrow, prime[2], p_val[2], p_val.data() + 2);
			         _subborrow_u64(borrow, prime[3], p_val[3], p_val.data() + 3);
		}

		static void mod_double(block_t& p_val)
		{
			mod_add(p_val, p_val, p_val);
		}


		static void order_reduce(block_t& p_val)
		{
			if(p_val[3] & 0xE000000000000000)
			{
				const uint64_t div = p_val[3] / (order[3] + 1);

				uint64_t mul_carry;
				uint8_t borrow;
				uint64_t tmp;

				borrow = _subborrow_u64(0, p_val[0], umul(order[0], div, &mul_carry), p_val.data());

				borrow = _subborrow_u64(borrow, p_val[1], mul_carry, &tmp);
				if(_subborrow_u64(0, tmp, umul(order[1], div, &mul_carry), p_val.data() + 1))
				{
					++mul_carry;
				}

				//this block is all zeros 0
				borrow = _subborrow_u64(borrow, p_val[2], mul_carry, p_val.data() + 2);

				_subborrow_u64(borrow, p_val[3], umul(order[3], div, &mul_carry), p_val.data() + 3);
			}
			if
			(
				p_val[3] > order[3] ||
				(
					p_val[3] == order[3] &&
					(
						p_val[2] ||
						(
							p_val[1] > order[1] ||
							(
								p_val[1] == order[1] &&
								p_val[0] >= order[0]
							)
						)
					)
				)
			)
			{
				uint8_t borrow;
				borrow = _subborrow_u64(0     , p_val[0], order[0], p_val.data());
				borrow = _subborrow_u64(borrow, p_val[1], order[1], p_val.data() + 1);
				borrow = _subborrow_u64(borrow, p_val[2], order[2], p_val.data() + 2);
				         _subborrow_u64(borrow, p_val[3], order[3], p_val.data() + 3);
			}
		}


		static void mul_reduce(std::array<uint64_t, 8>& p_val)
		{
			constexpr uint64_t max			= std::numeric_limits<uint64_t>::max();
			constexpr uint64_t first_block	= std::numeric_limits<uint64_t>::max() - 18;
			constexpr uint64_t last_block	= 0x7FFFFFFFFFFFFFFF;

			if(p_val[7])
			{
				constexpr uint64_t offset2 = 38;

				uint64_t mul_carry;
				uint64_t mul_carry2;
				uint64_t acum;
				uint8_t lcarry;
				uint8_t lcarry2;

				//block 1
				lcarry = _addcarry_u64(
					0,
					p_val[0],
					umul(p_val[4], offset2, &mul_carry),
					p_val.data());

				//block 2
				lcarry = _addcarry_u64(
					lcarry,
					mul_carry,
					umul(p_val[5], offset2, &mul_carry2),
					&acum);

				lcarry2 = _addcarry_u64(
					0,
					p_val[1],
					acum,
					p_val.data() + 1);

				//block 3
				lcarry = _addcarry_u64(
					lcarry,
					mul_carry2,
					umul(p_val[6], offset2, &mul_carry),
					&acum);

				lcarry2 = _addcarry_u64(
					lcarry2,
					p_val[2],
					acum,
					p_val.data() + 2);

				//block 4
				lcarry = _addcarry_u64(
					lcarry,
					mul_carry,
					umul(p_val[7], offset2, &mul_carry2),
					&acum);

				lcarry2 = _addcarry_u64(
					lcarry2,
					p_val[3],
					acum,
					p_val.data() + 3);

				//block5
				_addcarry_u64(lcarry, mul_carry2, lcarry2, p_val.data() + 4);

				if(p_val[4])
				{
					lcarry = _addcarry_u64(0     , p_val[0], umul(p_val[4], offset2, &mul_carry), p_val.data());
					lcarry = _addcarry_u64(lcarry, p_val[1], 0, p_val.data() + 1);
					lcarry = _addcarry_u64(lcarry, p_val[2], 0, p_val.data() + 2);
					if(      _addcarry_u64(lcarry, p_val[3], 0, p_val.data() + 3))
					{
						lcarry = _addcarry_u64(0     , p_val[0], offset2, p_val.data());
						lcarry = _addcarry_u64(lcarry, p_val[1], 0      , p_val.data() + 1);
						lcarry = _addcarry_u64(lcarry, p_val[2], 0      , p_val.data() + 2);
						         _addcarry_u64(lcarry, p_val[3], 0      , p_val.data() + 3);
					}
				}
			}
			else if(p_val[6] || p_val[5] || p_val[4])
			{
				constexpr uint64_t offset2 = 38;

				uint64_t mul_carry;
				uint64_t mul_carry2;
				uint64_t acum;
				uint8_t lcarry;
				uint8_t lcarry2;

				//block 1
				lcarry = _addcarry_u64(
					0,
					p_val[0],
					umul(p_val[4], offset2, &mul_carry),
					p_val.data());

				//block 2
				lcarry = _addcarry_u64(
					lcarry,
					mul_carry,
					umul(p_val[5], offset2, &mul_carry2),
					&acum);

				lcarry2 = _addcarry_u64(
					0,
					p_val[1],
					acum,
					p_val.data() + 1);

				//block 3
				lcarry = _addcarry_u64(
					lcarry,
					mul_carry2,
					umul(p_val[6], offset2, &mul_carry),
					&acum);

				lcarry2 = _addcarry_u64(
					lcarry2,
					p_val[2],
					acum,
					p_val.data() + 2);

				//block 4
				_addcarry_u64(lcarry2, mul_carry, 0, &mul_carry);
				if(_addcarry_u64(lcarry, p_val[3], mul_carry, p_val.data() + 3))
				{
					lcarry = _addcarry_u64(0     , p_val[0], offset2, p_val.data());
					lcarry = _addcarry_u64(lcarry, p_val[1], 0      , p_val.data() + 1);
					lcarry = _addcarry_u64(lcarry, p_val[2], 0      , p_val.data() + 2);
					         _addcarry_u64(lcarry, p_val[3], 0      , p_val.data() + 3);
				}
			}
			if(p_val[3] & 0x8000000000000000)
			{
				constexpr uint64_t offset = 19;
				uint8_t lcarry;

				lcarry = _addcarry_u64(0     , p_val[0], offset, p_val.data());
				lcarry = _addcarry_u64(lcarry, p_val[1], 0     , p_val.data() + 1);
				lcarry = _addcarry_u64(lcarry, p_val[2], 0     , p_val.data() + 2);
				         _addcarry_u64(lcarry, p_val[3] & 0x7FFFFFFFFFFFFFFF, 0, p_val.data() + 3);
				if(p_val[3] & 0x8000000000000000)
				{
					lcarry = _addcarry_u64(0     , p_val[0], offset, p_val.data());
					lcarry = _addcarry_u64(lcarry, p_val[1], 0     , p_val.data() + 1);
					lcarry = _addcarry_u64(lcarry, p_val[2], 0     , p_val.data() + 2);
					         _addcarry_u64(lcarry, p_val[3] & 0x7FFFFFFFFFFFFFFF, 0, p_val.data() + 3);
				}
			}
			if(p_val[0] >= first_block && p_val[1] == max && p_val[2] == max && p_val[3] == last_block)
			{
				constexpr uint64_t offset = 19;
				uint8_t lcarry;
				lcarry = _addcarry_u64(0     , p_val[0], offset, p_val.data());
				lcarry = _addcarry_u64(lcarry, p_val[1], 0     , p_val.data() + 1);
				lcarry = _addcarry_u64(lcarry, p_val[2], 0     , p_val.data() + 2);
				         _addcarry_u64(lcarry, p_val[3], 0     , p_val.data() + 3);
				p_val[3] &= 0x7FFFFFFFFFFFFFFF;
			}
		}

		static void mod_multiply(block_t& p_out, const block_t& p_1, const block_t& p_2)
		{
			std::array<uint64_t, 8> temp;

			//======== Multiply ========
			{
				uint64_t mul_carry;
				uint64_t mul_carry_2;
				uint64_t acum;
				uint8_t lcarry_A;
				uint8_t lcarry_B;
				uint8_t lcarry_C;
				uint8_t lcarry_D;
				uint8_t Dcarry_A;
				uint8_t Dcarry_B;
				uint8_t Dcarry_C;


				//Block 0
				temp[0] = umul(p_1[0], p_2[0], &mul_carry);


				//Block 1
				lcarry_A =
					_addcarry_u64(0,
						mul_carry,
						umul(p_1[0], p_2[1], &mul_carry_2),
						&acum);

				lcarry_B =
					_addcarry_u64(0,
						acum,
						umul(p_1[1], p_2[0], &mul_carry),
						temp.data() + 1);

				//--
				Dcarry_A =
					_addcarry_u64(lcarry_A, mul_carry, mul_carry_2, &mul_carry);


				//Block 2
				lcarry_A =
					_addcarry_u64(lcarry_B,
						mul_carry,
						umul(p_1[0], p_2[2], &mul_carry_2),
						&acum);

				lcarry_B =
					_addcarry_u64(0,
						acum,
						umul(p_1[1], p_2[1], &mul_carry),
						&acum);

				Dcarry_A =
					_addcarry_u64(Dcarry_A, mul_carry, mul_carry_2, &mul_carry);

				lcarry_C =
					_addcarry_u64(0,
						acum,
						umul(p_1[2], p_2[0], &mul_carry_2),
						temp.data() + 2);

				//--
				Dcarry_B =
					_addcarry_u64(lcarry_A, mul_carry, mul_carry_2, &mul_carry);


				//Block 3
				lcarry_A =
					_addcarry_u64(lcarry_B,
						mul_carry,
						umul(p_1[0], p_2[3], &mul_carry_2),
						&acum);

				lcarry_B =
					_addcarry_u64(lcarry_C,
						acum,
						umul(p_1[1], p_2[2], &mul_carry),
						&acum);

				Dcarry_A =
					_addcarry_u64(Dcarry_A, mul_carry, mul_carry_2, &mul_carry);

				lcarry_C =
					_addcarry_u64(0,
						acum,
						umul(p_1[2], p_2[1], &mul_carry_2),
						&acum);

				Dcarry_B =
					_addcarry_u64(Dcarry_B, mul_carry, mul_carry_2, &mul_carry);

				lcarry_D =
					_addcarry_u64(0,
						acum,
						umul(p_1[3], p_2[0], &mul_carry_2),
						temp.data() + 3);

				//--
				Dcarry_C =
					_addcarry_u64(lcarry_A, mul_carry, mul_carry_2, &mul_carry);


				//Block 4
				lcarry_A =
					_addcarry_u64(lcarry_B,
						mul_carry,
						umul(p_1[1], p_2[3], &mul_carry_2),
						&acum);

				lcarry_B =
					_addcarry_u64(lcarry_C,
						acum,
						umul(p_1[2], p_2[2], &mul_carry),
						&acum);

				Dcarry_A =
					_addcarry_u64(Dcarry_A, mul_carry + lcarry_A, mul_carry_2, &mul_carry);

				lcarry_C =
					_addcarry_u64(lcarry_D,
						acum,
						umul(p_1[3], p_2[1], &mul_carry_2),
						temp.data() + 4);

				//--
				Dcarry_B =
					_addcarry_u64(Dcarry_B, mul_carry, mul_carry_2 + Dcarry_C, &mul_carry);


				//Block 5
				lcarry_A =
					_addcarry_u64(lcarry_B,
						mul_carry,
						umul(p_1[2], p_2[3], &mul_carry_2),
						&acum);

				lcarry_B =
					_addcarry_u64(lcarry_C,
						acum,
						umul(p_1[3], p_2[2], &mul_carry),
						temp.data() + 5);

				//--
				Dcarry_A =
					_addcarry_u64(Dcarry_A, mul_carry + lcarry_A, mul_carry_2 + Dcarry_B, &mul_carry);


				//Block 6
				lcarry_A =
					_addcarry_u64(lcarry_B,
						mul_carry,
						umul(p_1[3], p_2[3], &mul_carry_2),
						temp.data() + 6);


				//Block 7
				_addcarry_u64(Dcarry_A, mul_carry_2, lcarry_A, temp.data() + 7);
			}

			mul_reduce(temp);
			memcpy(p_out.data(), temp.data(), sizeof(block_t));
		}

		static void mod_square(block_t& p_out, const block_t& p_in)
		{
			std::array<uint64_t, 8> temp;

			uint64_t mul_carry;
			uint64_t mul_carry_2;
			uint64_t mul_carry_3;
			uint64_t acum;
			uint8_t lcarry_A;
			uint8_t lcarry_B;

			uint8_t lcarry_2A;
			uint8_t lcarry_2B;


			//Block 0
			temp[0] = umul(p_in[0], p_in[0], &mul_carry);

			//Block 1
			acum = umul(p_in[0], p_in[1], &mul_carry_2);
			lcarry_A = _addcarry_u64(0, acum, acum, &acum);
			lcarry_B = _addcarry_u64(0, acum, mul_carry, temp.data() + 1);

			//Block 2
			lcarry_2A =
				_addcarry_u64(
					0,
					mul_carry_2,
					umul(p_in[0], p_in[2], &mul_carry),
					&acum);

			lcarry_A = _addcarry_u64(lcarry_A, acum, acum, &acum);

			lcarry_B =
				_addcarry_u64(
					lcarry_B,
					acum,
					umul(p_in[1], p_in[1], &mul_carry_2),
					temp.data() + 2);

			//Block 3
			lcarry_2A =
				_addcarry_u64(
					lcarry_2A,
					mul_carry,
					umul(p_in[0], p_in[3], &mul_carry_3),
					&acum);

			lcarry_2B =
				_addcarry_u64(
					0,
					acum,
					umul(p_in[1], p_in[2], &mul_carry),
					&acum);

			lcarry_A = _addcarry_u64(lcarry_A, acum, acum, &acum);
			lcarry_B = _addcarry_u64(lcarry_B, acum, mul_carry_2, temp.data() + 3);


			//Block 4
			lcarry_2A =
				_addcarry_u64(
					lcarry_2A,
					mul_carry,
					umul(p_in[1], p_in[3], &mul_carry_2),
					&acum);

			lcarry_2B = _addcarry_u64(lcarry_2B, acum, mul_carry_3, &acum);
			lcarry_A  = _addcarry_u64(lcarry_A, acum, acum, &acum);

			lcarry_B = _addcarry_u64(
				lcarry_B,
				umul(p_in[2], p_in[2], &mul_carry),
				acum,
				temp.data() + 4);


			//Block 5
			lcarry_2A =
				_addcarry_u64(
					lcarry_2A,
					umul(p_in[2], p_in[3], &mul_carry_3),
					mul_carry_2 + lcarry_2B,
					&acum);

			lcarry_A = _addcarry_u64(lcarry_A, acum, acum, &acum);
			lcarry_B = _addcarry_u64(lcarry_B, acum, mul_carry, temp.data() + 5);

			//Block 6
			lcarry_A =
				_addcarry_u64(lcarry_A,
					mul_carry_3 + lcarry_2A,
					umul(p_in[3], p_in[3], &mul_carry),
					&acum);

			lcarry_B = _addcarry_u64(lcarry_B, acum, mul_carry_3 + lcarry_2A, temp.data() + 6);

			//Block 7
			_addcarry_u64(lcarry_A, mul_carry, lcarry_B, temp.data() + 7);

			mul_reduce(temp);
			memcpy(p_out.data(), temp.data(), sizeof(block_t));
		}

		//uses eulers theorem which for primes inv(a) = a^(p-2) mod p
		static void mod_inverse(block_t& p_val)
		{
#if 1
			block_t k0;
			block_t k1;
			block_t accum;

			memcpy(k0.data(), p_val.data(), sizeof(block_t));
			mod_square(k1, k0);

			{
				mod_square(accum, k1);
				mod_square(accum, accum); // bit 3
			}

			mod_multiply(k0, k0, k1); //== 2 fill

			{
				mod_multiply(accum, accum, k0); // bits 0 and 1
			}

			{
				block_t temp;
				mod_square(temp, k0);
				mod_square(temp, temp);
				mod_multiply(k1, k0, temp); //== 4 fill

				mod_square(temp, temp);
				mod_square(temp, temp);
				mod_square(temp, temp);
				mod_multiply(accum, accum, temp); // bits 5 and 6
			}

			mod_square(k0, k1);
			mod_square(k0, k0);
			mod_square(k0, k0);
			mod_square(k0, k0);
			mod_multiply(k1, k1, k0); //== 8 fill


			mod_square(k0, k1);
			for(uint8_t i = 0; i < 6; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(accum, accum, k0);
			mod_square(k0, k0);
			mod_multiply(k1, k1, k0); //== 16 fill


			mod_square(k0, k1);
			for(uint8_t i = 0; i < 14; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(accum, accum, k0);
			mod_square(k0, k0);
			mod_multiply(k1, k1, k0); //== 32 fill


			mod_square(k0, k1);
			for(uint8_t i = 0; i < 30; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(accum, accum, k0);
			mod_square(k0, k0);
			mod_multiply(k1, k1, k0); //== 64 fill

			mod_square(k0, k1);
			for(uint8_t i = 0; i < 62; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(accum, accum, k0);
			mod_square(k0, k0);
			mod_multiply(k1, k1, k0); //== 128 fill

			mod_square(k0, k1);
			for(uint8_t i = 0; i < 126; ++i)
			{
				mod_square(k0, k0);
			}
			mod_multiply(p_val, accum, k0);
#else
			block_t k;
			block_t accum;
			memcpy(accum.data(), p_val.data(), sizeof(block_t));

			mod_square(k, accum);
			mod_multiply(accum, accum, k);

			mod_square(k, k);

			mod_square(k, k);
			mod_multiply(accum, accum, k);

			mod_square(k, k);

			for(uint8_t i = 5; i < 254; ++i)
			{
				mod_square(k, k);
				mod_multiply(accum, accum, k);
			}
			mod_square(k, k);
			mod_multiply(p_val, accum, k);
#endif
		}

		static void ED_point_add(const projective_point_t& p_1, projective_point_t& p_out)
		{
			//	A = (Y1-X1)*(Y2-X2)
			//	B = (Y1+X1)*(Y2+X2)
			//	C = T1*2*d*T2
			//	D = Z1*2*Z2
			//	E = B-A
			//	F = D-C
			//	G = D+C
			//	H = B+A
			//	X3 = E*F
			//	Y3 = G*H
			//	T3 = E*H
			//	Z3 = F*G

			block_t E;
			block_t F;
			block_t G;
			block_t H;

			{
				block_t tA;
				block_t tB;
				{
					block_t yx1;
					block_t yx2;

					memcpy(yx1.data(), p_1.m_x.data(), sizeof(block_t));
					memcpy(yx2.data(), p_out.m_x.data(), sizeof(block_t));
					mod_negate(yx1);
					mod_negate(yx2);

					mod_add(yx1, yx1, p_1.m_y);
					mod_add(yx2, yx2, p_out.m_y);
					mod_multiply(tA, yx1, yx2);

					mod_add(yx1, p_1.m_x, p_1.m_y);
					mod_add(yx2, p_out.m_x, p_out.m_y);

					mod_multiply(tB, yx1, yx2);
				}

				mod_add(H, tA, tB);
				mod_negate(tA);
				mod_add(E, tA, tB);
			}
			{
				block_t tC;
				block_t tD;

				mod_multiply(tC, p_1.m_t, p_out.m_t);
				mod_multiply(tC, tC, D);
				mod_double(tC);


				mod_multiply(tD, p_1.m_z, p_out.m_z);
				mod_double(tD);

				mod_add(G, tD, tC);
				mod_negate(tC);
				mod_add(F, tD, tC);
			}

			mod_multiply(p_out.m_x, E, F);
			mod_multiply(p_out.m_y, G, H);
			mod_multiply(p_out.m_z, F, G);
			mod_multiply(p_out.m_t, E, H);
		}

		static void ED_point_double(projective_point_t& p_point)
		{
			//	A = X1^2
			//	B = Y1^2
			//	C = 2*Z1^2
			//	H = A+B
			//	E = H-(X1+Y1)^2
			//	G = A-B
			//	F = C+G
			//	X3 = E*F
			//	Y3 = G*H
			//	T3 = E*H
			//	Z3 = F*G

			block_t E;
			block_t F;
			block_t G;
			block_t H;

			{
				block_t tA;
				block_t tB;
				mod_square(tA, p_point.m_x);
				mod_square(tB, p_point.m_y);
				
				mod_add(H, tA, tB);
				mod_negate(tB);
				mod_add(G, tA, tB);
			}

			mod_square(F, p_point.m_z);
			mod_double(F);
			mod_add(F, F, G);

			mod_add(E, p_point.m_x, p_point.m_y);
			mod_square(E, E);
			mod_negate(E);
			mod_add(E, E, H);

			mod_multiply(p_point.m_x, E, F);
			mod_multiply(p_point.m_y, G, H);
			mod_multiply(p_point.m_z, F, G);
			mod_multiply(p_point.m_t, E, H);
		}

	};


	void Ed25519::public_key(std::span<const uint8_t, key_lenght> p_private_key, point_t& p_public_key)
	{
		composite_key(p_private_key, Curve_25519::generator, p_public_key);
	}

	void Ed25519::composite_key(std::span<const uint8_t, key_lenght> p_private_key, const point_t& p_public_key, point_t& p_shared_key)
	{
		//TODO: Mod private key in relation to the order


		using block_t = Curve_25519::block_t;
		//using projective coordinates
		//x = X/Z, y = Y/Z, x * y = T/Z

		using projective_point_t = Curve_25519::projective_point_t;
		projective_point_t R0{.m_x{0, 0, 0, 0}, .m_y{1, 0, 0, 0}, .m_z{1, 0, 0, 0}, .m_t{0, 0, 0, 0}};
		projective_point_t R1;

		memcpy(R1.m_x.data(), p_public_key.m_x.data(), sizeof(block_t));
		memcpy(R1.m_y.data(), p_public_key.m_y.data(), sizeof(block_t));
		R1.m_z[0] = 1;
		R1.m_z[1] = 0;
		R1.m_z[2] = 0;
		R1.m_z[3] = 0;

		Curve_25519::mod_multiply(R1.m_t, R1.m_x, R1.m_y);

		block_t skey;
		memcpy(skey.data(), p_private_key.data(), sizeof(block_t));

		Curve_25519::order_reduce(skey);

		for(uint8_t j = 0; j < 3; ++j)
		{
			const uint64_t& tunit = skey[j];
			for(uint8_t i = 0; i < 64; ++i)
			{
				if(tunit & (1_ui64 << i))
				{
					Curve_25519::ED_point_add(R1, R0);
				}
				Curve_25519::ED_point_double(R1);
			}
		}

		{
			const uint64_t& tunit = skey[3];
			for(uint8_t i = 0; i < 60; ++i)
			{
				if(tunit & (1_ui64 << i))
				{
					Curve_25519::ED_point_add(R1, R0);
				}
				Curve_25519::ED_point_double(R1);
			}
			if(tunit & (1_ui64 << 60))
			{
				Curve_25519::ED_point_add(R1, R0);
			}
		}

		Curve_25519::mod_inverse(R0.m_z);
		Curve_25519::mod_multiply(reinterpret_cast<block_t&>(p_shared_key.m_x), R0.m_x, R0.m_z);
		Curve_25519::mod_multiply(reinterpret_cast<block_t&>(p_shared_key.m_y), R0.m_y, R0.m_z);
	}


	void Ed25519::key_compress(const point_t& p_public_key, std::span<uint8_t, key_lenght> p_compressed_key)
	{
		memcpy(p_compressed_key.data(), p_public_key.m_y.data(), key_lenght);
		p_compressed_key[31] |= static_cast<uint8_t>(p_public_key.m_x[0] << 7);
	}

	bool Ed25519::key_expand(const std::span<const uint8_t, key_lenght> p_compressed_key, point_t& p_public_key)
	{
		memcpy(p_public_key.m_y.data(), p_compressed_key.data(), key_lenght);
		p_public_key.m_y[31] &= 0x7F;

		const Curve_25519::block_t& t_y = reinterpret_cast<const Curve_25519::block_t&>(p_public_key.m_y);

		const bool x_bit = p_compressed_key[31] & 0x80 ? true : false;

		if(
			t_y[3] == 0x7FFFFFFFFFFFFFFF &&
			t_y[2] == 0xFFFFFFFFFFFFFFFF &&
			t_y[1] == 0xFFFFFFFFFFFFFFFF &&
			t_y[0] >= 0xFFFFFFFFFFFFFFED)
		{
			return false;
		}

		Curve_25519::block_t accum;
		{
			Curve_25519::block_t u;
			Curve_25519::block_t v;
			{
				Curve_25519::block_t uv_3;
				{
					{
						Curve_25519::block_t y2;
						Curve_25519::mod_square(y2, t_y);
						Curve_25519::mod_decrement(u, y2);

						if(Curve_25519::compare_equal(u, {0, 0, 0, 0}))
						{
							if(x_bit)
							{
								return false;
							}
							memset(p_public_key.m_x.data(), 0, key_lenght);
							return true;
						}

						Curve_25519::mod_multiply(y2, y2, Curve_25519::D);
						Curve_25519::mod_increment(v, y2);
					}

					Curve_25519::block_t v2;
					Curve_25519::mod_multiply(uv_3, u, v);
					Curve_25519::mod_square(v2, v);
					Curve_25519::mod_multiply(uv_3, uv_3, v2);
					Curve_25519::mod_square(v2, v2);
					Curve_25519::mod_multiply(accum, uv_3, v2);
				}

				{
					Curve_25519::block_t k0;
					Curve_25519::block_t k1;

					Curve_25519::mod_square(k0, accum);
					Curve_25519::mod_multiply(k1, accum, k0); //== 2 fill

					Curve_25519::mod_square(k0, k1);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_multiply(accum, accum, k0);

					Curve_25519::mod_multiply(k1, k1, k0); //== 4 fill

					Curve_25519::mod_square(k0, k1);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_multiply(k1, k1, k0); //== 8 fill

					Curve_25519::mod_square(k0, k1);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_multiply(accum, accum, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_multiply(k1, k1, k0); //== 16 fill

					Curve_25519::mod_square(k0, k1);
					for(uint8_t i = 0; i < 11; ++i)
					{
						Curve_25519::mod_square(k0, k0);
					}
					Curve_25519::mod_multiply(accum, accum, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_multiply(k1, k1, k0); //== 32 fill

					Curve_25519::mod_square(k0, k1);
					for(uint8_t i = 0; i < 27; ++i)
					{
						Curve_25519::mod_square(k0, k0);
					}
					Curve_25519::mod_multiply(accum, accum, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_multiply(k1, k1, k0); //== 64 fill

					Curve_25519::mod_square(k0, k1);
					for(uint8_t i = 0; i < 59; ++i)
					{
						Curve_25519::mod_square(k0, k0);
					}
					Curve_25519::mod_multiply(accum, accum, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_square(k0, k0);
					Curve_25519::mod_multiply(k1, k1, k0); //== 128 fill

					Curve_25519::mod_square(k0, k1);
					for(uint8_t i = 0; i < 123; ++i)
					{
						Curve_25519::mod_square(k0, k0);
					}
					Curve_25519::mod_multiply(accum, accum, k0);
				}

				Curve_25519::mod_multiply(accum, accum, uv_3);
			}

			{
				Curve_25519::block_t vx2;
				Curve_25519::mod_square(vx2, accum);
				Curve_25519::mod_multiply(vx2, vx2, v);
				if(!Curve_25519::compare_equal(vx2, u))
				{
					Curve_25519::mod_negate(u);
					if(!Curve_25519::compare_equal(vx2, u))
					{
						return false;
					}

					Curve_25519::mod_multiply(accum, accum,
						{0xc4ee1b274a0ea0b0,
						0x2f431806ad2fe478,
						0x2b4d00993dfbd7a7,
						0x2b8324804fc1df0b});
				}
			}
		}

		if((accum[0] & 0x01 ? true : false) != x_bit)
		{
			Curve_25519::mod_negate(accum);
		}

		memcpy(p_public_key.m_x.data(), accum.data(), key_lenght);

		return true;
	}


	void Ed25519::hashed_private_key(
		std::span<const uint8_t, key_lenght> p_input,
		std::span<uint8_t, key_lenght> p_output)
	{

		Curve_25519::block_t temp;

		{
			crypto::SHA2_512 ash;
			ash.reset();
			ash.update(p_input);
			ash.finalize();

			const crypto::SHA2_512::digest_t& res = ash.digest();

			static_assert(std::is_same_v<std::remove_cvref_t<decltype(res)>::value_type, uint64_t>);

			temp[0] = core::endian_host2big(res[0]);
			temp[1] = core::endian_host2big(res[1]);
			temp[2] = core::endian_host2big(res[2]);
			temp[3] = core::endian_host2big(res[3]);
		}

		{
			std::array<uint8_t, key_lenght>& conv = *reinterpret_cast<std::array<uint8_t, key_lenght>*>(&temp);
			conv[0] &= 0xF8;
			conv[31] &= 0x7F;
			conv[31] |= 0x40;
		}
		Curve_25519::order_reduce(temp);

		memcpy(p_output.data(), temp.data(), key_lenght);
	}

	void Ed25519::reduce_private_key(std::span<uint8_t, key_lenght> p_private_key)
	{
		Curve_25519::block_t temp;
		memcpy(temp.data(), p_private_key.data(), key_lenght);
		Curve_25519::order_reduce(temp);
		memcpy(p_private_key.data(), temp.data(), key_lenght);
	}



} //namespace crypto
