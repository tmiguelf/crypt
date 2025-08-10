//======== ======== ======== ======== ======== ======== ======== ========
///	\file
///
///	\copyright
///		Copyright (c) Tiago Miguel Oliveira Freire
///
///		Permission is hereby granted, free of charge, to any person obtaining a copy
///		of this software and associated documentation files (the "Software"),
///		to copy, modify, publish, and/or distribute copies of the Software,
///		and to permit persons to whom the Software is furnished to do so,
///		subject to the following conditions:
///
///		The copyright notice and this permission notice shall be included in all
///		copies or substantial portions of the Software.
///		The copyrighted work, or derived works, shall not be used to train
///		Artificial Intelligence models of any sort; or otherwise be used in a
///		transformative way that could obfuscate the source of the copyright.
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

#include <cstring>
#include <limits>

#include <CoreLib/core_type.hpp>
#include <CoreLib/core_endian.hpp>

#include <Crypt/hash/sha2.hpp>

#include "extended_precision.hpp"


#if !defined(_M_AMD64) && !defined(__amd64__)
#	error "Unsuported Architecture"
#endif

namespace crypto
{
	using namespace core::literals;

	namespace
	{

	struct Curve_25519
	{
		//ED: a * x^2 + y^2 = 1 + d * x^2 * y^2
		// a = -1
		// d = -121665/121666
		// P = 2^255-19

		using coord_t = Ed25519::coord_t;
		using point_t = Ed25519::point_t;
		using block_t = std::array<uint64_t, 4>;

		struct projective_point_t: public point_t
		{
			block_t m_z;
			block_t m_t;
		};

		static constexpr block_t prime
		{
			0xFFFFFFFFFFFFFFED_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0xFFFFFFFFFFFFFFFF_ui64,
			0x7FFFFFFFFFFFFFFF_ui64,
		};

		static constexpr block_t order
		{
			0x5812631A5CF5D3ED_ui64,
			0x14DEF9DEA2F79CD6_ui64,
			0x0000000000000000_ui64,
			0x1000000000000000_ui64,
		};

	//	static constexpr uint32_t cofactor {0x00000008};

		//Montgomery
	//	static constexpr std::array<uint8_t 32> U
	//	{
	//		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	//		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	//		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	//		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	//	};
	//
	//	static constexpr std::array<uint8_t 32> V
	//	{
	//		0x14, 0x2C, 0x31, 0x81, 0x5D, 0x3A, 0x16, 0xD6,
	//		0x4D, 0x9E, 0x83, 0x92, 0x81, 0xB2, 0xC2, 0x6D,
	//		0xB3, 0x2E, 0xB7, 0x88, 0xD3, 0x22, 0xE1, 0x1F,
	//		0x4B, 0x79, 0x5F, 0x47, 0x5E, 0xE6, 0x51, 0x5F,
	//	};
	//
	//	static constexpr uint32_t A{0x00076D06};

		//Edwards
		static constexpr block_t D
		{
			0x75EB4DCA135978A3_ui64,
			0x00700A4D4141D8AB_ui64,
			0x8CC740797779E898_ui64,
			0x52036CEE2B6FFE73_ui64,
		};

		static constexpr coord_t X
		{
			0xC9562D608F25D51A_ui64,
			0x692CC7609525A7B2_ui64,
			0xC0A4E231FDD6DC5C_ui64,
			0x216936D3CD6E53FE_ui64,
		};

		static constexpr coord_t Y
		{
			0x6666666666666658_ui64,
			0x6666666666666666_ui64,
			0x6666666666666666_ui64,
			0x6666666666666666_ui64,
		};

		static constexpr point_t generator{X, Y};

		static constexpr point_t neutral
		{
			.m_x{0, 0, 0, 0},
			.m_y{1, 0, 0, 0}
		};


		static bool compare_equal(const block_t& p_1, const block_t& p_2)
		{
			return
				(p_1[0] == p_2[0]) &&
				(p_1[1] == p_2[1]) &&
				(p_1[2] == p_2[2]) &&
				(p_1[3] == p_2[3]);
		}


		static void mpi_multiply(std::array<uint64_t, 8>& p_out, const block_t& p_1, const block_t& p_2)
		{
			block_t mid;
			std::array<uint64_t, 3> mul_carries;
			uint8_t carry;

			p_out[0] = umul(p_1[0], p_2[0], mul_carries[0]);
			p_out[1] = umul(p_1[0], p_2[1], mul_carries[1]);
			p_out[2] = umul(p_1[0], p_2[2], mul_carries[2]);
			p_out[3] = umul(p_1[0], p_2[3], p_out[4]);

			carry = addcarry(0    , p_out[1], mul_carries[0], p_out[1]);
			carry = addcarry(carry, p_out[2], mul_carries[1], p_out[2]);
			carry = addcarry(carry, p_out[3], mul_carries[2], p_out[3]);
			p_out[4] += carry;


			mid[0] = umul(p_1[1], p_2[0], mul_carries[0]);
			mid[1] = umul(p_1[1], p_2[1], mul_carries[1]);
			mid[2] = umul(p_1[1], p_2[2], mul_carries[2]);
			mid[3] = umul(p_1[1], p_2[3], p_out[5]      );

			carry = addcarry(0    , p_out[1], mid[0], p_out[1]);
			carry = addcarry(carry, p_out[2], mid[1], p_out[2]);
			carry = addcarry(carry, p_out[3], mid[2], p_out[3]);
			carry = addcarry(carry, p_out[4], mid[3], p_out[4]);
			p_out[5] += carry;

			carry = addcarry(0    , p_out[2], mul_carries[0], p_out[2]);
			carry = addcarry(carry, p_out[3], mul_carries[1], p_out[3]);
			carry = addcarry(carry, p_out[4], mul_carries[2], p_out[4]);
			p_out[5] += carry;


			mid[0] = umul(p_1[2], p_2[0], mul_carries[0]);
			mid[1] = umul(p_1[2], p_2[1], mul_carries[1]);
			mid[2] = umul(p_1[2], p_2[2], mul_carries[2]);
			mid[3] = umul(p_1[2], p_2[3], p_out[6]      );

			carry = addcarry(0    , p_out[2], mid[0], p_out[2]);
			carry = addcarry(carry, p_out[3], mid[1], p_out[3]);
			carry = addcarry(carry, p_out[4], mid[2], p_out[4]);
			carry = addcarry(carry, p_out[5], mid[3], p_out[5]);
			p_out[6] += carry;

			carry = addcarry(0    , p_out[3], mul_carries[0], p_out[3]);
			carry = addcarry(carry, p_out[4], mul_carries[1], p_out[4]);
			carry = addcarry(carry, p_out[5], mul_carries[2], p_out[5]);
			p_out[6] += carry;


			mid[0] = umul(p_1[3], p_2[0], mul_carries[0]);
			mid[1] = umul(p_1[3], p_2[1], mul_carries[1]);
			mid[2] = umul(p_1[3], p_2[2], mul_carries[2]);
			mid[3] = umul(p_1[3], p_2[3], p_out[7]      );

			carry = addcarry(0    , p_out[3], mid[0], p_out[3]);
			carry = addcarry(carry, p_out[4], mid[1], p_out[4]);
			carry = addcarry(carry, p_out[5], mid[2], p_out[5]);
			carry = addcarry(carry, p_out[6], mid[3], p_out[6]);
			p_out[7] += carry;

			carry = addcarry(0    , p_out[4], mul_carries[0], p_out[4]);
			carry = addcarry(carry, p_out[5], mul_carries[1], p_out[5]);
			carry = addcarry(carry, p_out[6], mul_carries[2], p_out[6]);
			p_out[7] += carry;
		}


		static void mpi_square(std::array<uint64_t, 8>& p_out, const block_t& p_in)
		{
			block_t mul_carries;
			std::array<uint64_t, 3> mid;
			uint8_t carry;

			p_out[1] = umul(p_in[0], p_in[1], mul_carries[0]);
			p_out[2] = umul(p_in[0], p_in[2], mul_carries[1]);
			p_out[3] = umul(p_in[0], p_in[3], p_out[4]);

			carry = addcarry(0    , p_out[2], mul_carries[0], p_out[2]);
			carry = addcarry(carry, p_out[3], mul_carries[1], p_out[3]);
			p_out[4] += carry;

			mid[0] = umul(p_in[1], p_in[2], mul_carries[0]);
			mid[1] = umul(p_in[1], p_in[3], p_out[5]);

			carry = addcarry(0    , p_out[3], mid[0], p_out[3]);
			carry = addcarry(carry, p_out[4], mid[1], p_out[4]);
			p_out[5] += carry;

			carry = addcarry(0, p_out[4], mul_carries[0], p_out[4]);
			p_out[5] += carry;

			carry = addcarry(0, p_out[5], umul(p_in[2], p_in[3], p_out[6]), p_out[5]);
			p_out[6] += carry;

			//== Doubling ==
			carry    = addcarry(0    , p_out[1], p_out[1], p_out[1]);
			carry    = addcarry(carry, p_out[2], p_out[2], p_out[2]);
			carry    = addcarry(carry, p_out[3], p_out[3], p_out[3]);
			carry    = addcarry(carry, p_out[4], p_out[4], p_out[4]);
			carry    = addcarry(carry, p_out[5], p_out[5], p_out[5]);
			p_out[7] = addcarry(carry, p_out[6], p_out[6], p_out[6]);

			//-- singles
			p_out[0] = umul(p_in[0], p_in[0], mul_carries[0]);
			mid[0]   = umul(p_in[1], p_in[1], mul_carries[1]);
			mid[1]   = umul(p_in[2], p_in[2], mul_carries[2]);
			mid[2]   = umul(p_in[3], p_in[3], mul_carries[3]);

			carry = addcarry(0    , p_out[1], mul_carries[0], p_out[1]);
			carry = addcarry(carry, p_out[2], mid[0]        , p_out[2]);
			carry = addcarry(carry, p_out[3], mul_carries[1], p_out[3]);
			carry = addcarry(carry, p_out[4], mid[1]        , p_out[4]);
			carry = addcarry(carry, p_out[5], mul_carries[2], p_out[5]);
			carry = addcarry(carry, p_out[6], mid[2]        , p_out[6]);
			        addcarry(carry, p_out[7], mul_carries[3], p_out[7]);

		}


		static void mod_increment(block_t& p_out)
		{
			if
			(
				(p_out[0] == prime[0] - 1) &&
				(p_out[1] == prime[1]) &&
				(p_out[2] == prime[2]) &&
				(p_out[3] == prime[3])
			)
			{
				p_out[0] = 0;
				p_out[1] = 0;
				p_out[2] = 0;
				p_out[3] = 0;
			}
			else
			{

				uint8_t carry;
				carry = addcarry(1    , p_out[0], 0, p_out[0]);
				carry = addcarry(carry, p_out[1], 0, p_out[1]);
				carry = addcarry(carry, p_out[2], 0, p_out[2]);
				p_out[3] += carry;
			}
		}

		static void mod_decrement(block_t& p_out)
		{
			if
			(
				p_out[0] == 0 &&
				p_out[1] == 0 &&
				p_out[2] == 0 &&
				p_out[3] == 0
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
				borrow = subborrow(1     , p_out[0], 0, p_out[0]);
				borrow = subborrow(borrow, p_out[1], 0, p_out[1]);
				borrow = subborrow(borrow, p_out[2], 0, p_out[2]);
				p_out[3] -= borrow;
			}
		}

		static void mod_add(block_t& p_out, const block_t& p_1, const block_t& p_2)
		{
			//add
			{
				uint8_t carry;
				carry = addcarry(0    , p_1[0], p_2[0], p_out[0]);
				carry = addcarry(carry, p_1[1], p_2[1], p_out[1]);
				carry = addcarry(carry, p_1[2], p_2[2], p_out[2]);
						addcarry(carry, p_1[3], p_2[3], p_out[3]);
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
				borrow = subborrow(0     , p_out[0], prime[0], p_out[0]);
				borrow = subborrow(borrow, p_out[1], prime[1], p_out[1]);
				borrow = subborrow(borrow, p_out[2], prime[2], p_out[2]);
				         subborrow(borrow, p_out[3], prime[3], p_out[3]);
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
			borrow = subborrow(0     , prime[0], p_val[0], p_val[0]);
			borrow = subborrow(borrow, prime[1], p_val[1], p_val[1]);
			borrow = subborrow(borrow, prime[2], p_val[2], p_val[2]);
			         subborrow(borrow, prime[3], p_val[3], p_val[3]);
		}

		static void mod_double(block_t& p_val)
		{
			mod_add(p_val, p_val, p_val);
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
				lcarry = addcarry(
					0,
					p_val[0],
					umul(p_val[4], offset2, mul_carry),
					p_val[0]);

				//block 2
				lcarry = addcarry(
					lcarry,
					mul_carry,
					umul(p_val[5], offset2, mul_carry2),
					acum);

				lcarry2 = addcarry(
					0,
					p_val[1],
					acum,
					p_val[1]);

				//block 3
				lcarry = addcarry(
					lcarry,
					mul_carry2,
					umul(p_val[6], offset2, mul_carry),
					acum);

				lcarry2 = addcarry(
					lcarry2,
					p_val[2],
					acum,
					p_val[2]);

				//block 4
				lcarry = addcarry(
					lcarry,
					mul_carry,
					umul(p_val[7], offset2, mul_carry2),
					acum);

				lcarry2 = addcarry(
					lcarry2,
					p_val[3],
					acum,
					p_val[3]);

				//block5
				addcarry(lcarry, mul_carry2, lcarry2, p_val[4]);

				if(p_val[4])
				{
					lcarry = addcarry(0     , p_val[0], umul(p_val[4], offset2, mul_carry), p_val[0]);
					lcarry = addcarry(lcarry, p_val[1], 0, p_val[1]);
					lcarry = addcarry(lcarry, p_val[2], 0, p_val[2]);
					if(      addcarry(lcarry, p_val[3], 0, p_val[3]))
					{
						lcarry = addcarry(0     , p_val[0], offset2, p_val[0]);
						lcarry = addcarry(lcarry, p_val[1], 0      , p_val[1]);
						lcarry = addcarry(lcarry, p_val[2], 0      , p_val[2]);
						         addcarry(lcarry, p_val[3], 0      , p_val[3]);
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
				lcarry = addcarry(
					0,
					p_val[0],
					umul(p_val[4], offset2, mul_carry),
					p_val[0]);

				//block 2
				lcarry = addcarry(
					lcarry,
					mul_carry,
					umul(p_val[5], offset2, mul_carry2),
					acum);

				lcarry2 = addcarry(
					0,
					p_val[1],
					acum,
					p_val[1]);

				//block 3
				lcarry = addcarry(
					lcarry,
					mul_carry2,
					umul(p_val[6], offset2, mul_carry),
					acum);

				lcarry2 = addcarry(
					lcarry2,
					p_val[2],
					acum,
					p_val[2]);

				//block 4
				addcarry(lcarry2, mul_carry, 0, mul_carry);
				if(addcarry(lcarry, p_val[3], mul_carry, p_val[3]))
				{
					lcarry = addcarry(0     , p_val[0], offset2, p_val[0]);
					lcarry = addcarry(lcarry, p_val[1], 0      , p_val[1]);
					lcarry = addcarry(lcarry, p_val[2], 0      , p_val[2]);
					         addcarry(lcarry, p_val[3], 0      , p_val[3]);
				}
			}
			if(p_val[3] & 0x8000000000000000)
			{
				constexpr uint64_t offset = 19;
				uint8_t lcarry;

				lcarry = addcarry(0     , p_val[0], offset, p_val[0]);
				lcarry = addcarry(lcarry, p_val[1], 0     , p_val[1]);
				lcarry = addcarry(lcarry, p_val[2], 0     , p_val[2]);
				         addcarry(lcarry, p_val[3] & 0x7FFFFFFFFFFFFFFF, 0, p_val[3]);
				if(p_val[3] & 0x8000000000000000)
				{
					lcarry = addcarry(0     , p_val[0], offset, p_val[0]);
					lcarry = addcarry(lcarry, p_val[1], 0     , p_val[1]);
					lcarry = addcarry(lcarry, p_val[2], 0     , p_val[2]);
					         addcarry(lcarry, p_val[3] & 0x7FFFFFFFFFFFFFFF, 0, p_val[3]);
				}
			}
			if(p_val[0] >= first_block && p_val[1] == max && p_val[2] == max && p_val[3] == last_block)
			{
				constexpr uint64_t offset = 19;
				uint8_t lcarry;
				lcarry = addcarry(0     , p_val[0], offset, p_val[0]);
				lcarry = addcarry(lcarry, p_val[1], 0     , p_val[1]);
				lcarry = addcarry(lcarry, p_val[2], 0     , p_val[2]);
				         addcarry(lcarry, p_val[3], 0     , p_val[3]);
				p_val[3] &= 0x7FFFFFFFFFFFFFFF;
			}
		}


		static void mod_multiply(block_t& p_out, const block_t& p_1, const block_t& p_2)
		{
			std::array<uint64_t, 8> temp;
			mpi_multiply(temp, p_1, p_2);
			mul_reduce(temp);
			memcpy(p_out.data(), temp.data(), sizeof(block_t));
		}


		static void mod_square(block_t& p_out, const block_t& p_in)
		{
			std::array<uint64_t, 8> temp;
			mpi_square(temp, p_in);
			mul_reduce(temp);
			memcpy(p_out.data(), temp.data(), sizeof(block_t));
		}

		//uses eulers theorem which for primes inv(a) = a^(p-2) mod p
		static void mod_inverse(block_t& p_val)
		{
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

//should yield same result as
//			block_t k;
//			block_t accum;
//			memcpy(accum.data(), p_val.data(), sizeof(block_t));
//
//			mod_square(k, accum);
//			mod_multiply(accum, accum, k);
//
//			mod_square(k, k);
//
//			mod_square(k, k);
//			mod_multiply(accum, accum, k);
//
//			mod_square(k, k);
//
//			for(uint8_t i = 5; i < 254; ++i)
//			{
//				mod_square(k, k);
//				mod_multiply(accum, accum, k);
//			}
//			mod_square(k, k);
//			mod_multiply(p_val, accum, k);
		}


		static inline bool order_should_reduce(const std::span<const uint64_t, 4> p_val)
		{
			return p_val[3] > order[3] ||
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
				);
		}

		static inline void order_simple_reduce(const std::span<uint64_t, 4> p_val)
		{
			uint8_t borrow;
			borrow = subborrow(0     , p_val[0], order[0], p_val[0]);
			borrow = subborrow(borrow, p_val[1], order[1], p_val[1]);
			borrow = subborrow(borrow, p_val[2], order[2], p_val[2]);
			         subborrow(borrow, p_val[3], order[3], p_val[3]);
		}

		static void order_low_reduce(const std::span<uint64_t, 4> p_val)
		{
			if(p_val[3] & 0xE000000000000000)
			{
				const uint64_t div = p_val[3] / (order[3]);
				if(div > 1)
				{
					uint64_t mul_carry;
					uint8_t borrow;
					uint64_t tmp;

					borrow = subborrow(0, p_val[0], umul(order[0], div, mul_carry), p_val[0]);

					borrow = subborrow(borrow, p_val[1], mul_carry, tmp);
					if(subborrow(0, tmp, umul(order[1], div, mul_carry), p_val[1]))
					{
						++mul_carry;
					}

					//this block is all zeros 0
					borrow = subborrow(borrow, p_val[2], mul_carry, p_val[2]);

					if(subborrow(borrow, p_val[3], umul(order[3], div, mul_carry), p_val[3]))
					{
						borrow = addcarry(0     , p_val[0], order[0], p_val[0]);
						borrow = addcarry(borrow, p_val[1], order[1], p_val[1]);
						borrow = addcarry(borrow, p_val[2], order[2], p_val[2]);
						         addcarry(borrow, p_val[3], order[3], p_val[3]);
					}
					return;
				}
			}

			if(order_should_reduce(p_val))
			{
				order_simple_reduce(p_val);
			}
		}

		//assumes high bits < oder
		static void order_hi_reduce(const std::span<uint64_t, 5> p_val)
		{
			if(p_val[4])
			{
				[[maybe_unused]] uint64_t unused;
				const uint64_t div = (p_val[4] == order[3]) ? 0xFFFFFFFFFFFFFFFF : udiv(p_val[4], p_val[3], order[3], unused);

				uint64_t mul_carry;
				uint8_t borrow;

				borrow = subborrow(0, p_val[0], umul(div, order[0], mul_carry), p_val[0]);

				borrow = subborrow(borrow, p_val[1], mul_carry, p_val[1]);
				if(subborrow(0, p_val[1], umul(div, order[1], mul_carry), p_val[1]))
				{
					++mul_carry;
				}

				borrow = subborrow(borrow, p_val[2], mul_carry, p_val[2]);

				borrow = subborrow(borrow, p_val[3], umul(div, order[3], mul_carry), p_val[3]);

				if(subborrow(borrow, p_val[4], mul_carry, p_val[4]))
				{
					borrow = addcarry(0     , p_val[0], order[0], p_val[0]);
					borrow = addcarry(borrow, p_val[1], order[1], p_val[1]);
					borrow = addcarry(borrow, p_val[2], order[2], p_val[2]);
					         addcarry(borrow, p_val[3], order[3], p_val[3]);
				//	p_val[4] = 0; //doesn't matter if zeroed
				}
			}
		}

		static void order_reduce(block_t& p_val)
		{
			order_low_reduce(p_val);
		}

		static void order_mul_reduce(std::array<uint64_t, 8>& p_val)
		{
			order_hi_reduce (std::span<uint64_t, 5>{p_val.data() + 3, 5});
			order_low_reduce(std::span<uint64_t, 4>{p_val.data() + 3, 4});

			order_hi_reduce (std::span<uint64_t, 5>{p_val.data() + 2, 5});
			order_low_reduce(std::span<uint64_t, 4>{p_val.data() + 2, 4});

			order_hi_reduce (std::span<uint64_t, 5>{p_val.data() + 1, 5});
			order_low_reduce(std::span<uint64_t, 4>{p_val.data() + 1, 4});

			order_hi_reduce (std::span<uint64_t, 5>{p_val.data() + 0, 5});
			order_low_reduce(std::span<uint64_t, 4>{p_val.data() + 0, 4});
		}

		static void order_multiply(block_t& p_1, const block_t& p_2)
		{
			std::array<uint64_t, 8> temp;
			mpi_multiply(temp, p_1, p_2);
			order_mul_reduce(temp);
			memcpy(p_1.data(), temp.data(), sizeof(block_t));
		}

		static void order_add(block_t& p_1, const block_t& p_2)
		{
			uint8_t carry;
			carry = addcarry(0    , p_1[0], p_2[0], p_1[0]);
			carry = addcarry(carry, p_1[1], p_2[1], p_1[1]);
			carry = addcarry(carry, p_1[2], p_2[2], p_1[2]);
			        addcarry(carry, p_1[3], p_2[3], p_1[3]);

			if(order_should_reduce(p_1))
			{
				order_simple_reduce(p_1);
			}
		}

		static void compute_r_key(
			const block_t& skey,
			const std::span<const uint8_t, Ed25519::key_lenght> message_digest,
			const std::span<const uint8_t> context, const uint8_t token, block_t& rkey)
		{
			SHA2_256 hasher;
			static_assert(sizeof(block_t) == sizeof(decltype(hasher)::digest_t));

			hasher.update(context);
			hasher.update(std::span<const uint8_t>{&token, 1});
			hasher.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(skey.data()), sizeof(skey)));
			hasher.update(message_digest);
			hasher.finalize();
			memcpy(rkey.data(), hasher.digest().data(), sizeof(block_t));

			order_reduce(rkey);
		}

		static void compute_k_key(
			const std::span<const uint8_t, Ed25519::key_lenght> message_digest,
			const std::span<const uint8_t> context, const point_t& R_key, block_t& kkey)
		{
			SHA2_256 hasher;
			constexpr block_t null{0, 0, 0, 0};
			static_assert(sizeof(block_t) == sizeof(decltype(hasher)::digest_t));

			hasher.update(context);
			hasher.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&R_key), sizeof(R_key)));
			hasher.update(message_digest);
			hasher.finalize();
			memcpy(kkey.data(), hasher.digest().data(), sizeof(block_t));
			order_reduce(kkey);

			if(memcmp(kkey.data(), &null, sizeof(block_t)) == 0)
			{
				kkey[0] = 1;
			}
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

	} //namespace


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

	void Ed25519::public_key(std::span<const uint8_t, key_lenght> p_private_key, point_t& p_public_key)
	{
		composite_key(p_private_key, Curve_25519::generator, p_public_key);
	}

	void Ed25519::composite_key(std::span<const uint8_t, key_lenght> p_private_key, const point_t& p_public_key, point_t& p_shared_key)
	{
		using block_t = Curve_25519::block_t;
		//using projective coordinates
		//x = X/Z, y = Y/Z, x * y = T/Z

		using projective_point_t = Curve_25519::projective_point_t;
		projective_point_t R0{Curve_25519::neutral.m_x, Curve_25519::neutral.m_y, {1, 0, 0, 0}, {0, 0, 0, 0}};

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
		p_compressed_key[31] |= static_cast<uint8_t>(reinterpret_cast<const key_t&>(p_public_key.m_x)[0] << 7);
	}

	bool Ed25519::key_expand(const std::span<const uint8_t, key_lenght> p_compressed_key, point_t& p_public_key)
	{
		using block_t = Curve_25519::block_t;

		memcpy(p_public_key.m_y.data(), p_compressed_key.data(), key_lenght);
		reinterpret_cast<key_t&>(p_public_key.m_y)[31] &= 0x7F;

		const block_t& t_y = reinterpret_cast<const block_t&>(p_public_key.m_y);

		const bool x_bit = p_compressed_key[31] & 0x80 ? true : false;

		if(
			t_y[0] >= Curve_25519::prime[0] &&
			t_y[1] == Curve_25519::prime[1] &&
			t_y[2] == Curve_25519::prime[2] &&
			t_y[3] == Curve_25519::prime[3])
		{
			return false;
		}

		block_t accum;
		{
			block_t u;
			block_t v;
			{
				block_t uv_3;
				{
					{
						Curve_25519::mod_square(u, t_y);

						if(Curve_25519::compare_equal(u, {1, 0, 0, 0}))
						{
							if(x_bit)
							{
								return false;
							}
							memset(p_public_key.m_x.data(), 0, sizeof(block_t));
							return true;
						}

						Curve_25519::mod_multiply(v, u, Curve_25519::D);
						Curve_25519::mod_decrement(u);
						Curve_25519::mod_increment(v);
					}

					block_t v2;
					Curve_25519::mod_multiply(uv_3, u, v);
					Curve_25519::mod_square(v2, v);
					Curve_25519::mod_multiply(uv_3, uv_3, v2);
					Curve_25519::mod_square(v2, v2);
					Curve_25519::mod_multiply(accum, uv_3, v2);
				}

				{
					block_t k0;
					block_t k1;

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
				block_t vx2;
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


	bool Ed25519::is_null(const point_t& p_public_key)
	{
		return memcmp(&p_public_key, &Curve_25519::neutral, sizeof(point_t)) == 0;
	}

	bool Ed25519::is_on_curve(const point_t& p_public_key)
	{
		using block_t = Curve_25519::block_t;
		block_t lt;
		block_t y2;
		block_t rt;

		Curve_25519::mod_square(lt, p_public_key.m_x);
		Curve_25519::mod_square(y2, p_public_key.m_y);

		Curve_25519::mod_multiply(rt, lt, y2);
		Curve_25519::mod_multiply(rt, rt, Curve_25519::D);
		Curve_25519::mod_increment(rt);

		Curve_25519::mod_negate(lt);
		Curve_25519::mod_add(lt, lt, y2);

		return memcmp(&lt, &rt, sizeof(block_t)) == 0;
	}


	void Ed25519::sign(
		const std::span<const uint8_t, key_lenght> p_private_key,
		const std::span<const uint8_t, key_lenght> p_message_digest, const std::span<const uint8_t> p_context,
		point_t& p_R, const std::span<uint8_t, key_lenght> p_S)
	{
		//	r = sha2(context| 0 | sk | M)
		//	if r == 0: r = sha2(context| 1 | sk | M)
		//	R = r*G
		//	k = sha2(context| R | M)
		//	if k == 0: k = 1
		//	S = (r + k*sk)

		using block_t = Curve_25519::block_t;

		constexpr block_t null{0, 0, 0, 0};

		block_t skey;
		memcpy(skey.data(), p_private_key.data(), sizeof(block_t));

		Curve_25519::order_reduce(skey);

		//r key
		block_t rkey;
		{
			Curve_25519::compute_r_key(skey, p_message_digest, p_context, 0, rkey);
			if(memcmp(rkey.data(), &null, sizeof(block_t)) == 0)
			{
				Curve_25519::compute_r_key(skey, p_message_digest, p_context, 1, rkey);
				if(memcmp(rkey.data(), &null, sizeof(block_t)) == 0)
				{
					memset(&p_R, 0, sizeof(p_R));
					memset(p_S.data(), 0, p_S.size());
					return;
				}
			}
		}

		public_key(std::span<const uint8_t, key_lenght>(reinterpret_cast<const uint8_t*>(rkey.data()), key_lenght), p_R);

		//k key
		block_t kkey;
		Curve_25519::compute_k_key(p_message_digest, p_context, p_R, kkey);
		Curve_25519::order_multiply(skey, kkey);
		Curve_25519::order_add(skey, rkey);

		memcpy(p_S.data(), skey.data(), key_lenght);
	}

	bool Ed25519::verify(const point_t& p_public_key,
		std::span<const uint8_t, key_lenght> p_message_digest, std::span<const uint8_t> p_context,
		const point_t& p_R, std::span<const uint8_t, key_lenght> p_S)
	{
		if(!is_on_curve(p_R))
		{
			return false;
		}

		//	k = sha2(context| R | M)
		//	if k == 0: k = 1
		//	P1 = S*G
		//	P2 = R + k*Pk
		//	P1 == P2
		using block_t = Curve_25519::block_t;
		using projective_point_t = Curve_25519::projective_point_t;
		block_t kkey;
		Curve_25519::compute_k_key(p_message_digest, p_context, p_R, kkey);

		point_t p1;
		public_key(p_S, p1);

		projective_point_t p2;
		composite_key(std::span<const uint8_t, key_lenght>{reinterpret_cast<const uint8_t*>(kkey.data()), key_lenght}, p_public_key, p2);

		{
			p2.m_z[0] = 1;
			p2.m_z[1] = 0;
			p2.m_z[2] = 0;
			p2.m_z[3] = 0;
			Curve_25519::mod_multiply(p2.m_t, p2.m_x, p2.m_y);

			projective_point_t R_p;
			memcpy(R_p.m_x.data(), p_R.m_x.data(), sizeof(block_t));
			memcpy(R_p.m_y.data(), p_R.m_y.data(), sizeof(block_t));
			R_p.m_z[0] = 1;
			R_p.m_z[1] = 0;
			R_p.m_z[2] = 0;
			R_p.m_z[3] = 0;
			Curve_25519::mod_multiply(R_p.m_t, R_p.m_x, R_p.m_y);

			Curve_25519::ED_point_add(R_p, p2);

			Curve_25519::mod_inverse(p2.m_z);
			Curve_25519::mod_multiply(p2.m_x, p2.m_x, p2.m_z);
			Curve_25519::mod_multiply(p2.m_y, p2.m_y, p2.m_z);
		}

		return memcmp(&p1, &static_cast<point_t&>(p2), sizeof(p1)) == 0;
	}

} //namespace crypto
