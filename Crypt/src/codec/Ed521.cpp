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

		struct projective_point_t: public point_t
		{
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
			0x00000000000001FF_ui64,
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

		static constexpr point_t neutral
		{
			.m_x{0, 0, 0, 0, 0, 0, 0, 0, 0},
			.m_y{1, 0, 0, 0, 0, 0, 0, 0, 0}
		};

		static bool compare_equal(const block_t& p_1, const block_t& p_2)
		{
			return memcmp(p_1.data(), p_2.data(), sizeof(block_t)) == 0;
		}

		static void mpi_multiply(std::array<uint64_t, 17>& p_out, const block_t& p_1, const block_t& p_2)
		{
			uint64_t mul_carry;
			uint64_t mul_carry_2;
			uint64_t acum;
			std::array<uint8_t, 9> lcarry;
			std::array<uint8_t, 7> Dcarry;

			//Block 0
			p_out[0] = umul(p_1[0], p_2[0], mul_carry);


			//Block 1
			lcarry[0] =
				addcarry(0,
					mul_carry,
					umul(p_1[0], p_2[1], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(0,
					acum,
					umul(p_1[1], p_2[0], mul_carry),
					p_out[1]);

			//--
			Dcarry[0] =
				addcarry(0, mul_carry, mul_carry_2, mul_carry);


			//Block 2
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[0], p_2[2], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[1], p_2[1], mul_carry),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(0,
					acum,
					umul(p_1[2], p_2[0], mul_carry_2),
					p_out[2]);

			//--
			Dcarry[1] =
				addcarry(0, mul_carry, mul_carry_2, mul_carry);


			//Block 3
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[0], p_2[3], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[1], p_2[2], mul_carry),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[2], p_2[1], mul_carry_2),
					acum);

			Dcarry[1] =
				addcarry(Dcarry[1], mul_carry, mul_carry_2, mul_carry);

			lcarry[3] =
				addcarry(0,
					acum,
					umul(p_1[3], p_2[0], mul_carry_2),
					p_out[3]);

			//--
			Dcarry[2] =
				addcarry(0, mul_carry, mul_carry_2, mul_carry);


			//Block 4
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[0], p_2[4], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[1], p_2[3], mul_carry),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[2], p_2[2], mul_carry_2),
					acum);

			Dcarry[1] =
				addcarry(Dcarry[1], mul_carry, mul_carry_2, mul_carry);

			lcarry[3] =
				addcarry(lcarry[3],
					acum,
					umul(p_1[3], p_2[1], mul_carry_2),
					acum);

			Dcarry[2] =
				addcarry(Dcarry[2], mul_carry, mul_carry_2, mul_carry);


			lcarry[4] =
				addcarry(0,
					acum,
					umul(p_1[4], p_2[0], mul_carry_2),
					p_out[4]);

			//--
			Dcarry[3] =
				addcarry(0, mul_carry, mul_carry_2, mul_carry);


			//Block 5
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[0], p_2[5], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[1], p_2[4], mul_carry),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[2], p_2[3], mul_carry_2),
					acum);

			Dcarry[1] =
				addcarry(Dcarry[1], mul_carry, mul_carry_2, mul_carry);

			lcarry[3] =
				addcarry(lcarry[3],
					acum,
					umul(p_1[3], p_2[2], mul_carry_2),
					acum);

			Dcarry[2] =
				addcarry(Dcarry[2], mul_carry, mul_carry_2, mul_carry);

			lcarry[4] =
				addcarry(lcarry[4],
					acum,
					umul(p_1[4], p_2[1], mul_carry_2),
					acum);

			Dcarry[3] =
				addcarry(Dcarry[3], mul_carry, mul_carry_2, mul_carry);

			lcarry[5] =
				addcarry(0,
					acum,
					umul(p_1[5], p_2[0], mul_carry_2),
					p_out[5]);

			//--
			Dcarry[4] =
				addcarry(0, mul_carry, mul_carry_2, mul_carry);


			//Block 6
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[0], p_2[6], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[1], p_2[5], mul_carry),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[2], p_2[4], mul_carry_2),
					acum);

			Dcarry[1] =
				addcarry(Dcarry[1], mul_carry, mul_carry_2, mul_carry);

			lcarry[3] =
				addcarry(lcarry[3],
					acum,
					umul(p_1[3], p_2[3], mul_carry_2),
					acum);

			Dcarry[2] =
				addcarry(Dcarry[2], mul_carry, mul_carry_2, mul_carry);

			lcarry[4] =
				addcarry(lcarry[4],
					acum,
					umul(p_1[4], p_2[2], mul_carry_2),
					acum);

			Dcarry[3] =
				addcarry(Dcarry[3], mul_carry, mul_carry_2, mul_carry);

			lcarry[5] =
				addcarry(lcarry[5],
					acum,
					umul(p_1[5], p_2[1], mul_carry_2),
					acum);

			Dcarry[4] =
				addcarry(Dcarry[4], mul_carry, mul_carry_2, mul_carry);

			lcarry[6] =
				addcarry(0,
					acum,
					umul(p_1[6], p_2[0], mul_carry_2),
					p_out[6]);

			//--
			Dcarry[5] =
				addcarry(0, mul_carry, mul_carry_2, mul_carry);


			//Block 7
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[0], p_2[7], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[1], p_2[6], mul_carry),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[2], p_2[5], mul_carry_2),
					acum);

			Dcarry[1] =
				addcarry(Dcarry[1], mul_carry, mul_carry_2, mul_carry);

			lcarry[3] =
				addcarry(lcarry[3],
					acum,
					umul(p_1[3], p_2[4], mul_carry_2),
					acum);

			Dcarry[2] =
				addcarry(Dcarry[2], mul_carry, mul_carry_2, mul_carry);

			lcarry[4] =
				addcarry(lcarry[4],
					acum,
					umul(p_1[4], p_2[3], mul_carry_2),
					acum);

			Dcarry[3] =
				addcarry(Dcarry[3], mul_carry, mul_carry_2, mul_carry);

			lcarry[5] =
				addcarry(lcarry[5],
					acum,
					umul(p_1[5], p_2[2], mul_carry_2),
					acum);

			Dcarry[4] =
				addcarry(Dcarry[4], mul_carry, mul_carry_2, mul_carry);

			lcarry[6] =
				addcarry(lcarry[6],
					acum,
					umul(p_1[6], p_2[1], mul_carry_2),
					acum);

			Dcarry[5] =
				addcarry(Dcarry[5], mul_carry, mul_carry_2, mul_carry);

			lcarry[7] =
				addcarry(0,
					acum,
					umul(p_1[7], p_2[0], mul_carry_2),
					p_out[7]);

			//--
			Dcarry[6] =
				addcarry(0, mul_carry, mul_carry_2, mul_carry);


			//Block 8
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[0], p_2[8], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[8], p_2[0], mul_carry),
					acum);

			addcarry(Dcarry[6], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[1], p_2[7], mul_carry_2),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[3] =
				addcarry(lcarry[3],
					acum,
					umul(p_1[2], p_2[6], mul_carry_2),
					acum);

			Dcarry[1] =
				addcarry(Dcarry[1], mul_carry, mul_carry_2, mul_carry);

			lcarry[4] =
				addcarry(lcarry[4],
					acum,
					umul(p_1[3], p_2[5], mul_carry_2),
					acum);

			Dcarry[2] =
				addcarry(Dcarry[2], mul_carry, mul_carry_2, mul_carry);

			lcarry[5] =
				addcarry(lcarry[5],
					acum,
					umul(p_1[4], p_2[4], mul_carry_2),
					acum);

			Dcarry[3] =
				addcarry(Dcarry[3], mul_carry, mul_carry_2, mul_carry);

			lcarry[6] =
				addcarry(lcarry[6],
					acum,
					umul(p_1[5], p_2[3], mul_carry_2),
					acum);

			Dcarry[4] =
				addcarry(Dcarry[4], mul_carry, mul_carry_2, mul_carry);

			lcarry[7] =
				addcarry(lcarry[7],
					acum,
					umul(p_1[6], p_2[2], mul_carry_2),
					acum);

			Dcarry[5] =
				addcarry(Dcarry[5], mul_carry, mul_carry_2, mul_carry);

			lcarry[8] =
				addcarry(0,
					acum,
					umul(p_1[7], p_2[1], mul_carry_2),
					p_out[8]);

			//--
			Dcarry[6] =
				addcarry(lcarry[8], mul_carry, mul_carry_2, mul_carry);


			//Block 9
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[1], p_2[8], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[8], p_2[1], mul_carry),
					acum);

			addcarry(Dcarry[6], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[2], p_2[7], mul_carry_2),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[3] =
				addcarry(lcarry[3],
					acum,
					umul(p_1[3], p_2[6], mul_carry_2),
					acum);

			Dcarry[1] =
				addcarry(Dcarry[1], mul_carry, mul_carry_2, mul_carry);

			lcarry[4] =
				addcarry(lcarry[4],
					acum,
					umul(p_1[4], p_2[5], mul_carry_2),
					acum);

			Dcarry[2] =
				addcarry(Dcarry[2], mul_carry, mul_carry_2, mul_carry);

			lcarry[5] =
				addcarry(lcarry[5],
					acum,
					umul(p_1[5], p_2[4], mul_carry_2),
					acum);

			Dcarry[3] =
				addcarry(Dcarry[3], mul_carry, mul_carry_2, mul_carry);

			lcarry[6] =
				addcarry(lcarry[6],
					acum,
					umul(p_1[6], p_2[3], mul_carry_2),
					acum);

			Dcarry[4] =
				addcarry(Dcarry[4], mul_carry, mul_carry_2, mul_carry);


			lcarry[7] =
				addcarry(lcarry[7],
					acum,
					umul(p_1[7], p_2[2], mul_carry_2),
					p_out[9]);

			//--
			Dcarry[5] =
				addcarry(Dcarry[5], mul_carry, mul_carry_2 + lcarry[7], mul_carry);


			//Block 10
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[2], p_2[8], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[8], p_2[2], mul_carry),
					acum);

			addcarry(Dcarry[5], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[3], p_2[7], mul_carry_2),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[3] =
				addcarry(lcarry[3],
					acum,
					umul(p_1[4], p_2[6], mul_carry_2),
					acum);

			Dcarry[1] =
				addcarry(Dcarry[1], mul_carry, mul_carry_2, mul_carry);

			lcarry[4] =
				addcarry(lcarry[4],
					acum,
					umul(p_1[5], p_2[5], mul_carry_2),
					acum);

			Dcarry[2] =
				addcarry(Dcarry[2], mul_carry, mul_carry_2, mul_carry);

			lcarry[5] =
				addcarry(lcarry[5],
					acum,
					umul(p_1[6], p_2[4], mul_carry_2),
					acum);

			Dcarry[3] =
				addcarry(Dcarry[3], mul_carry, mul_carry_2, mul_carry);

			lcarry[6] =
				addcarry(lcarry[6],
					acum,
					umul(p_1[7], p_2[3], mul_carry_2),
					p_out[10]);

			//--
			Dcarry[4] =
				addcarry(Dcarry[4], mul_carry, mul_carry_2 + lcarry[6], mul_carry);


			//Block 11
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[3], p_2[8], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[8], p_2[3], mul_carry),
					acum);

			addcarry(Dcarry[4], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[4], p_2[7], mul_carry_2),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[3] =
				addcarry(lcarry[3],
					acum,
					umul(p_1[5], p_2[6], mul_carry_2),
					acum);

			Dcarry[1] =
				addcarry(Dcarry[1], mul_carry, mul_carry_2, mul_carry);

			lcarry[4] =
				addcarry(lcarry[4],
					acum,
					umul(p_1[6], p_2[5], mul_carry_2),
					acum);

			Dcarry[2] =
				addcarry(Dcarry[2], mul_carry, mul_carry_2, mul_carry);

			lcarry[5] =
				addcarry(lcarry[5],
					acum,
					umul(p_1[7], p_2[4], mul_carry_2),
					p_out[11]);

			//--
			Dcarry[3] =
				addcarry(Dcarry[3], mul_carry, mul_carry_2 + lcarry[5], mul_carry);


			//Block 12
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[4], p_2[8], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[8], p_2[4], mul_carry),
					acum);

			addcarry(Dcarry[3], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[5], p_2[7], mul_carry_2),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[3] =
				addcarry(lcarry[3],
					acum,
					umul(p_1[6], p_2[6], mul_carry_2),
					acum);

			Dcarry[1] =
				addcarry(Dcarry[1], mul_carry, mul_carry_2, mul_carry);

			lcarry[4] =
				addcarry(lcarry[4],
					acum,
					umul(p_1[7], p_2[5], mul_carry_2),
					p_out[12]);

			//--
			Dcarry[2] =
				addcarry(Dcarry[2], mul_carry, mul_carry_2 + lcarry[4], mul_carry);


			//Block 13
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[5], p_2[8], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[8], p_2[5], mul_carry),
					acum);

			addcarry(Dcarry[2], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[6], p_2[7], mul_carry_2),
					acum);

			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2, mul_carry);

			lcarry[3] =
				addcarry(lcarry[3],
					acum,
					umul(p_1[7], p_2[6], mul_carry_2),
					p_out[13]);

			//--
			Dcarry[1] =
				addcarry(Dcarry[1], mul_carry, mul_carry_2 + lcarry[3], mul_carry);


			//Block 14
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[6], p_2[8], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[8], p_2[6], mul_carry),
					acum);

			addcarry(Dcarry[1], mul_carry, mul_carry_2, mul_carry);

			lcarry[2] =
				addcarry(lcarry[2],
					acum,
					umul(p_1[7], p_2[7], mul_carry_2),
					p_out[14]);

			//--
			Dcarry[0] =
				addcarry(Dcarry[0], mul_carry, mul_carry_2 + lcarry[2], mul_carry);

			//Block 15
			lcarry[0] =
				addcarry(lcarry[0],
					mul_carry,
					umul(p_1[7], p_2[8], mul_carry_2),
					acum);

			lcarry[1] =
				addcarry(lcarry[1],
					acum,
					umul(p_1[8], p_2[7], mul_carry),
					p_out[15]);

			//--
			addcarry(Dcarry[0], mul_carry, mul_carry_2 + lcarry[1], mul_carry);

			//Block 16
			addcarry(lcarry[0],
				mul_carry,
				umul(p_1[8], p_2[8], mul_carry_2),
				p_out[16]);
		}

		static void mpi_square(std::array<uint64_t, 17>& p_out, const block_t& p_in)
		{
			{
				uint64_t mul_carry;

				//double blocks
				{
					std::array<uint8_t, 4> lcarry;
					std::array<uint8_t, 3> Dcarry;
					//Block 0
					//Block 1
					p_out[1] = umul(p_in[0], p_in[1], p_out[2]);

					//Block 2
					lcarry[0] =
						addcarry(0,
							umul(p_in[0], p_in[2], p_out[3]),
							p_out[2],
							p_out[2]);

					//Block 3
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[3], p_out[4]),
							p_out[3],
							p_out[3]);

					lcarry[1] =
						addcarry(0,
							umul(p_in[1], p_in[2], mul_carry),
							p_out[3],
							p_out[3]);

					//--
					Dcarry[0] =
						addcarry(0, p_out[4], mul_carry, p_out[4]);

					//Block 4
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[4], p_out[5]),
							p_out[4],
							p_out[4]);

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[1], p_in[3], mul_carry),
							p_out[4],
							p_out[4]);

					//--
					Dcarry[0] =
						addcarry(Dcarry[0], p_out[5], mul_carry, p_out[5]);

					//Block 5
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[5], p_out[6]),
							p_out[5],
							p_out[5]);

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[1], p_in[4], mul_carry),
							p_out[5],
							p_out[5]);

					Dcarry[0] =
						addcarry(Dcarry[0], p_out[6], mul_carry, p_out[6]);

					lcarry[2] =
						addcarry(0,
							umul(p_in[2], p_in[3], mul_carry),
							p_out[5],
							p_out[5]);

					//--
					Dcarry[1] =
						addcarry(0, p_out[6], mul_carry, p_out[6]);

					//Block 6
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[6], p_out[7]),
							p_out[6],
							p_out[6]);

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[1], p_in[5], mul_carry),
							p_out[6],
							p_out[6]);

					Dcarry[0] =
						addcarry(Dcarry[0], p_out[7], mul_carry, p_out[7]);

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[2], p_in[4], mul_carry),
							p_out[6],
							p_out[6]);

					//--
					Dcarry[1] =
						addcarry(Dcarry[1], p_out[7], mul_carry, p_out[7]);

					//Block 7
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[7], p_out[8]),
							p_out[7],
							p_out[7]);

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[1], p_in[6], mul_carry),
							p_out[7],
							p_out[7]);

					Dcarry[0] =
						addcarry(Dcarry[0], p_out[8], mul_carry, p_out[8]);

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[2], p_in[5], mul_carry),
							p_out[7],
							p_out[7]);

					Dcarry[1] =
						addcarry(Dcarry[1], p_out[8], mul_carry, p_out[8]);

					lcarry[3] =
						addcarry(0,
							umul(p_in[3], p_in[4], mul_carry),
							p_out[7],
							p_out[7]);

					//--
					Dcarry[2] =
						addcarry(0, p_out[8], mul_carry, p_out[8]);

					//Block 8
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[0], p_in[8], p_out[9]),
							p_out[8],
							p_out[8]);

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[1], p_in[7], mul_carry),
							p_out[8],
							p_out[8]);

					Dcarry[0] =
						addcarry(Dcarry[0], p_out[9], mul_carry, p_out[9]);

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[2], p_in[6], mul_carry),
							p_out[8],
							p_out[8]);

					Dcarry[1] =
						addcarry(Dcarry[1], p_out[9], mul_carry, p_out[9]);

					lcarry[3] =
						addcarry(lcarry[3],
							umul(p_in[3], p_in[5], mul_carry),
							p_out[8],
							p_out[8]);

					//--
					Dcarry[2] =
						addcarry(Dcarry[2], p_out[9], mul_carry, p_out[9]);

					//Block 9
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[1], p_in[8], p_out[10]),
							p_out[9],
							p_out[9]);

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[2], p_in[7], mul_carry),
							p_out[9],
							p_out[9]);

					Dcarry[0] =
						addcarry(Dcarry[0], p_out[10], mul_carry, p_out[10]);

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[3], p_in[6], mul_carry),
							p_out[9],
							p_out[9]);

					Dcarry[1] =
						addcarry(Dcarry[1], p_out[10], mul_carry, p_out[10]);

					lcarry[3] =
						addcarry(lcarry[3],
							umul(p_in[4], p_in[5], mul_carry),
							p_out[9],
							p_out[9]);

					//--
					Dcarry[2] =
						addcarry(Dcarry[2], p_out[10], mul_carry + lcarry[3], p_out[10]);

					//Block 10
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[2], p_in[8], p_out[11]),
							p_out[10],
							p_out[10]);

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[3], p_in[7], mul_carry),
							p_out[10],
							p_out[10]);

					Dcarry[0] =
						addcarry(Dcarry[0], p_out[11], mul_carry, p_out[11]);

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[4], p_in[6], mul_carry),
							p_out[10],
							p_out[10]);

					//--
					Dcarry[1] =
						addcarry(Dcarry[1], p_out[11], mul_carry + Dcarry[2], p_out[11]);

					//Block 11
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[3], p_in[8], p_out[12]),
							p_out[11],
							p_out[11]);

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[4], p_in[7], mul_carry),
							p_out[11],
							p_out[11]);

					Dcarry[0] =
						addcarry(Dcarry[0], p_out[12], mul_carry, p_out[12]);

					lcarry[2] =
						addcarry(lcarry[2],
							umul(p_in[5], p_in[6], mul_carry),
							p_out[11],
							p_out[11]);

					//--
					Dcarry[1] =
						addcarry(Dcarry[1], p_out[12], mul_carry + lcarry[2], p_out[12]);

					//Block 12
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[4], p_in[8], p_out[13]),
							p_out[12],
							p_out[12]);

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[5], p_in[7], mul_carry),
							p_out[12],
							p_out[12]);

					//--
					Dcarry[0] =
						addcarry(Dcarry[0], p_out[13], mul_carry + Dcarry[1], p_out[13]);

					//Block 13
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[5], p_in[8], p_out[14]),
							p_out[13],
							p_out[13]);

					lcarry[1] =
						addcarry(lcarry[1],
							umul(p_in[6], p_in[7], mul_carry),
							p_out[13],
							p_out[13]);

					//--
					Dcarry[0] =
						addcarry(Dcarry[0], p_out[14], mul_carry + lcarry[1], p_out[14]);

					//Block 14
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[6], p_in[8], p_out[15]),
							p_out[14],
							p_out[14]);

					//Block 15
					lcarry[0] =
						addcarry(lcarry[0],
							umul(p_in[7], p_in[8], p_out[16]),
							p_out[15] + Dcarry[0],
							p_out[15]);

					//Block 16
					p_out[16] += lcarry[0];

					//Block 17
				}
				uint8_t lcarry;

				//== Doubling ==
				lcarry = addcarry(0     , p_out[ 1], p_out[ 1], p_out[ 1]);
				lcarry = addcarry(lcarry, p_out[ 2], p_out[ 2], p_out[ 2]);
				lcarry = addcarry(lcarry, p_out[ 3], p_out[ 3], p_out[ 3]);
				lcarry = addcarry(lcarry, p_out[ 4], p_out[ 4], p_out[ 4]);
				lcarry = addcarry(lcarry, p_out[ 5], p_out[ 5], p_out[ 5]);
				lcarry = addcarry(lcarry, p_out[ 6], p_out[ 6], p_out[ 6]);
				lcarry = addcarry(lcarry, p_out[ 7], p_out[ 7], p_out[ 7]);
				lcarry = addcarry(lcarry, p_out[ 8], p_out[ 8], p_out[ 8]);
				lcarry = addcarry(lcarry, p_out[ 9], p_out[ 9], p_out[ 9]);
				lcarry = addcarry(lcarry, p_out[10], p_out[10], p_out[10]);
				lcarry = addcarry(lcarry, p_out[11], p_out[11], p_out[11]);
				lcarry = addcarry(lcarry, p_out[12], p_out[12], p_out[12]);
				lcarry = addcarry(lcarry, p_out[13], p_out[13], p_out[13]);
				lcarry = addcarry(lcarry, p_out[14], p_out[14], p_out[14]);
				lcarry = addcarry(lcarry, p_out[15], p_out[15], p_out[15]);
				         addcarry(lcarry, p_out[16], p_out[16], p_out[16]);

				//single blocks
				//Block 0
				p_out[0] = umul(p_in[0], p_in[0], mul_carry);

				//Block 1
				lcarry = addcarry(0, p_out[1], mul_carry, p_out[1]);

				//Block 2
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[1], p_in[1], mul_carry),
						p_out[2],
						p_out[2]);

				//Block 3
				lcarry = addcarry(lcarry, p_out[3], mul_carry, p_out[3]);

				//Block 4
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[2], p_in[2], mul_carry),
						p_out[4],
						p_out[4]);

				//Block 5
				lcarry = addcarry(lcarry, p_out[5], mul_carry, p_out[5]);

				//Block 6
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[3], p_in[3], mul_carry),
						p_out[6],
						p_out[6]);

				//Block 7
				lcarry = addcarry(lcarry, p_out[7], mul_carry, p_out[7]);

				//Block 8
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[4], p_in[4], mul_carry),
						p_out[8],
						p_out[8]);

				//Block 9
				lcarry = addcarry(lcarry, p_out[9], mul_carry, p_out[9]);

				//Block 10
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[5], p_in[5], mul_carry),
						p_out[10],
						p_out[10]);

				//Block 11
				lcarry = addcarry(lcarry, p_out[11], mul_carry, p_out[11]);

				//Block 12
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[6], p_in[6], mul_carry),
						p_out[12],
						p_out[12]);

				//Block 13
				lcarry = addcarry(lcarry, p_out[13], mul_carry, p_out[13]);

				//Block 14
				lcarry =
					addcarry(
						lcarry,
						umul(p_in[7], p_in[7], mul_carry),
						p_out[14],
						p_out[14]);

				//Block 15
				lcarry = addcarry(lcarry, p_out[15], mul_carry, p_out[15]);

				//Block 16
				addcarry(
					lcarry,
					umul(p_in[8], p_in[8], mul_carry),
					p_out[16],
					p_out[16]);
			}
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
				carry = addcarry(1    , v_1[0], 0, p_out[0]);
				carry = addcarry(carry, v_1[1], 0, p_out[1]);
				carry = addcarry(carry, v_1[2], 0, p_out[2]);
				carry = addcarry(carry, v_1[3], 0, p_out[3]);
				carry = addcarry(carry, v_1[4], 0, p_out[4]);
				carry = addcarry(carry, v_1[5], 0, p_out[5]);
				carry = addcarry(carry, v_1[6], 0, p_out[6]);
				carry = addcarry(carry, v_1[7], 0, p_out[7]);
				        addcarry(carry, v_1[8], 0, p_out[8]);
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
				borrow = subborrow(1     , p_in[0], 0, p_out[0]);
				borrow = subborrow(borrow, p_in[1], 0, p_out[1]);
				borrow = subborrow(borrow, p_in[2], 0, p_out[2]);
				borrow = subborrow(borrow, p_in[3], 0, p_out[3]);
				borrow = subborrow(borrow, p_in[4], 0, p_out[4]);
				borrow = subborrow(borrow, p_in[5], 0, p_out[5]);
				borrow = subborrow(borrow, p_in[6], 0, p_out[6]);
				borrow = subborrow(borrow, p_in[7], 0, p_out[7]);
				         subborrow(borrow, p_in[8], 0, p_out[8]);
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
				carry = addcarry(carry, p_1[3], p_2[3], p_out[3]);
				carry = addcarry(carry, p_1[4], p_2[4], p_out[4]);
				carry = addcarry(carry, p_1[5], p_2[5], p_out[5]);
				carry = addcarry(carry, p_1[6], p_2[6], p_out[6]);
				carry = addcarry(carry, p_1[7], p_2[7], p_out[7]);
						addcarry(carry, p_1[8], p_2[8], p_out[8]);
			}

			//mod
			if(p_out[8] & 0x200_ui64)
			{
				uint8_t borrow;
				borrow = subborrow(0     , p_out[0], prime_base  , p_out[0]);
				borrow = subborrow(borrow, p_out[1], prime_base  , p_out[1]);
				borrow = subborrow(borrow, p_out[2], prime_base  , p_out[2]);
				borrow = subborrow(borrow, p_out[3], prime_base  , p_out[3]);
				borrow = subborrow(borrow, p_out[4], prime_base  , p_out[4]);
				borrow = subborrow(borrow, p_out[5], prime_base  , p_out[5]);
				borrow = subborrow(borrow, p_out[6], prime_base  , p_out[6]);
				borrow = subborrow(borrow, p_out[7], prime_base  , p_out[7]);
				         subborrow(borrow, p_out[8], prime_base_l, p_out[8]);
			}
			else if(
				p_out[0] == prime_base &&
				p_out[1] == prime_base &&
				p_out[2] == prime_base &&
				p_out[3] == prime_base &&
				p_out[4] == prime_base &&
				p_out[5] == prime_base &&
				p_out[6] == prime_base &&
				p_out[7] == prime_base &&
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
			borrow = subborrow(0     , prime_base  , p_val[0], p_val[0]);
			borrow = subborrow(borrow, prime_base  , p_val[1], p_val[1]);
			borrow = subborrow(borrow, prime_base  , p_val[2], p_val[2]);
			borrow = subborrow(borrow, prime_base  , p_val[3], p_val[3]);
			borrow = subborrow(borrow, prime_base  , p_val[4], p_val[4]);
			borrow = subborrow(borrow, prime_base  , p_val[5], p_val[5]);
			borrow = subborrow(borrow, prime_base  , p_val[6], p_val[6]);
			borrow = subborrow(borrow, prime_base  , p_val[7], p_val[7]);
			         subborrow(borrow, prime_base_l, p_val[8], p_val[8]);
		}

		static void mod_double(block_t& p_val)
		{
			mod_add(p_val, p_val, p_val);
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
				carry = addcarry(0    , p_val[0], (p_val[ 8] >> 9) | (p_val[ 9] << 55), p_val[0]);
				carry = addcarry(carry, p_val[1], (p_val[ 9] >> 9) | (p_val[10] << 55), p_val[1]);
				carry = addcarry(carry, p_val[2], (p_val[10] >> 9) | (p_val[11] << 55), p_val[2]);
				carry = addcarry(carry, p_val[3], (p_val[11] >> 9) | (p_val[12] << 55), p_val[3]);
				carry = addcarry(carry, p_val[4], (p_val[12] >> 9) | (p_val[13] << 55), p_val[4]);
				carry = addcarry(carry, p_val[5], (p_val[13] >> 9) | (p_val[14] << 55), p_val[5]);
				carry = addcarry(carry, p_val[6], (p_val[14] >> 9) | (p_val[15] << 55), p_val[6]);
				carry = addcarry(carry, p_val[7], (p_val[15] >> 9) | (p_val[16] << 55), p_val[7]);
				        addcarry(carry, p_val[8] & 0x1FF, (p_val[16] >> 9)            , p_val[8]);

				if(p_val[8] & 0x200)
				{
					carry = addcarry(1    , p_val[0]        , 0, p_val[0]);
					carry = addcarry(carry, p_val[1]        , 0, p_val[1]);
					carry = addcarry(carry, p_val[2]        , 0, p_val[2]);
					carry = addcarry(carry, p_val[3]        , 0, p_val[3]);
					carry = addcarry(carry, p_val[4]        , 0, p_val[4]);
					carry = addcarry(carry, p_val[5]        , 0, p_val[5]);
					carry = addcarry(carry, p_val[6]        , 0, p_val[6]);
					carry = addcarry(carry, p_val[7]        , 0, p_val[7]);
					        addcarry(carry, p_val[8] & 0x1FF, 0, p_val[8]);
					if(p_val[8] & 0x200)
					{
						p_val[0] = 1;
						p_val[8] = 0;
					}
					return;
				}
			}

			if
			(
				p_val[0] == prime_base &&
				p_val[1] == prime_base &&
				p_val[2] == prime_base &&
				p_val[3] == prime_base &&
				p_val[4] == prime_base &&
				p_val[6] == prime_base &&
				p_val[7] == prime_base &&
				p_val[8] == prime_base_l
			)
			{
				memset(p_val.data(), 0, sizeof(block_t));
			}

		}

		static void mod_multiply(block_t& p_out, const block_t& p_1, const block_t& p_2)
		{
			std::array<uint64_t, 17> temp;
			mpi_multiply(temp, p_1, p_2);
			mul_reduce(temp);
			memcpy(p_out.data(), temp.data(), sizeof(block_t));
		}


		static void mod_square(block_t& p_out, const block_t& p_in)
		{
			std::array<uint64_t, 17> temp;
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

		static inline bool order_should_reduce(const std::span<const uint64_t, 9> p_val)
		{
			return p_val[8] > order[8] ||
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
													p_val[0] >= order[0]
												)
											)
										)
									)
								)
							)
						)
					)
				);
		}

		static inline void order_simple_reduce(const std::span<uint64_t, 9> p_val)
		{
			uint8_t borrow;
			borrow = subborrow(0     , p_val[0], order[0], p_val[0]);
			borrow = subborrow(borrow, p_val[1], order[1], p_val[1]);
			borrow = subborrow(borrow, p_val[2], order[2], p_val[2]);
			borrow = subborrow(borrow, p_val[3], order[3], p_val[3]);
			borrow = subborrow(borrow, p_val[4], order[4], p_val[4]);
			borrow = subborrow(borrow, p_val[5], order[5], p_val[5]);
			borrow = subborrow(borrow, p_val[6], order[6], p_val[6]);
			borrow = subborrow(borrow, p_val[7], order[7], p_val[7]);
			         subborrow(borrow, p_val[8], order[8], p_val[8]);
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

				borrow = subborrow(0, p_val[0], umul(order[0], div, mul_carry), p_val[0]);

				for(uint8_t i = 1; i < 9; ++i)
				{
					borrow  = subborrow(borrow , p_val[i], mul_carry                     , tmp);
					borrow2 = subborrow(borrow2, tmp     , umul(order[i], div, mul_carry), p_val[i]);
				}

				if(p_val[8] & 0x80)
				{
					order_simple_reduce(p_val);
				}
			}
			if(order_should_reduce(p_val))
			{
				order_simple_reduce(p_val);
			}
		}

		static void order_low_reduce(const std::span<uint64_t, 9> p_val)
		{
			const uint64_t div = p_val[8] / (order[8] + 1);

			if(div > 1)
			{
				uint64_t mul_carry;
				uint8_t borrow;
				uint8_t borrow2 = 0;
				uint64_t tmp;

				borrow = subborrow(0, p_val[0], umul(order[0], div, mul_carry), p_val[0]);

				for(uint8_t i = 1; i < 9; ++i)
				{
					borrow  = subborrow(borrow , p_val[i], mul_carry                     , tmp);
					borrow2 = subborrow(borrow2, tmp     , umul(order[i], div, mul_carry), p_val[i]);
				}

				if(p_val[8] & 0x80)
				{
					order_simple_reduce(p_val);
				}
			}
			if(order_should_reduce(p_val))
			{
				order_simple_reduce(p_val);
			}
		}

		static void order_hi_reduce(const std::span<uint64_t, 10> p_val)
		{
			if(p_val[9])
			{
				uint64_t mul_carry;
				uint8_t borrow;
				uint8_t borrow2 = 0;
				uint64_t tmp;

				const uint64_t div = udiv(p_val[9], p_val[8], order[8] + 1, mul_carry);

				borrow = subborrow(0, p_val[0], umul(order[0], div, mul_carry), p_val[0]);

				for(uint8_t i = 1; i < 9; ++i)
				{
					borrow  = subborrow(borrow , p_val[i], mul_carry                     , tmp);
					borrow2 = subborrow(borrow2, tmp     , umul(order[i], div, mul_carry), p_val[i]);
				}

				//subborrow(borrow, p_val[9], mul_carry, p_val[9]);  //doesn't matter if zeroed
			}
		}

		static void order_mul_reduce(std::array<uint64_t, 17>& p_val)
		{
			order_low_reduce(std::span<uint64_t,  9>{p_val.data() + 8,  9});

			for(uint8_t i = 8; i--;)
			{
				order_hi_reduce (std::span<uint64_t, 10>{p_val.data() + i, 10});
				order_low_reduce(std::span<uint64_t,  9>{p_val.data() + i,  9});
			}
		}

		static void order_multiply(block_t& p_1, const block_t& p_2)
		{
			std::array<uint64_t, 17> temp;
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
			carry = addcarry(carry, p_1[3], p_2[3], p_1[3]);
			carry = addcarry(carry, p_1[4], p_2[4], p_1[4]);
			carry = addcarry(carry, p_1[5], p_2[5], p_1[5]);
			carry = addcarry(carry, p_1[6], p_2[6], p_1[6]);
			carry = addcarry(carry, p_1[7], p_2[7], p_1[7]);
			        addcarry(carry, p_1[8], p_2[8], p_1[8]);

			if(order_should_reduce(p_1))
			{
				order_simple_reduce(p_1);
			}
		}

		static void compute_r_key(
			const block_t& skey,
			const std::span<const uint8_t, Ed521::key_lenght> message_digest,
			const std::span<const uint8_t> context, const uint8_t token, block_t& rkey)
		{
			SHA2_512 hasher_hi;
			SHA2_256 hasher_lo;

			hasher_hi.update(context);
			hasher_hi.update(std::span<const uint8_t>{&token, 1});
			hasher_hi.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(skey.data()), sizeof(skey)));
			hasher_hi.update(message_digest);
			hasher_hi.finalize();

			hasher_lo.update(context);
			hasher_lo.update(std::span<const uint8_t>{&token, 1});
			hasher_lo.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(skey.data()), sizeof(skey)));
			hasher_lo.update(message_digest);
			hasher_lo.finalize();

			memcpy(rkey.data(), hasher_hi.digest().data(), sizeof(SHA2_512::digest_t));

			rkey[8] = hasher_lo.digest()[0] & 0xFFFF;

			order_reduce(rkey);
		}

		static void compute_k_key(
			const std::span<const uint8_t, Ed521::key_lenght> message_digest,
			const std::span<const uint8_t> context, const point_t& R_key, block_t& kkey)
		{
			SHA2_512 hasher_hi;
			SHA2_256 hasher_lo;
			constexpr block_t null{0, 0, 0, 0, 0, 0, 0, 0, 0};

			hasher_hi.update(context);
			hasher_hi.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&R_key), sizeof(R_key)));
			hasher_hi.update(message_digest);
			hasher_hi.finalize();

			hasher_lo.update(context);
			hasher_lo.update(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(&R_key), sizeof(R_key)));
			hasher_lo.update(message_digest);
			hasher_lo.finalize();

			memcpy(kkey.data(), hasher_hi.digest().data(), sizeof(SHA2_512::digest_t));
			kkey[8] = hasher_lo.digest()[0] & 0xFFFF;

			order_reduce(kkey);

			if(memcmp(kkey.data(), &null, sizeof(block_t)) == 0)
			{
				kkey[0] = 1;
			}
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
			//	Y3 = A*H*(D - a*C);
			//	Z3 = F*H;

			block_t tA;
			block_t tC;
			block_t tD;
			block_t F;
			block_t H;

			{
				block_t tB;
				block_t E;

				mod_multiply(tC, p_1.m_x, p_out.m_x);
				mod_multiply(tD, p_1.m_y, p_out.m_y);
				mod_multiply(tA, p_1.m_z, p_out.m_z);

				mod_square(tB, tA);

				mod_multiply(E, tD, tC);
				mod_multiply(E, E, D);

				mod_add(H, tB, E);
				mod_negate(E);
				mod_add(F, tB, E);
			}

			mod_multiply(p_out.m_z, F, H);

			block_t aux1;
			block_t aux2;

			mod_add(aux1, p_1.m_x, p_1.m_y);
			mod_add(aux2, p_out.m_x, p_out.m_y);
			mod_multiply(aux2, aux2, aux1);

			mod_negate(tC);
			mod_add(aux1, tD, tC);
			mod_multiply(aux1, aux1, H);
			mod_multiply(p_out.m_y, aux1, tA);


			mod_negate(tD);
			mod_add(aux1, aux2, tC);
			mod_add(aux1, aux1, tD);

			mod_multiply(aux1, aux1, F);
			mod_multiply(p_out.m_x, aux1, tA);
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
			mod_square(H, p_point.m_z);

			mod_add(E, tC, tD);

			mod_double(H);
			mod_negate(H);

			mod_add(J, E, H);
			mod_multiply(p_point.m_z, E, J);


			mod_negate(tD);
			mod_add(tD, tD, tC);
			mod_multiply(p_point.m_y, E, tD);

			mod_negate(E);
			mod_add(tB, tB, E);
			mod_multiply(p_point.m_x, tB, J);
		}
	};

	} //namespace

	
	void Ed521::reduce_private_key(std::span<uint8_t, key_lenght> p_private_key)
	{
		Curve_E521::block_t temp;
		temp[8] = 0;
		memcpy(temp.data(), p_private_key.data(), key_lenght);
		Curve_E521::order_reduce(temp);
		memcpy(p_private_key.data(), temp.data(), key_lenght);
	}

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
		projective_point_t R0{Curve_E521::neutral.m_x, Curve_E521::neutral.m_y, {1, 0, 0, 0, 0, 0, 0, 0, 0}};
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
		skey[8] &= 0;
		memcpy(skey.data(), p_private_key.data(), p_private_key.size());

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

	void Ed521::key_compress(const point_t& p_public_key, std::span<uint8_t, key_lenght> p_compressed_key)
	{
		memcpy(p_compressed_key.data(), p_public_key.m_y.data(), key_lenght);
		if(p_public_key.m_x[0] & 1)
		{
			p_compressed_key[65] |= 0x80;
		}
	}

	bool Ed521::key_expand(const std::span<const uint8_t, key_lenght> p_compressed_key, point_t& p_public_key)
	{
		using block_t = Curve_E521::block_t;

		if(p_compressed_key[65] & 0x06)
		{
			return false;
		}

		const bool x_bit = p_compressed_key[65] & 0x80 ? true : false;

		p_public_key.m_y[8] = 0;
		memcpy(p_public_key.m_y.data(), p_compressed_key.data(), key_lenght);
		p_public_key.m_y[8] &= 0x1FFF;


		const block_t& t_y = reinterpret_cast<const block_t&>(p_public_key.m_y);

		if(Curve_E521::compare_equal(
				t_y,
				block_t
				{
					Curve_E521::prime_base,
					Curve_E521::prime_base,
					Curve_E521::prime_base,
					Curve_E521::prime_base,
					Curve_E521::prime_base,
					Curve_E521::prime_base,
					Curve_E521::prime_base,
					Curve_E521::prime_base,
					Curve_E521::prime_base_l,
				}))
		{
			return false;
		}


		block_t u;
		block_t v;
		block_t aux;

		Curve_E521::mod_square(u, p_public_key.m_y);

		if(Curve_E521::compare_equal(u, {1, 0, 0, 0, 0, 0, 0, 0, 0}))
		{
			if(x_bit)
			{
				return false;
			}
			memset(p_public_key.m_x.data(), 0, sizeof(block_t));
			return true;
		}


		Curve_E521::mod_multiply(v, u, Curve_E521::D);
		Curve_E521::mod_decrement(u, u);
		Curve_E521::mod_decrement(v, v);

		//todo: find smaller algorithm
		memcpy(aux.data(), v.data(), sizeof(block_t));

		Curve_E521::mod_inverse(aux);

		Curve_E521::mod_multiply(aux, u, aux);

		for(uint16_t i = 0; i < 521 - 3; ++i)
		{
			Curve_E521::mod_square(aux, aux);
		}

		Curve_E521::mod_square(p_public_key.m_x, aux);

		Curve_E521::mod_square(aux, p_public_key.m_x);
		Curve_E521::mod_multiply(aux, v, aux);
		if(!Curve_E521::compare_equal(aux, u))
		{
			return false;
		}

		if((p_public_key.m_x[0] & 0x01 ? true : false) != x_bit)
		{
			Curve_E521::mod_negate(p_public_key.m_x);
		}

		return true;
	}


	bool Ed521::is_null(const point_t& p_public_key)
	{
		return memcmp(&p_public_key, &Curve_E521::neutral, sizeof(point_t)) == 0;
	}

	bool Ed521::is_on_curve(const point_t& p_public_key)
	{
		using block_t = Curve_E521::block_t;
		block_t lt;
		block_t y2;
		block_t rt;

		Curve_E521::mod_square(lt, p_public_key.m_x);
		Curve_E521::mod_square(y2, p_public_key.m_y);

		Curve_E521::mod_multiply(rt, lt, y2);
		Curve_E521::mod_multiply(rt, rt, Curve_E521::D);
		Curve_E521::mod_increment(rt, rt);

		Curve_E521::mod_add(lt, lt, y2);

		return memcmp(&lt, &rt, sizeof(block_t)) == 0;
	}


	void Ed521::sign(
		std::span<const uint8_t, key_lenght> p_private_key,
		std::span<const uint8_t, key_lenght> p_message_digest, std::span<const uint8_t> p_context,
		point_t& p_R, std::span<uint8_t, key_lenght> p_S)
	{
		//	r = sha2(context| 0 | sk | M)
		//	if r == 0: r = sha2(context| 1 | sk | M)
		//	R = r*G
		//	k = sha2(context| R | M)
		//	if k == 0: k = 1
		//	S = (r + k*sk)

		using block_t = Curve_E521::block_t;

		constexpr block_t null{0, 0, 0, 0, 0, 0, 0, 0, 0};

		block_t skey;
		skey[8] = 0;
		memcpy(skey.data(), p_private_key.data(), key_lenght);

		Curve_E521::order_reduce(skey);

		//r key
		block_t rkey;
		{
			Curve_E521::compute_r_key(skey, p_message_digest, p_context, 0, rkey);
			if(memcmp(rkey.data(), &null, sizeof(block_t)) == 0)
			{
				Curve_E521::compute_r_key(skey, p_message_digest, p_context, 1, rkey);
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
		Curve_E521::compute_k_key(p_message_digest, p_context, p_R, kkey);
		Curve_E521::order_multiply(skey, kkey);
		Curve_E521::order_add(skey, rkey);

		memcpy(p_S.data(), skey.data(), key_lenght);
	}

	bool Ed521::verify(const point_t& p_public_key,
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

		using block_t = Curve_E521::block_t;
		using projective_point_t = Curve_E521::projective_point_t;
		block_t kkey;
		Curve_E521::compute_k_key(p_message_digest, p_context, p_R, kkey);

		point_t p1;
		public_key(p_S, p1);

		projective_point_t p2;
		composite_key(std::span<const uint8_t, key_lenght>{reinterpret_cast<const uint8_t*>(kkey.data()), key_lenght}, p_public_key, p2);

		{
			p2.m_z[0] = 1;
			p2.m_z[1] = 0;
			p2.m_z[2] = 0;
			p2.m_z[3] = 0;
			p2.m_z[4] = 0;
			p2.m_z[5] = 0;
			p2.m_z[6] = 0;
			p2.m_z[7] = 0;
			p2.m_z[8] = 0;

			projective_point_t R_p;
			memcpy(R_p.m_x.data(), p_R.m_x.data(), sizeof(block_t));
			memcpy(R_p.m_y.data(), p_R.m_y.data(), sizeof(block_t));
			R_p.m_z[0] = 1;
			R_p.m_z[1] = 0;
			R_p.m_z[2] = 0;
			R_p.m_z[3] = 0;
			R_p.m_z[4] = 0;
			R_p.m_z[5] = 0;
			R_p.m_z[6] = 0;
			R_p.m_z[7] = 0;
			R_p.m_z[8] = 0;

			Curve_E521::ED_point_add(R_p, p2);

			Curve_E521::mod_inverse(p2.m_z);
			Curve_E521::mod_multiply(p2.m_x, p2.m_x, p2.m_z);
			Curve_E521::mod_multiply(p2.m_y, p2.m_y, p2.m_z);
		}

		return memcmp(&p1, &static_cast<point_t&>(p2), sizeof(p1)) == 0;
	}

} //namespace crypto
