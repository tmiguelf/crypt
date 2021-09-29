//======== ======== ======== ======== ======== ======== ======== ========
///	\file
///
///	\copyright
///		Copyright (c) 2021 Tiago Miguel Oliveira Freire
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

#include <Crypt/hash/sha2.hpp>

#include <cstring>
#include <bit>

#include <CoreLib/Core_Type.hpp>
#include <CoreLib/Core_Endian.hpp>

#if defined(_M_AMD64) || defined(__x86_64__)
#include <immintrin.h>
#else
#endif

namespace crypt
{
	using core::literals::operator "" _ui32;
	using core::literals::operator "" _ui64;

	namespace
	{
		struct SHA2_256_Help
		{
			static constexpr std::array<uint32_t, 64> K =
			{
				0x428A2F98_ui32, 0x71374491_ui32, 0xB5C0FBCF_ui32, 0xE9B5DBA5_ui32,
				0x3956C25B_ui32, 0x59F111F1_ui32, 0x923F82A4_ui32, 0xAB1C5ED5_ui32,
				0xD807AA98_ui32, 0x12835B01_ui32, 0x243185BE_ui32, 0x550C7DC3_ui32,
				0x72BE5D74_ui32, 0x80DEB1FE_ui32, 0x9BDC06A7_ui32, 0xC19BF174_ui32,
				0xE49B69C1_ui32, 0xEFBE4786_ui32, 0x0FC19DC6_ui32, 0x240CA1CC_ui32,
				0x2DE92C6F_ui32, 0x4A7484AA_ui32, 0x5CB0A9DC_ui32, 0x76F988DA_ui32,
				0x983E5152_ui32, 0xA831C66D_ui32, 0xB00327C8_ui32, 0xBF597FC7_ui32,
				0xC6E00BF3_ui32, 0xD5A79147_ui32, 0x06CA6351_ui32, 0x14292967_ui32,
				0x27B70A85_ui32, 0x2E1B2138_ui32, 0x4D2C6DFC_ui32, 0x53380D13_ui32,
				0x650A7354_ui32, 0x766A0ABB_ui32, 0x81C2C92E_ui32, 0x92722C85_ui32,
				0xA2BFE8A1_ui32, 0xA81A664B_ui32, 0xC24B8B70_ui32, 0xC76C51A3_ui32,
				0xD192E819_ui32, 0xD6990624_ui32, 0xF40E3585_ui32, 0x106AA070_ui32,
				0x19A4C116_ui32, 0x1E376C08_ui32, 0x2748774C_ui32, 0x34B0BCB5_ui32,
				0x391C0CB3_ui32, 0x4ED8AA4A_ui32, 0x5B9CCA4F_ui32, 0x682E6FF3_ui32,
				0x748F82EE_ui32, 0x78A5636F_ui32, 0x84C87814_ui32, 0x8CC70208_ui32,
				0x90BEFFFA_ui32, 0xA4506CEB_ui32, 0xBEF9A3F7_ui32, 0xC67178F2_ui32,
			};

			static inline constexpr uint32_t Ch(const uint32_t p_x, const uint32_t p_y, const uint32_t p_z)
			{
				return (p_x & p_y) ^ ((~p_x) & p_z);
			}

			static inline constexpr uint32_t Maj(const uint32_t p_x, const uint32_t p_y, const uint32_t p_z)
			{
				return (p_x & p_y) ^ (p_x & p_z) ^ (p_y & p_z);
			}

			static inline constexpr uint32_t Sigma_U_0(const uint32_t p_val)
			{
				return std::rotr(p_val, 2) ^ std::rotr(p_val, 13) ^ std::rotr(p_val, 22);
			}

			static inline constexpr uint32_t Sigma_U_1(const uint32_t p_val)
			{
				return std::rotr(p_val, 6) ^ std::rotr(p_val, 11) ^ std::rotr(p_val, 25);
			}

			static inline constexpr uint32_t sigma_l_0(const uint32_t p_val)
			{
				return std::rotr(p_val, 7) ^ std::rotr(p_val, 18) ^ (p_val >> 3);
			}

			static inline constexpr uint32_t sigma_l_1(const uint32_t p_val)
			{
				return std::rotr(p_val, 17) ^ std::rotr(p_val, 19) ^ (p_val >> 10);
			}

			static void round(SHA2_256::digest_t& p_state, uint32_t const p_KW)
			{
				const uint32_t T1 =
					p_state[7]
					+ Sigma_U_1(p_state[4])
					+ Ch(p_state[4], p_state[5], p_state[6])
					+ p_KW;

				const uint32_t T2 =
					Sigma_U_0(p_state[0]) + Maj(p_state[0], p_state[1], p_state[2]);

				p_state[7] = p_state[6];
				p_state[6] = p_state[5];
				p_state[5] = p_state[4];
				p_state[4] = p_state[3];
				p_state[3] = p_state[2];
				p_state[2] = p_state[1];
				p_state[1] = p_state[0];

				p_state[0] = T1 + T2;
				p_state[4] += T1;
			}

			static void block_digest(SHA2_256::digest_t& p_digest, const SHA2_256::block_t& p_block)
			{
				SHA2_256::digest_t localD = p_digest;
				std::array<uint32_t, 64> block_M;
				memcpy(block_M.data(), p_block.data(), sizeof(SHA2_256::block_t));

				for(uintptr_t i = 16; i < 64; ++i)
				{
					block_M[i] =
						sigma_l_1(block_M[i - 2])
						+ block_M[i - 7]
						+ sigma_l_0(block_M[i - 15])
						+ block_M[i - 16];
				}

				for(uintptr_t i = 0; i < 64; ++i)
				{
					round(localD, K[i] + block_M[i]);
				}

				for(uintptr_t i = 0; i < 8; ++i)
				{
					p_digest[i] += localD[i];
				}
			}
		};

	} //namespace

	void SHA2_256::trasform(digest_t& p_digest, std::span<const block_t> p_data)
	{
		for(const block_t& tBlock : p_data)
		{
			SHA2_256_Help::block_digest(p_digest, tBlock);
		}
	}

	void SHA2_256::trasform_final(digest_t& p_digest, std::span<const uint8_t> p_data, uint64_t p_totalSize)
	{
		//todo







		block_t block;



		memset(block.data(), 0, sizeof(block_t));
		block[0] = 0x80000000;

		memcpy(block.data() + 14, reinterpret_cast<uint32_t*>(&p_totalSize) + 1, 4);
		memcpy(block.data() + 15, reinterpret_cast<uint32_t*>(&p_totalSize), 4);

		SHA2_256_Help::block_digest(p_digest, block);

	}



	//static void SHA2_256::trasform_final(digest_t& p_digest, std::span<const uint8_t> p_data, uint64_t p_totalSize);

} //namespace crypt
