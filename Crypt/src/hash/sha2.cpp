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

#include <algorithm>
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
			static constexpr uintptr_t block_size = 64;

			using block_t = std::array<uint8_t, block_size>;

			using M_block_t = std::array<uint32_t, 64>;

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

			static inline void gen_16_64_M_block(M_block_t& p_prefilledBlock)
			{
				for(uintptr_t i = 16; i < 64; ++i)
				{
					p_prefilledBlock[i] =
						sigma_l_1(p_prefilledBlock[i - 2])
						+ p_prefilledBlock[i - 7]
						+ sigma_l_0(p_prefilledBlock[i - 15])
						+ p_prefilledBlock[i - 16];
				}
			}

			static inline void transfer_to_M_block(const block_t& p_block, M_block_t& p_out)
			{
				memcpy(&p_out, &p_block, sizeof(M_block_t));
				for(uintptr_t i = 0; i < 16; ++i)
				{
					p_out[i] = core::endian_big2host(p_out[i]);
				}
			}

			static void M_block_digest(SHA2_256::digest_t& p_digest, const M_block_t& p_M)
			{
				SHA2_256::digest_t localD = p_digest;

				for(uintptr_t i = 0; i < 64; ++i)
				{
					round(localD, K[i] + p_M[i]);
				}

				for(uintptr_t i = 0; i < 8; ++i)
				{
					p_digest[i] += localD[i];
				}
			}

			static void process_block(SHA2_256::digest_t& p_digest, const block_t& p_block)
			{
				std::array<uint32_t, 64> block_M;
				transfer_to_M_block(p_block, block_M);
				gen_16_64_M_block(block_M);
				M_block_digest(p_digest, block_M);
			}

			static void process_blocks(SHA2_256::digest_t& p_digest, const std::span<const block_t> p_blocks)
			{
				for(const block_t& tblock : p_blocks)
				{
					process_block(p_digest, tblock);
				}
			}














		};
	} //namespace


	void SHA2_256::reset()
	{
		m_context = default_init();
		m_total_size = 0;
		m_cached_size = 0;
	}


	void SHA2_256::update(std::span<const uint8_t> p_data)
	{
		uintptr_t size = p_data.size();
		m_total_size += size;
		
		if(m_cached_size)
		{
			if(size + m_cached_size >= SHA2_256_Help::block_size)
			{
				uintptr_t remain = SHA2_256_Help::block_size - m_cached_size;
				remain = std::min(remain, size);
				memcpy(m_cached.data() + m_cached_size, p_data.data(), remain);
				m_cached_size = 0;
				//process block
				SHA2_256_Help::process_block(m_context, m_cached);

				if(size == remain) return;

				p_data = p_data.subspan(remain);
				size   = p_data.size();
			}
			else
			{
				memcpy(m_cached.data() + m_cached_size, p_data.data(), size);
				m_cached_size += static_cast<uint8_t>(size);
				return;
			}
		}

		const uint8_t   remainder		= static_cast<uint8_t>(size & (SHA2_256_Help::block_size - 1)); // size % 64
		const uintptr_t handled_bytes	= size - remainder;

		if(handled_bytes)
		{
			const uintptr_t handled_blocks = handled_bytes >> 6; // size / 64
			SHA2_256_Help::process_blocks(
				m_context,
				std::span<const SHA2_256_Help::block_t>{reinterpret_cast<const SHA2_256_Help::block_t*>(p_data.data()), handled_blocks});
			p_data = p_data.subspan(handled_bytes);
		}

		if(remainder)
		{
			memcpy(m_cached.data(), p_data.data(), remainder);
			m_cached_size = remainder;
		}
	}


	void SHA2_256::finalize()
	{
		const uint8_t cached_size = m_cached_size + 1;
		m_cached[m_cached_size] = 0x80;
		m_cached_size = 0;

		const uint64_t total_size = m_total_size << 3; //m_total_size * 8
		m_total_size = 0;

		const uintptr_t remainder = SHA2_256_Help::block_size - cached_size;

		SHA2_256_Help::M_block_t block_M{0};
		memset(m_cached.data() + cached_size, 0, remainder);
		if(remainder < 8)
		{
			memset(m_cached.data() + cached_size, 0, remainder);
			SHA2_256_Help::process_block(m_context, m_cached);
		}
		else
		{
			memset(m_cached.data() + cached_size, 0, remainder - 8);
			SHA2_256_Help::transfer_to_M_block(m_cached, block_M);
		}

		block_M[14] = static_cast<uint32_t>(total_size >> 32);
		block_M[15] = static_cast<uint32_t>(total_size);

		SHA2_256_Help::gen_16_64_M_block(block_M);
		SHA2_256_Help::M_block_digest(m_context, block_M);
	}


} //namespace crypt
