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

#include <Crypt/codec/symmetric/AES.hpp>

#include <bit>
#include <cstring>

#include <CoreLib/Core_Type.hpp>

namespace Crypt
{
	using core::literals::operator "" _ui8;
	using core::literals::operator "" _ui64;

	static constexpr std::array<uint8_t, 256> invert_s_box(const std::array<uint8_t, 256>& p_s_box)
	{
		std::array<uint8_t, 256> out{};
		uint8_t i = 0;
		for(const uint8_t aux : p_s_box)
		{
			out[aux] = i++;
		}
		return out;
	}

//	static constexpr uint8_t galois_mult(uint8_t p_1, uint8_t p_2)
//	{
//		uint8_t p = 0;
//		while(p_1 && p_2)
//		{
//			if(p_2 & 0x01)
//			{
//				p ^= p_1;
//			}
//
//			if(p_1 & 0x80)
//			{
//				p_1 = (p_1 << 1) ^ 0x1B;
//			}
//			else
//			{
//				p_1 <<= 1;
//			}
//			p_2 >>= 1;
//		}
//		return p;
//	}

	struct AES_Help
	{
		static constexpr uintptr_t block_lenght = 16;
		using state_t = std::array<uint8_t, block_lenght>;

		static constexpr std::array<uint8_t, 256> s_box =
		{
			0x63_ui8, 0x7c_ui8, 0x77_ui8, 0x7b_ui8, 0xf2_ui8, 0x6b_ui8, 0x6f_ui8, 0xc5_ui8,
			0x30_ui8, 0x01_ui8, 0x67_ui8, 0x2b_ui8, 0xfe_ui8, 0xd7_ui8, 0xab_ui8, 0x76_ui8,
			0xca_ui8, 0x82_ui8, 0xc9_ui8, 0x7d_ui8, 0xfa_ui8, 0x59_ui8, 0x47_ui8, 0xf0_ui8,
			0xad_ui8, 0xd4_ui8, 0xa2_ui8, 0xaf_ui8, 0x9c_ui8, 0xa4_ui8, 0x72_ui8, 0xc0_ui8,
			0xb7_ui8, 0xfd_ui8, 0x93_ui8, 0x26_ui8, 0x36_ui8, 0x3f_ui8, 0xf7_ui8, 0xcc_ui8,
			0x34_ui8, 0xa5_ui8, 0xe5_ui8, 0xf1_ui8, 0x71_ui8, 0xd8_ui8, 0x31_ui8, 0x15_ui8,
			0x04_ui8, 0xc7_ui8, 0x23_ui8, 0xc3_ui8, 0x18_ui8, 0x96_ui8, 0x05_ui8, 0x9a_ui8,
			0x07_ui8, 0x12_ui8, 0x80_ui8, 0xe2_ui8, 0xeb_ui8, 0x27_ui8, 0xb2_ui8, 0x75_ui8,
			0x09_ui8, 0x83_ui8, 0x2c_ui8, 0x1a_ui8, 0x1b_ui8, 0x6e_ui8, 0x5a_ui8, 0xa0_ui8,
			0x52_ui8, 0x3b_ui8, 0xd6_ui8, 0xb3_ui8, 0x29_ui8, 0xe3_ui8, 0x2f_ui8, 0x84_ui8,
			0x53_ui8, 0xd1_ui8, 0x00_ui8, 0xed_ui8, 0x20_ui8, 0xfc_ui8, 0xb1_ui8, 0x5b_ui8,
			0x6a_ui8, 0xcb_ui8, 0xbe_ui8, 0x39_ui8, 0x4a_ui8, 0x4c_ui8, 0x58_ui8, 0xcf_ui8,
			0xd0_ui8, 0xef_ui8, 0xaa_ui8, 0xfb_ui8, 0x43_ui8, 0x4d_ui8, 0x33_ui8, 0x85_ui8,
			0x45_ui8, 0xf9_ui8, 0x02_ui8, 0x7f_ui8, 0x50_ui8, 0x3c_ui8, 0x9f_ui8, 0xa8_ui8,
			0x51_ui8, 0xa3_ui8, 0x40_ui8, 0x8f_ui8, 0x92_ui8, 0x9d_ui8, 0x38_ui8, 0xf5_ui8,
			0xbc_ui8, 0xb6_ui8, 0xda_ui8, 0x21_ui8, 0x10_ui8, 0xff_ui8, 0xf3_ui8, 0xd2_ui8,
			0xcd_ui8, 0x0c_ui8, 0x13_ui8, 0xec_ui8, 0x5f_ui8, 0x97_ui8, 0x44_ui8, 0x17_ui8,
			0xc4_ui8, 0xa7_ui8, 0x7e_ui8, 0x3d_ui8, 0x64_ui8, 0x5d_ui8, 0x19_ui8, 0x73_ui8,
			0x60_ui8, 0x81_ui8, 0x4f_ui8, 0xdc_ui8, 0x22_ui8, 0x2a_ui8, 0x90_ui8, 0x88_ui8,
			0x46_ui8, 0xee_ui8, 0xb8_ui8, 0x14_ui8, 0xde_ui8, 0x5e_ui8, 0x0b_ui8, 0xdb_ui8,
			0xe0_ui8, 0x32_ui8, 0x3a_ui8, 0x0a_ui8, 0x49_ui8, 0x06_ui8, 0x24_ui8, 0x5c_ui8,
			0xc2_ui8, 0xd3_ui8, 0xac_ui8, 0x62_ui8, 0x91_ui8, 0x95_ui8, 0xe4_ui8, 0x79_ui8,
			0xe7_ui8, 0xc8_ui8, 0x37_ui8, 0x6d_ui8, 0x8d_ui8, 0xd5_ui8, 0x4e_ui8, 0xa9_ui8,
			0x6c_ui8, 0x56_ui8, 0xf4_ui8, 0xea_ui8, 0x65_ui8, 0x7a_ui8, 0xae_ui8, 0x08_ui8,
			0xba_ui8, 0x78_ui8, 0x25_ui8, 0x2e_ui8, 0x1c_ui8, 0xa6_ui8, 0xb4_ui8, 0xc6_ui8,
			0xe8_ui8, 0xdd_ui8, 0x74_ui8, 0x1f_ui8, 0x4b_ui8, 0xbd_ui8, 0x8b_ui8, 0x8a_ui8,
			0x70_ui8, 0x3e_ui8, 0xb5_ui8, 0x66_ui8, 0x48_ui8, 0x03_ui8, 0xf6_ui8, 0x0e_ui8,
			0x61_ui8, 0x35_ui8, 0x57_ui8, 0xb9_ui8, 0x86_ui8, 0xc1_ui8, 0x1d_ui8, 0x9e_ui8,
			0xe1_ui8, 0xf8_ui8, 0x98_ui8, 0x11_ui8, 0x69_ui8, 0xd9_ui8, 0x8e_ui8, 0x94_ui8,
			0x9b_ui8, 0x1e_ui8, 0x87_ui8, 0xe9_ui8, 0xce_ui8, 0x55_ui8, 0x28_ui8, 0xdf_ui8,
			0x8c_ui8, 0xa1_ui8, 0x89_ui8, 0x0d_ui8, 0xbf_ui8, 0xe6_ui8, 0x42_ui8, 0x68_ui8,
			0x41_ui8, 0x99_ui8, 0x2d_ui8, 0x0f_ui8, 0xb0_ui8, 0x54_ui8, 0xbb_ui8, 0x16_ui8,
		};

		static constexpr std::array<uint8_t, 256> inv_s_box = invert_s_box(s_box);

		static constexpr std::array<uint8_t, 10> rcon =
		{
			0x01_ui8, 0x02_ui8, 0x04_ui8, 0x08_ui8, 0x10_ui8,
			0x20_ui8, 0x40_ui8, 0x80_ui8, 0x1B_ui8, 0x36_ui8,
		};

		static inline void RotWord(uint32_t& p_Key)
		{
			if constexpr(std::endian::native == std::endian::little)
			{
				p_Key = std::rotr(p_Key, 8);
			}
			else
			{
				p_Key = std::rotl(p_Key, 8);
			}
		}

		static inline void RotWord(uint32_t& p_Key, const uint8_t p_count)
		{
			if constexpr(std::endian::native == std::endian::little)
			{
				p_Key = std::rotr(p_Key, p_count);
			}
			else
			{
				p_Key = std::rotl(p_Key, p_count);
			}
		}

		static void ShiftRows(state_t& p_state)
		{
			const _p::wblock_t sv{.ui32 = *reinterpret_cast<uint32_t*>(p_state.data())};
			const uint8_t aux = p_state[6];

			p_state[ 1] = p_state[ 5];
			p_state[ 5] = p_state[ 9];
			p_state[ 9] = p_state[13];

			p_state[ 2] = p_state[10];
			p_state[ 6] = p_state[14];

			p_state[ 3] = p_state[15];
			p_state[15] = p_state[11];
			p_state[11] = p_state[ 7];

			p_state[13] = sv.ui8[1];
			p_state[10] = sv.ui8[2];
			p_state[14] = aux;
			p_state[ 7] = sv.ui8[3];

		}

		static void InvShiftRows(state_t& p_state)
		{
			const _p::wblock_t sv{.ui32 = *reinterpret_cast<uint32_t*>(p_state.data())};
			const uint8_t aux = p_state[6];

			p_state[ 1] = p_state[13];
			p_state[13] = p_state[ 9];
			p_state[ 9] = p_state[ 5];

			p_state[ 2] = p_state[10];
			p_state[ 6] = p_state[14];

			p_state[ 3] = p_state[ 7];
			p_state[ 7] = p_state[11];
			p_state[11] = p_state[15];

			p_state[ 5] = sv.ui8[1];
			p_state[10] = sv.ui8[2];
			p_state[14] = aux;
			p_state[15] = sv.ui8[3];
		}

		static inline void SubWord(_p::wblock_t& p_word)
		{
			p_word.ui8[0] = s_box[p_word.ui8[0]];
			p_word.ui8[1] = s_box[p_word.ui8[1]];
			p_word.ui8[2] = s_box[p_word.ui8[2]];
			p_word.ui8[3] = s_box[p_word.ui8[3]];
		}

		static void SubBytes(state_t& p_state)
		{
			for(uint8_t& tpoint : p_state)
			{
				tpoint = s_box[tpoint];
			}
		}

		static void InvSubBytes(state_t& p_state)
		{
			for(uint8_t& tpoint : p_state)
			{
				tpoint = inv_s_box[tpoint];
			}
		}

		//note:
		//	1. Galois mult gm(2,P) = (P << 1) ^ (0x80 & P ? 0x1B : 0)
		//	2. Galois mult gm(3,P) = P ^ gm(2,P)
		//	3. s0 = gm(2,s0) ^ gm(3,s1) ^ s2 ^ s3 is same as
		//		s0 ^= s0 ^ s1 ^ s2 ^ s3 ^ gm(2, s0) ^ gm(2, s1)
		static void galouis_mix(uint64_t& p_val)
		{
			const uint64_t in = p_val;

			uint64_t mix_val = in ^ (in >> 8);
			mix_val ^= (mix_val >> 16);
			mix_val = (mix_val & 0x000000FF000000FF_ui64) * 0x01010101_ui64;

			const uint64_t rem_gal =
				(((in & 0x8080808080808080_ui64) >> 7) * 0x1B_ui64) ^
				( (in & 0x7F7F7F7F7F7F7F7F_ui64) << 1);

			uint64_t rot_gal = rem_gal;
			RotWord(*reinterpret_cast<uint32_t*>(&rot_gal));
			RotWord(*(reinterpret_cast<uint32_t*>(&rot_gal) + 1));

			p_val ^= mix_val ^ rot_gal ^ rem_gal;
		}


		static inline void inv_g_mod(uint8_t& p_1)
		{
			constexpr uint8_t v_1 = 0x1B;
			constexpr uint8_t v_2 = 0x36;
			constexpr uint8_t v_4 = 0x6C;

			constexpr std::array<uint8_t, 8> tab =
			{
				0,
				v_1,
				v_2,
				v_2 ^ v_1,
				v_4,
				v_4 ^ v_1,
				v_4 ^ v_2,
				v_4 ^ v_2 ^ v_1,
			};

			p_1 ^= static_cast<uint8_t>(static_cast<uint8_t>(p_1 << 3) ^ tab[p_1 >> 5]);
		}

		//algorithm extensively simplified
		static void inv_galouis_mix(uint64_t& p_val)
		{
			const uint64_t in = p_val;

			uint64_t mix_val = in ^ (in >> 8);
			mix_val ^= (mix_val >> 16);
			mix_val &= 0x000000FF000000FF_ui64;

			if constexpr (std::endian::native == std::endian::little)
			{
				inv_g_mod(*reinterpret_cast<uint8_t*>(&mix_val));
				inv_g_mod(*(reinterpret_cast<uint8_t*>(&mix_val) + 4));
			}
			else
			{
				inv_g_mod(*(reinterpret_cast<uint8_t*>(&mix_val) + 3));
				inv_g_mod(*(reinterpret_cast<uint8_t*>(&mix_val) + 7));
			}

			mix_val *= 0x01010101_ui64;

			const uint64_t lb = (in >> 7) & 0x0101010101010101;
			const uint64_t mb = (in >> 6) & 0x0101010101010101;

			uint64_t f_B_1 = ((in & 0x7F7F7F7F7F7F7F7F) << 1) ^ (lb * 0x1B);
			uint64_t f_B_2 = ((in & 0x3F3F3F3F3F3F3F3F) << 2) ^ (lb * 0x36) ^ (mb * 0x1B);
			const uint64_t f_B_3 = f_B_1 ^ f_B_2;

			RotWord(*reinterpret_cast<uint32_t*>(&f_B_1));
			RotWord(*(reinterpret_cast<uint32_t*>(&f_B_1) + 1));
			RotWord(*reinterpret_cast<uint32_t*>(&f_B_2), 16);
			RotWord(*(reinterpret_cast<uint32_t*>(&f_B_2) + 1), 16);

			p_val ^= mix_val ^ f_B_3 ^ f_B_2 ^ f_B_1;
		}

		static void MixColumns(state_t& p_state)
		{
			galouis_mix(*reinterpret_cast<uint64_t*>(p_state.data()));
			galouis_mix(*(reinterpret_cast<uint64_t*>(p_state.data()) + 1));
		}

		static void InvMixColumns(state_t& p_state)
		{
			inv_galouis_mix(*reinterpret_cast<uint64_t*>(p_state.data()));
			inv_galouis_mix(*(reinterpret_cast<uint64_t*>(p_state.data()) + 1));
		}

		static void AddRoundKey(state_t& p_state, std::span<const _p::wblock_t, 4> p_roundKey)
		{
			*reinterpret_cast<uint64_t*>(p_state.data()) ^= *reinterpret_cast<const uint64_t*>(p_roundKey.data());
			*(reinterpret_cast<uint64_t*>(p_state.data()) + 1) ^= *(reinterpret_cast<const uint64_t*>(p_roundKey.data()) + 1);
		}
	};

	void AES_128::make_key_schedule(std::span<const uint8_t, key_lenght> p_key, key_schedule_t& p_wkey)
	{
		memcpy(p_wkey.wkey.data(), p_key.data(), key_lenght);

		_p::wblock_t* pivot = p_wkey.wkey.data();

		for(uint8_t i = 0; i < 10; ++i)
		{
			_p::wblock_t* const pivot_next = pivot + 4;
			memcpy(pivot_next, pivot, 16);

			_p::wblock_t temp = *(pivot + 3);
			AES_Help::RotWord(temp.ui32);
			AES_Help::SubWord(temp);
			temp.ui8[0] ^= AES_Help::rcon[i];

			pivot_next[0].ui32 ^= temp.ui32;
			pivot_next[1].ui32 ^= pivot_next[0].ui32;
			pivot_next[2].ui32 ^= pivot_next[1].ui32;
			pivot_next[3].ui32 ^= pivot_next[2].ui32;

			pivot = pivot_next;
		}
	}

	void AES_128::encode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out)
	{
		alignas(8) AES_Help::state_t state;
		memcpy(&state, p_input.data(), sizeof(state));

		for(uint8_t i = 0; i < number_of_rounds - 1; ++i)
		{
			AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (i << 2), 4});
			AES_Help::SubBytes(state);
			AES_Help::ShiftRows(state);
			AES_Help::MixColumns(state);
		}

		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + ((number_of_rounds - 1) * 4), 4});
		AES_Help::SubBytes(state);
		AES_Help::ShiftRows(state);
		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (number_of_rounds * 4), 4});

		memcpy(p_out.data(), &state, sizeof(state));
	}


	void AES_128::decode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out)
	{
		alignas(8) AES_Help::state_t state;
		memcpy(&state, p_input.data(), sizeof(state));

		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (number_of_rounds * 4), 4});


		for(uint8_t i = number_of_rounds - 1; i; --i)
		{
			AES_Help::InvShiftRows(state);
			AES_Help::InvSubBytes(state);
			AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (i << 2), 4});
			AES_Help::InvMixColumns(state);
		}

		AES_Help::InvShiftRows(state);
		AES_Help::InvSubBytes(state);
		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data(), 4});

		memcpy(p_out.data(), &state, sizeof(state));
	}


	void AES_192::make_key_schedule(std::span<const uint8_t, key_lenght> p_key, key_schedule_t& p_wkey)
	{
		memcpy(p_wkey.wkey.data(), p_key.data(), key_lenght);

		_p::wblock_t* pivot = p_wkey.wkey.data();

		for(uint8_t i = 0; i < 7; ++i)
		{
			_p::wblock_t* const pivot_next = pivot + 6;
			memcpy(pivot_next, pivot, 24);

			_p::wblock_t temp = *(pivot + 5);
			AES_Help::RotWord(temp.ui32);
			AES_Help::SubWord(temp);
			temp.ui8[0] ^= AES_Help::rcon[i];

			pivot_next[0].ui32 ^= temp.ui32;
			pivot_next[1].ui32 ^= pivot_next[0].ui32;
			pivot_next[2].ui32 ^= pivot_next[1].ui32;
			pivot_next[3].ui32 ^= pivot_next[2].ui32;
			pivot_next[4].ui32 ^= pivot_next[3].ui32;
			pivot_next[5].ui32 ^= pivot_next[4].ui32;

			pivot = pivot_next;
		}
		{
			_p::wblock_t* const pivot_next = pivot + 6;
			memcpy(pivot_next, pivot, 16);
			_p::wblock_t temp = *(pivot + 5);
			AES_Help::RotWord(temp.ui32);
			AES_Help::SubWord(temp);
			temp.ui8[0] ^= AES_Help::rcon[7];
			pivot_next[0].ui32 ^= temp.ui32;
			pivot_next[1].ui32 ^= pivot_next[0].ui32;
			pivot_next[2].ui32 ^= pivot_next[1].ui32;
			pivot_next[3].ui32 ^= pivot_next[2].ui32;
		}
	}

	void AES_192::encode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out)
	{
		alignas(8) AES_Help::state_t state;
		memcpy(&state, p_input.data(), sizeof(state));

		for(uint8_t i = 0; i < number_of_rounds - 1; ++i)
		{
			AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (i << 2), 4});
			AES_Help::SubBytes(state);
			AES_Help::ShiftRows(state);
			AES_Help::MixColumns(state);
		}

		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + ((number_of_rounds - 1) * 4), 4});
		AES_Help::SubBytes(state);
		AES_Help::ShiftRows(state);
		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (number_of_rounds * 4), 4});

		memcpy(p_out.data(), &state, sizeof(state));
	}

	void AES_192::decode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out)
	{
		alignas(8) AES_Help::state_t state;
		memcpy(&state, p_input.data(), sizeof(state));

		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (number_of_rounds * 4), 4});


		for(uint8_t i = number_of_rounds - 1; i; --i)
		{
			AES_Help::InvShiftRows(state);
			AES_Help::InvSubBytes(state);
			AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (i << 2), 4});
			AES_Help::InvMixColumns(state);
		}

		AES_Help::InvShiftRows(state);
		AES_Help::InvSubBytes(state);
		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data(), 4});

		memcpy(p_out.data(), &state, sizeof(state));
	}


	void AES_256::make_key_schedule(std::span<const uint8_t, key_lenght> p_key, key_schedule_t& p_wkey)
	{
		memcpy(p_wkey.wkey.data(), p_key.data(), key_lenght);

		_p::wblock_t* pivot = p_wkey.wkey.data();

		for(uint8_t i = 0; i < 6; ++i)
		{
			_p::wblock_t* const pivot_next = pivot + 8;
			memcpy(pivot_next, pivot, 32);

			_p::wblock_t temp = *(pivot + 7);
			AES_Help::RotWord(temp.ui32);
			AES_Help::SubWord(temp);
			temp.ui8[0] ^= AES_Help::rcon[i];

			pivot_next[0].ui32 ^= temp.ui32;
			pivot_next[1].ui32 ^= pivot_next[0].ui32;
			pivot_next[2].ui32 ^= pivot_next[1].ui32;
			pivot_next[3].ui32 ^= pivot_next[2].ui32;

			temp = pivot_next[3];
			AES_Help::SubWord(temp);

			pivot_next[4].ui32 ^= temp.ui32;
			pivot_next[5].ui32 ^= pivot_next[4].ui32;
			pivot_next[6].ui32 ^= pivot_next[5].ui32;
			pivot_next[7].ui32 ^= pivot_next[6].ui32;

			pivot = pivot_next;
		}
		{
			_p::wblock_t* const pivot_next = pivot + 8;
			memcpy(pivot_next, pivot, 16);
			_p::wblock_t temp = *(pivot + 7);
			AES_Help::RotWord(temp.ui32);
			AES_Help::SubWord(temp);
			temp.ui8[0] ^= AES_Help::rcon[6];
			pivot_next[0].ui32 ^= temp.ui32;
			pivot_next[1].ui32 ^= pivot_next[0].ui32;
			pivot_next[2].ui32 ^= pivot_next[1].ui32;
			pivot_next[3].ui32 ^= pivot_next[2].ui32;
		}
	}

	void AES_256::encode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out)
	{
		alignas(8) AES_Help::state_t state;
		memcpy(&state, p_input.data(), sizeof(state));

		for(uint8_t i = 0; i < number_of_rounds - 1; ++i)
		{
			AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (i << 2), 4});
			AES_Help::SubBytes(state);
			AES_Help::ShiftRows(state);
			AES_Help::MixColumns(state);
		}

		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + ((number_of_rounds - 1) * 4), 4});
		AES_Help::SubBytes(state);
		AES_Help::ShiftRows(state);
		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (number_of_rounds * 4), 4});

		memcpy(p_out.data(), &state, sizeof(state));
	}

	void AES_256::decode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out)
	{
		alignas(8) AES_Help::state_t state;
		memcpy(&state, p_input.data(), sizeof(state));

		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (number_of_rounds * 4), 4});


		for(uint8_t i = number_of_rounds - 1; i; --i)
		{
			AES_Help::InvShiftRows(state);
			AES_Help::InvSubBytes(state);
			AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data() + (i << 2), 4});
			AES_Help::InvMixColumns(state);
		}

		AES_Help::InvShiftRows(state);
		AES_Help::InvSubBytes(state);
		AES_Help::AddRoundKey(state, std::span<const _p::wblock_t, 4>{p_wkey.wkey.data(), 4});

		memcpy(p_out.data(), &state, sizeof(state));
	}



}


