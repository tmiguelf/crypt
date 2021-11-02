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

#pragma once
#include <cstdint>
#include <array>
#include <span>

namespace Crypt
{
	namespace _p
	{
		union wblock_t
		{
			uint32_t ui32;
			uint8_t  ui8[4];
		};
	}//namespace _p

	class AES_128
	{
	public:
		static constexpr uintptr_t key_lenght = 16;
		static constexpr uintptr_t block_lenght = 16;
		static constexpr uintptr_t number_of_rounds = 10;

		static constexpr uintptr_t key_schedule_size = (number_of_rounds + 1) * 4;

		struct key_schedule_t
		{
			alignas(8) std::array<_p::wblock_t, key_schedule_size> wkey;
		};

	public:
		static void make_key_schedule(std::span<const uint8_t, key_lenght> p_key, key_schedule_t& p_wkey);

		static void encode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out);
		static void decode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out);
	};

	class AES_192
	{
	public:
		static constexpr uintptr_t key_lenght = 24;
		static constexpr uintptr_t block_lenght = 16;
		static constexpr uintptr_t number_of_rounds = 12;

		static constexpr uintptr_t key_schedule_size = (number_of_rounds + 1) * 4;

		struct key_schedule_t
		{
			alignas(8) std::array<_p::wblock_t, key_schedule_size> wkey;
		};

	public:
		static void make_key_schedule(std::span<const uint8_t, key_lenght> p_key, key_schedule_t& p_wkey);

		static void encode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out);
		static void decode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out);
	};

	class AES_256
	{
	public:
		static constexpr uintptr_t key_lenght = 32;
		static constexpr uintptr_t block_lenght = 16;
		static constexpr uintptr_t number_of_rounds = 14;

		static constexpr uintptr_t key_schedule_size = (number_of_rounds + 1) * 4;

		struct key_schedule_t
		{
			alignas(8) std::array<_p::wblock_t, key_schedule_size> wkey;
		};

	public:
		static void make_key_schedule(std::span<const uint8_t, key_lenght> p_key, key_schedule_t& p_wkey);

		static void encode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out);
		static void decode(const key_schedule_t& p_wkey, std::span<const uint8_t, block_lenght> p_input, std::span<uint8_t, block_lenght> p_out);
	};
}
