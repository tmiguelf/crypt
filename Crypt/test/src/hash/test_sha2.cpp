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




#include <array>

#include <CoreLib/Core_Type.hpp>
#include <CoreLib/toPrint/toPrint.hpp>
#include <CoreLib/toPrint/toPrint_std_ostream.hpp>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <Crypt/hash/sha2.hpp>


#include <test_utils.hpp>


using core::literals::operator "" _ui8;
using core::literals::operator "" _ui32;
using core::literals::operator "" _ui64;


template<>
class core::toPrint<crypt::SHA2_256::digest_t>: public core::toPrint_base
{
private:
	static constexpr uintptr_t array_size = core::to_chars_hex_max_digits_v<uint32_t> * 8 + 7;

public:
	constexpr toPrint(const crypt::SHA2_256::digest_t&p_data): m_data{p_data} {}

	template<_p::c_toPrint_char CharT>
	static inline constexpr uintptr_t size(const CharT&) { return array_size; }

	template<_p::c_toPrint_char CharT>
	inline void getPrint(CharT* p_out) const
	{
		core::_p::to_chars_hex_fix_unsafe(m_data[0], p_out);
		p_out += 8;
		*(p_out++) = ' ';
		core::_p::to_chars_hex_fix_unsafe(m_data[1], p_out);
		p_out += 8;
		*(p_out++) = ' ';
		core::_p::to_chars_hex_fix_unsafe(m_data[2], p_out);
		p_out += 8;
		*(p_out++) = ' ';
		core::_p::to_chars_hex_fix_unsafe(m_data[3], p_out);
		p_out += 8;
		*(p_out++) = ' ';
		core::_p::to_chars_hex_fix_unsafe(m_data[4], p_out);
		p_out += 8;
		*(p_out++) = ' ';
		core::_p::to_chars_hex_fix_unsafe(m_data[5], p_out);
		p_out += 8;
		*(p_out++) = ' ';
		core::_p::to_chars_hex_fix_unsafe(m_data[6], p_out);
		p_out += 8;
		*(p_out++) = ' ';
		core::_p::to_chars_hex_fix_unsafe(m_data[7], p_out);
	}

private:
	const crypt::SHA2_256::digest_t& m_data;
};


TEST(Hash, SHA2_256)
{

	testUtils::HashList testList = testUtils::getHashList("../test_vectors/tests.scef", U"SHA2_256", 32);
	ASSERT_FALSE(testList.empty());


	std::array<uint32_t, 16> data =
		{
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
			0x00000000_ui32,
		};

	const crypt::SHA2_256::digest_t expected =
		{
			0xf5a5fd42_ui32,
			0xd16a2030_ui32,
			0x2798ef6e_ui32,
			0xd309979b_ui32,
			0x43003d23_ui32,
			0x20d9f0e8_ui32,
			0xea9831a9_ui32,
			0x2759fb4b_ui32,
		};


	crypt::SHA2_256::digest_t tdigest = crypt::SHA2_256::default_init();

	crypt::SHA2_256::trasform(tdigest, {&data, 1});
	crypt::SHA2_256::trasform_final(tdigest, {}, 512);


	ASSERT_EQ(expected, tdigest) << core::toPrint{expected} << '\n' << core::toPrint{tdigest};


}
