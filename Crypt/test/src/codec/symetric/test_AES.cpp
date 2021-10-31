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
#include <CoreLib/Core_Endian.hpp>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <Crypt/codec/symetric/AES.hpp>

#include <test_utils.hpp>


TEST(codec_symetric, AES_128)
{

	const std::array<const uint8_t, 16> key =
	{
		0x00,
		0x01,
		0x02,
		0x03,
		0x04,
		0x05,
		0x06,
		0x07,
		0x08,
		0x09,
		0x0a,
		0x0b,
		0x0c,
		0x0d,
		0x0e,
		0x0f,
	};

	const std::array<const uint8_t, 16> data =
	{
		0x00,
		0x11,
		0x22,
		0x33,
		0x44,
		0x55,
		0x66,
		0x77,
		0x88,
		0x99,
		0xaa,
		0xbb,
		0xcc,
		0xdd,
		0xee,
		0xff,
	};

	const std::array<const uint8_t, 16> expected =
	{
		0x69,
		0xc4,
		0xe0,
		0xd8,
		0x6a,
		0x7b,
		0x04,
		0x30,
		0xd8,
		0xcd,
		0xb7,
		0x80,
		0x70,
		0xb4,
		0xc5,
		0x5a,
	};

	std::array<uint8_t, 16> encoded;
	crypt::AES_128::key_schedule_t w_key;

	crypt::AES_128::make_key_schedule(key, w_key);
	crypt::AES_128::encode(w_key, data, encoded);

	const bool result = (memcmp(encoded.data(), expected.data(), sizeof(encoded)) == 0);

	ASSERT_TRUE(result)
		<< "\n  Actual: " << testPrint{encoded}
		<< "\nExpected: " << testPrint{expected};


	std::array<uint8_t, 16> decoded;

	crypt::AES_128::decode(w_key, encoded, decoded);


	const bool result2 = (memcmp(decoded.data(), data.data(), sizeof(decoded)) == 0);

	ASSERT_TRUE(result2)
		<< "\n  Actual: " << testPrint{decoded}
		<< "\nExpected: " << testPrint{data};

}
