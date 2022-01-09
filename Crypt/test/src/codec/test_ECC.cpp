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

#include <array>
#include <random>

#include <CoreLib/Core_Type.hpp>
#include <CoreLib/toPrint/toPrint.hpp>
#include <CoreLib/toPrint/toPrint_std_ostream.hpp>
#include <CoreLib/Core_Endian.hpp>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <Crypt/codec/ECC.hpp>

#include <test_utils.hpp>

#include "../src/codec/ECC.cpp"


TEST(codec_asymmetric, ECC_ED25519_compute)
{
	using key_t   = crypto::ElypticCurve_Ed25519::key_t;
	using point_t = crypto::ElypticCurve_Ed25519::point_t;
	struct TestCase
	{
		key_t private_key;
		key_t public_key;
	};

	const std::array test_cases
	{
	//	TestCase
	//	{
	//		.private_key
	//		{
	//			0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
	//			0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	//			0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
	//			0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x00,
	//		},
	//		.public_key
	//		{
	//			0x20, 0xDA, 0xCB, 0xAB, 0x40, 0x74, 0x14, 0x01,
	//			0x09, 0xE7, 0x17, 0xEE, 0x73, 0x43, 0xD3, 0x44,
	//			0xE8, 0xCA, 0xD0, 0x7F, 0xCA, 0x9F, 0x0E, 0xC4,
	//			0x55, 0x7D, 0xE5, 0x27, 0xFD, 0xDF, 0x8A, 0xBD,
	//		}
	//	},
		TestCase
		{
			.private_key
			{

				0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
				0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
				0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
				0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
			},
			.public_key
			{
				0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
				0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
				0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
				0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
			}
		},
	};

	for(const TestCase& tcase : test_cases)
	{
		point_t computed_key;
		key_t compressed_key;
		crypto::ElypticCurve_Ed25519::public_key(tcase.private_key, computed_key);
		crypto::ElypticCurve_Ed25519::key_compress(computed_key, compressed_key);

		const bool result = (memcmp(compressed_key.data(), tcase.public_key.data(), sizeof(key_t)) == 0);

		ASSERT_TRUE(result)
			<< "\n  Actual: " << testPrint{compressed_key}
			<< "\nExpected: " << testPrint{tcase.public_key}
			<< "\n       X: " << testPrint{computed_key.m_x}
			<< "\n       Y: " << testPrint{computed_key.m_y};
	}
}
TEST(codec_asymmetric, ECC_ED25519_key_agreement)
{
	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<uint64_t> distrib(0, std::numeric_limits<uint64_t>::max());

	crypto::ElypticCurve_Ed25519::key_t secret1;
	crypto::ElypticCurve_Ed25519::key_t secret2;
	{
		crypto::Curve_25519::block_t& temp = reinterpret_cast<crypto::Curve_25519::block_t&>(secret1);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
	}

	{
		crypto::Curve_25519::block_t& temp = reinterpret_cast<crypto::Curve_25519::block_t&>(secret2);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
	}

	crypto::ElypticCurve_Ed25519::point_t pub1;
	crypto::ElypticCurve_Ed25519::public_key(secret1, pub1);

	crypto::ElypticCurve_Ed25519::point_t pub2;
	crypto::ElypticCurve_Ed25519::public_key(secret2, pub2);

	crypto::ElypticCurve_Ed25519::point_t shared1;
	crypto::ElypticCurve_Ed25519::point_t shared2;

	crypto::ElypticCurve_Ed25519::composite_key(secret1, pub2, shared1);
	crypto::ElypticCurve_Ed25519::composite_key(secret2, pub1, shared2);

	const bool result = (memcmp(&shared1, &shared2, sizeof(crypto::ElypticCurve_Ed25519::point_t)) == 0);
	ASSERT_TRUE(result)
		<< "\nShare 1: " << '{' << testPrint{shared1.m_x} << "; " << testPrint{shared1.m_y} << '}'
		<< "\nShare 2: " << '{' << testPrint{shared2.m_x} << "; " << testPrint{shared2.m_y} << '}';

}

TEST(codec_asymmetric, ECC_2_compute)
{
	crypto::ElypticCurve_Ed25519::key_t secret1
	{
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x38,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x00,
	};

	crypto::ElypticCurve_Ed25519::point_t pub1;
	crypto::ElypticCurve_Ed25519::public_key(secret1, pub1);

	crypto::ElypticCurve_Ed25519::key_t compress;
	crypto::ElypticCurve_Ed25519::point_t expanded;

	crypto::ElypticCurve_Ed25519::key_compress(pub1, compress);
	{
		const bool expand_res = crypto::ElypticCurve_Ed25519::key_expand(compress, expanded);
		ASSERT_TRUE(expand_res);
	}

	const bool result = (memcmp(&pub1, &expanded, sizeof(crypto::ElypticCurve_Ed25519::point_t)) == 0);
	ASSERT_TRUE(result)
		<< "\nOrigin    : " << '{' << testPrint{pub1.m_x} << "; " << testPrint{pub1.m_y} << '}'
		<< "\nRound-trip: " << '{' << testPrint{expanded.m_x} << "; " << testPrint{expanded.m_y} << '}';

#if 0
	crypto::Curve_25519::block_t accum{2, 0, 0, 0};
	{
		crypto::Curve_25519::block_t z;

		crypto::Curve_25519::mod_square(z, accum);
		crypto::Curve_25519::mod_multiply(accum, accum, z);
		crypto::Curve_25519::mod_square(z, z);

		for(uint8_t i = 0; i < 250; ++i)
		{
			crypto::Curve_25519::mod_square(z, z);
			crypto::Curve_25519::mod_multiply(accum, accum, z);
		}
	}
	crypto::Curve_25519::block_t expect
	{
		0xc4ee1b274a0ea0b0,
		0x2f431806ad2fe478,
		0x2b4d00993dfbd7a7,
		0x2b8324804fc1df0b
	};

	EXPECT_EQ(accum, expect);
#endif
}
