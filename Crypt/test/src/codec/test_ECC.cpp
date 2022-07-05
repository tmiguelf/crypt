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
#include <Crypt/hash/sha2.hpp>

#include <test_utils.hpp>

TEST(codec_asymmetric, ED25519_gen_public)
{
	using key_t   = crypto::Ed25519::key_t;
	using point_t = crypto::Ed25519::point_t;

	constexpr uintptr_t key_size = sizeof(key_t);

	struct TestCase
	{
		key_t private_key;
		key_t public_key;
	};

	testUtils::PairList cases = testUtils::getPrivatePublicKeyList("../test_vectors/tests.scef", U"Ed25519_hashed", key_size, key_size);

	for(const testUtils::DataPair& tcase : cases)
	{
		key_t private_key;
		key_t expected_public_key;

		memcpy(private_key.data(), tcase.d0.data(), key_size);
		memcpy(expected_public_key.data(), tcase.d1.data(), key_size);

		point_t computed_key;
		key_t compressed_key;
	
		{
			key_t hashed_private_key;
			crypto::Ed25519::hashed_private_key(private_key, hashed_private_key);
			crypto::Ed25519::public_key(hashed_private_key, computed_key);
		}

		crypto::Ed25519::key_compress(computed_key, compressed_key);
	
		const bool result = (memcmp(compressed_key.data(), expected_public_key.data(), key_size) == 0);
	
		ASSERT_TRUE(result)
			<< "\nCase    : " << testPrint{private_key}
			<< "\nExpected: " << testPrint{expected_public_key}
			<< "\nActual  : " << testPrint{compressed_key}
			<< "\nX       : " << testPrint{computed_key.m_x}
			<< "\nY       : " << testPrint{computed_key.m_y};
	}

}

TEST(codec_asymmetric, ED25519_key_agreement)
{
	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<uint64_t> distrib(0, std::numeric_limits<uint64_t>::max());

	alignas(8) crypto::Ed25519::key_t secret1;
	alignas(8) crypto::Ed25519::key_t secret2;

	using alias_t = std::array<uint64_t, 4>;
	{
		alias_t& temp = reinterpret_cast<alias_t&>(secret1);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
	}

	{
		alias_t& temp = reinterpret_cast<alias_t&>(secret2);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
	}

	crypto::Ed25519::point_t pub1;
	crypto::Ed25519::public_key(secret1, pub1);

	crypto::Ed25519::point_t pub2;
	crypto::Ed25519::public_key(secret2, pub2);

	crypto::Ed25519::point_t shared1;
	crypto::Ed25519::point_t shared2;

	crypto::Ed25519::composite_key(secret1, pub2, shared1);
	crypto::Ed25519::composite_key(secret2, pub1, shared2);

	const bool result = (memcmp(&shared1, &shared2, sizeof(crypto::Ed25519::point_t)) == 0);
	ASSERT_TRUE(result)
		<< "\nShared 1: " << '{' << testPrint{shared1.m_x} << "; " << testPrint{shared1.m_y} << '}'
		<< "\nShared 2: " << '{' << testPrint{shared2.m_x} << "; " << testPrint{shared2.m_y} << '}'
		<< "\nSecret 1: " << testPrint{secret1}
		<< "\nSecret 2: " << testPrint{secret2};
}

TEST(codec_asymmetric, ED25519_compress_roundtrip)
{
	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<uint64_t> distrib(0, std::numeric_limits<uint64_t>::max());

	alignas(8) crypto::Ed25519::key_t secret1;

	using alias_t = std::array<uint64_t, 4>;
	{
		alias_t& temp = reinterpret_cast<alias_t&>(secret1);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
	}

	crypto::Ed25519::point_t pub1;
	crypto::Ed25519::public_key(secret1, pub1);

	crypto::Ed25519::key_t compress;
	crypto::Ed25519::point_t expanded;

	crypto::Ed25519::key_compress(pub1, compress);
	{
		const bool expand_res = crypto::Ed25519::key_expand(compress, expanded);
		ASSERT_TRUE(expand_res)
			<< "\nOrigin    : " << '{' << testPrint{pub1.m_x} << "; " << testPrint{pub1.m_y} << '}'
			<< "\nSecret    : " << testPrint{secret1};
	}

	const bool result = (memcmp(&pub1, &expanded, sizeof(crypto::Ed25519::point_t)) == 0);
	ASSERT_TRUE(result)
		<< "\nOrigin    : " << '{' << testPrint{pub1.m_x} << "; " << testPrint{pub1.m_y} << '}'
		<< "\nRound-trip: " << '{' << testPrint{expanded.m_x} << "; " << testPrint{expanded.m_y} << '}'
		<< "\nSecret    : " << testPrint{secret1};
}

TEST(codec_asymmetric, ED25519_point_on_curve)
{
	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<uint64_t> distrib(0, std::numeric_limits<uint64_t>::max());

	alignas(8) crypto::Ed25519::key_t secret;

	using alias_t = std::array<uint64_t, 4>;
	{
		alias_t& temp = reinterpret_cast<alias_t&>(secret);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
	}

	crypto::Ed25519::point_t pub;
	crypto::Ed25519::public_key(secret, pub);

	ASSERT_TRUE(crypto::Ed25519::is_on_curve(pub)) << "\nSecret    : " << testPrint{secret};

	pub.m_x[1] ^= 0xFFFFFFFFFFFFFFFF;

	ASSERT_FALSE(crypto::Ed25519::is_on_curve(pub)) << "\nSecret    : " << testPrint{secret};
}


TEST(codec_asymmetric, ED25519_signature)
{
	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<uint64_t> distrib(0, std::numeric_limits<uint64_t>::max());

	alignas(8) crypto::Ed25519::key_t secret;
	alignas(8) crypto::Ed25519::key_t fake;
	std::array<uint64_t, 4> rand_hash;

	std::array<uint8_t, 256> rand_context;
	const uint8_t context_length = static_cast<uint8_t>(distrib(gen));

	for(uint8_t i = context_length; i--; )
	{
		rand_context[i] = static_cast<uint8_t>(distrib(gen));
	}

	const std::span<const uint8_t> context{rand_context.data(), context_length};

	using alias_t = std::array<uint64_t, 4>;
	{
		alias_t& temp = reinterpret_cast<alias_t&>(secret);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
	}

	{
		alias_t& temp = reinterpret_cast<alias_t&>(fake);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
	}

	crypto::Ed25519::reduce_private_key(secret);
	crypto::Ed25519::reduce_private_key(fake);

	if(memcmp(&secret, &fake, sizeof(secret)) == 0)
	{
		fake[0] ^= 1;
	}

	{
		rand_hash[0] = distrib(gen);
		rand_hash[1] = distrib(gen);
		rand_hash[2] = distrib(gen);
		rand_hash[3] = distrib(gen);
	}

	const std::span<const uint8_t, 32> message_digest{reinterpret_cast<uint8_t*>(rand_hash.data()), 32};

	using point_t = crypto::Ed25519::point_t;
	using key_t = crypto::Ed25519::key_t;

	point_t public_key;

	crypto::Ed25519::public_key(secret, public_key);

	point_t real_r;
	key_t real_s;

	point_t fake_r;
	key_t fake_s;

	crypto::Ed25519::sign(secret, message_digest, context, real_r, real_s);
	crypto::Ed25519::sign(fake, message_digest, context, fake_r, fake_s);

	const bool res1 = crypto::Ed25519::verify(public_key, message_digest, context, real_r, real_s);
	ASSERT_TRUE(res1);

	const bool res2 = crypto::Ed25519::verify(public_key, message_digest, context, fake_r, fake_s);
	ASSERT_FALSE(res2);

}




TEST(codec_asymmetric, ED521_key_agreement)
{
	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<uint64_t> distrib(0, std::numeric_limits<uint64_t>::max());

	alignas(8) crypto::Ed521::key_t secret1;
	alignas(8) crypto::Ed521::key_t secret2;

	using alias_t = std::array<uint64_t, 8>;
	{
		alias_t& temp = reinterpret_cast<alias_t&>(secret1);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
		temp[4] = distrib(gen);
		temp[5] = distrib(gen);
		temp[6] = distrib(gen);
		temp[7] = distrib(gen);
		reinterpret_cast<uint16_t&>(secret1[64]) = static_cast<uint16_t>(distrib(gen));
	}

	{
		alias_t& temp = reinterpret_cast<alias_t&>(secret2);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
		temp[4] = distrib(gen);
		temp[5] = distrib(gen);
		temp[6] = distrib(gen);
		temp[7] = distrib(gen);
		reinterpret_cast<uint16_t&>(secret2[64]) = static_cast<uint16_t>(distrib(gen));
	}

	crypto::Ed521::point_t pub1;
	crypto::Ed521::public_key(secret1, pub1);

	crypto::Ed521::point_t pub2;
	crypto::Ed521::public_key(secret2, pub2);

	crypto::Ed521::point_t shared1;
	crypto::Ed521::point_t shared2;

	crypto::Ed521::composite_key(secret1, pub2, shared1);
	crypto::Ed521::composite_key(secret2, pub1, shared2);

	const bool result = (memcmp(&shared1, &shared2, sizeof(crypto::Ed521::point_t)) == 0);
	ASSERT_TRUE(result)
		<< "\nShared 1: " << '{' << testPrint{shared1.m_x} << "; " << testPrint{shared1.m_y} << '}'
		<< "\nShared 2: " << '{' << testPrint{shared2.m_x} << "; " << testPrint{shared2.m_y} << '}'
		<< "\nSecret 1: " << testPrint{secret1}
		<< "\nSecret 2: " << testPrint{secret2};
}

TEST(codec_asymmetric, ED521_compress_roundtrip)
{
	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<uint64_t> distrib(0, std::numeric_limits<uint64_t>::max());

	alignas(8) crypto::Ed521::key_t secret1;

	using alias_t = std::array<uint64_t, 8>;
	{
		alias_t& temp = reinterpret_cast<alias_t&>(secret1);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
		temp[4] = distrib(gen);
		temp[5] = distrib(gen);
		temp[6] = distrib(gen);
		temp[7] = distrib(gen);
		reinterpret_cast<uint16_t&>(secret1[64]) = static_cast<uint16_t>(distrib(gen));
	}

	crypto::Ed521::point_t pub1;
	crypto::Ed521::public_key(secret1, pub1);

	crypto::Ed521::key_t compress;
	crypto::Ed521::point_t expanded;

	crypto::Ed521::key_compress(pub1, compress);
	{
		const bool expand_res = crypto::Ed521::key_expand(compress, expanded);
		ASSERT_TRUE(expand_res)
			<< "\nOrigin    : " << '{' << testPrint{pub1.m_x} << "; " << testPrint{pub1.m_y} << '}'
			<< "\nSecret    : " << testPrint{secret1};
	}

	const bool result = (memcmp(&pub1, &expanded, sizeof(crypto::Ed521::point_t)) == 0);
	ASSERT_TRUE(result)
		<< "\nOrigin    : " << '{' << testPrint{pub1.m_x} << "; " << testPrint{pub1.m_y} << '}'
		<< "\nRound-trip: " << '{' << testPrint{expanded.m_x} << "; " << testPrint{expanded.m_y} << '}'
		<< "\nSecret    : " << testPrint{secret1};
}


TEST(codec_asymmetric, Ed521_point_on_curve)
{
	std::random_device rd;  //Will be used to obtain a seed for the random number engine
	std::mt19937 gen(rd()); //Standard mersenne_twister_engine seeded with rd()
	std::uniform_int_distribution<uint64_t> distrib(0, std::numeric_limits<uint64_t>::max());

	alignas(8) crypto::Ed521::key_t secret;

	using alias_t = std::array<uint64_t, 8>;
	{
		alias_t& temp = reinterpret_cast<alias_t&>(secret);
		temp[0] = distrib(gen);
		temp[1] = distrib(gen);
		temp[2] = distrib(gen);
		temp[3] = distrib(gen);
		temp[4] = distrib(gen);
		temp[5] = distrib(gen);
		temp[6] = distrib(gen);
		temp[7] = distrib(gen);
		reinterpret_cast<uint16_t&>(secret[64]) = static_cast<uint16_t>(distrib(gen));
	}

	crypto::Ed521::point_t pub;
	crypto::Ed521::public_key(secret, pub);

	ASSERT_TRUE(crypto::Ed521::is_on_curve(pub)) << "\nSecret    : " << testPrint{secret};

	pub.m_x[1] ^= 0xFFFFFFFFFFFFFFFF;

	ASSERT_FALSE(crypto::Ed521::is_on_curve(pub)) << "\nSecret    : " << testPrint{secret};
}
