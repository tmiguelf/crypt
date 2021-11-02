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

#include <Crypt/hash/sha2.hpp>


#include <test_utils.hpp>


using core::literals::operator "" _ui8;
using core::literals::operator "" _ui32;
using core::literals::operator "" _ui64;


TEST(Hash, SHA2_256)
{
	using digest_t = Crypt::SHA2_256::digest_t;

	testUtils::HashList testList = testUtils::getHashList("../test_vectors/tests.scef", U"SHA2_256", sizeof(digest_t));
	ASSERT_FALSE(testList.empty());

	Crypt::SHA2_256 engine;

	uintptr_t case_count = 0;
	for(const testUtils::Hashable& testcase : testList)
	{
		engine.reset();
		std::optional<std::vector<uint8_t>> test_data = testcase.source.getData();

		EXPECT_TRUE(test_data.has_value());

		if(!test_data.has_value())
		{
			continue;
		}

		engine.update(test_data.value());
		engine.finalize();

		const digest_t digest = engine.digest();
		digest_t order_digets;
		order_digets[0] = core::endian_host2big(digest[0]);
		order_digets[1] = core::endian_host2big(digest[1]);
		order_digets[2] = core::endian_host2big(digest[2]);
		order_digets[3] = core::endian_host2big(digest[3]);
		order_digets[4] = core::endian_host2big(digest[4]);
		order_digets[5] = core::endian_host2big(digest[5]);
		order_digets[6] = core::endian_host2big(digest[6]);
		order_digets[7] = core::endian_host2big(digest[7]);

		const bool result = (memcmp(&order_digets, testcase.hash.data(), sizeof(digest_t)) == 0);

		ASSERT_TRUE(result)
			<< "Case " << case_count
			<< "\n  Actual: " << testPrint{std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(&digest), sizeof(digest_t)}}
			<< "\nExpected: " << testPrint{std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(testcase.hash.data()), sizeof(digest_t)}};

		++case_count;
	}

}

TEST(Hash, SHA2_512)
{
	using digest_t = Crypt::SHA2_512::digest_t;

	testUtils::HashList testList = testUtils::getHashList("../test_vectors/tests.scef", U"SHA2_512", sizeof(digest_t));
	ASSERT_FALSE(testList.empty());

	Crypt::SHA2_512 engine;

	uintptr_t case_count = 0;
	for(const testUtils::Hashable& testcase : testList)
	{
		engine.reset();
		std::optional<std::vector<uint8_t>> test_data = testcase.source.getData();

		EXPECT_TRUE(test_data.has_value());

		if(!test_data.has_value())
		{
			continue;
		}

		engine.update(test_data.value());
		engine.finalize();

		const digest_t digest = engine.digest();
		digest_t order_digets;
		order_digets[0] = core::endian_host2big(digest[0]);
		order_digets[1] = core::endian_host2big(digest[1]);
		order_digets[2] = core::endian_host2big(digest[2]);
		order_digets[3] = core::endian_host2big(digest[3]);
		order_digets[4] = core::endian_host2big(digest[4]);
		order_digets[5] = core::endian_host2big(digest[5]);
		order_digets[6] = core::endian_host2big(digest[6]);
		order_digets[7] = core::endian_host2big(digest[7]);

		const bool result = (memcmp(&order_digets, testcase.hash.data(), sizeof(digest_t)) == 0);

		ASSERT_TRUE(result)
			<< "Case " << case_count
			<< "\n  Actual: " << testPrint{std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(&digest), sizeof(digest_t)}}
		<< "\nExpected: " << testPrint{std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(testcase.hash.data()), sizeof(digest_t)}};

		++case_count;
	}

}
