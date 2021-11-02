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

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <array>

#include <CoreLib/Core_Type.hpp>
#include <CoreLib/toPrint/toPrint.hpp>
#include <CoreLib/toPrint/toPrint_std_ostream.hpp>
#include <CoreLib/Core_Endian.hpp>


#include <Crypt/hash/crc.hpp>
#include <Crypt/utils.hpp>

#include <test_utils.hpp>


using core::literals::operator "" _ui8;
using core::literals::operator "" _ui32;
using core::literals::operator "" _ui64;

TEST(Hash, CRC_32C)
{
	using digest_t = Crypt::CRC_32C::digest_t;

	testUtils::HashList testList = testUtils::getHashList("../test_vectors/tests.scef", U"CRC_32C", sizeof(digest_t));
	ASSERT_FALSE(testList.empty());

	Crypt::CRC_32C engine;

	ASSERT_EQ(engine.digest(), 0x0_ui32);

	uintptr_t case_count = 0;
	for(const testUtils::Hashable& testcase : testList)
	{
		std::optional<std::vector<uint8_t>> tdata = testcase.source.getData();
		EXPECT_TRUE(tdata.has_value());
		if(!tdata.has_value())
		{
			continue;
		}
		const std::vector<uint8_t> test_data = std::move(tdata.value());
		const uintptr_t data_size = test_data.size();
		std::vector<uint8_t> aligned_data;
		aligned_data.resize(data_size + 8);

		const uintptr_t alignMod = Crypt::align_mod<8>(aligned_data.data());

		for(uint8_t i = 0; i < 8; ++i)
		{
			engine.reset();
			memcpy(aligned_data.data() + i, test_data.data(), data_size);

			engine.update(std::span<const uint8_t>{aligned_data.data() + i, data_size});

			const uintptr_t	alignment	= (alignMod + i) & (0x07);
			const digest_t	digest		= core::endian_host2big(engine.digest());
			const bool		result		= (memcmp(&digest, testcase.hash.data(), sizeof(digest_t)) == 0);

			ASSERT_TRUE(result)
				<< "Case " << case_count << " alignment " << alignment
				<< "\n  Actual: " << testPrint{std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(&digest), sizeof(digest_t)}}
				<< "\nExpected: " << testPrint{std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(testcase.hash.data()), sizeof(digest_t)}};
		}
		++case_count;
	}
}

TEST(Hash, CRC_64)
{
	using digest_t = Crypt::CRC_64::digest_t;

	testUtils::HashList testList = testUtils::getHashList("../test_vectors/tests.scef", U"CRC_64", sizeof(digest_t));
	ASSERT_FALSE(testList.empty());

	Crypt::CRC_64 engine;

	ASSERT_EQ(engine.digest(), 0x0_ui64);

	uintptr_t case_count = 0;
	for(const testUtils::Hashable& testcase : testList)
	{
		std::optional<std::vector<uint8_t>> tdata = testcase.source.getData();
		EXPECT_TRUE(tdata.has_value());
		if(!tdata.has_value())
		{
			continue;
		}
		const std::vector<uint8_t> test_data = std::move(tdata.value());

		const uintptr_t data_size = test_data.size();
		std::vector<uint8_t> aligned_data;
		aligned_data.resize(data_size + 8);

		const uintptr_t alignMod = Crypt::align_mod<8>(aligned_data.data());

		for(uint8_t i = 0; i < 8; ++i)
		{
			engine.reset();
			memcpy(aligned_data.data() + i, test_data.data(), data_size);

			engine.update(std::span<const uint8_t>{aligned_data.data() + i, data_size});

			const uintptr_t	alignment	= (alignMod + i) & (0x07);
			const digest_t	digest		= core::endian_host2big(engine.digest());
			const bool		result		= (memcmp(&digest, testcase.hash.data(), sizeof(digest_t)) == 0);

			ASSERT_TRUE(result)
				<< "Case " << case_count << " alignment " << alignment
				<< "\n  Actual: " << testPrint{std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(&digest), sizeof(digest_t)}}
				<< "\nExpected: " << testPrint{std::span<const uint8_t>{reinterpret_cast<const uint8_t*>(testcase.hash.data()), sizeof(digest_t)}};
		}
		++case_count;
	}
}

