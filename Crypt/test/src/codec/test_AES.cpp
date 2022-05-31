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

#include <CoreLib/Core_Type.hpp>
#include <CoreLib/toPrint/toPrint.hpp>
#include <CoreLib/toPrint/toPrint_std_ostream.hpp>
#include <CoreLib/Core_Endian.hpp>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <Crypt/codec/AES.hpp>

#include <test_utils.hpp>

TEST(codec_symmetric, AES_128)
{
	constexpr uintptr_t block_lenght	= crypto::AES_128::block_lenght;
	constexpr uintptr_t key_lenght		= crypto::AES_128::key_lenght;

	testUtils::EncodeList testList = testUtils::getSymmetricEncodeList("../test_vectors/tests.scef", U"AES_128", key_lenght);
	ASSERT_FALSE(testList.empty());

	for(const testUtils::SymmetricEncodable& testcase : testList)
	{

		std::optional<std::vector<uint8_t>> tdata = testcase.source.getData();
		EXPECT_TRUE(tdata.has_value());
		if(!tdata.has_value())
		{
			continue;
		}

		const std::vector<uint8_t> testData = std::move(tdata.value());

		EXPECT_EQ(testData.size(), block_lenght);

		if(testData.size() != block_lenght)
		{
			continue;
		}

		for(const testUtils::SymmetricEncodable::result_t& tkeyCase : testcase.encoded)
		{
			EXPECT_EQ(tkeyCase.key.size(), key_lenght);
			if(tkeyCase.key.size() != key_lenght)
			{
				continue;
			}

			std::optional<std::vector<uint8_t>> texpected = tkeyCase.source.getData();

			EXPECT_TRUE(texpected.has_value());
			if(!texpected.has_value())
			{
				continue;
			}

			EXPECT_EQ(texpected.value().size(), block_lenght);
			if(texpected.value().size() != block_lenght)
			{
				continue;
			}

			std::array<uint8_t, block_lenght> expected;
			memcpy(expected.data(), texpected.value().data(), block_lenght);


			crypto::AES_128::key_schedule_t tkey_schedule;
			crypto::AES_128::make_key_schedule(std::span<const uint8_t, key_lenght>{tkeyCase.key.data(), key_lenght}, tkey_schedule);

			std::array<uint8_t, block_lenght> encoded;
			crypto::AES_128::encode(
				tkey_schedule,
				std::span<const uint8_t, block_lenght>{testData.data(), block_lenght},
				encoded);

			{
				const bool result = (memcmp(encoded.data(), expected.data(), block_lenght) == 0);

				ASSERT_TRUE(result)
					<< "\n  Actual: " << testPrint{encoded}
					<< "\nExpected: " << testPrint{expected};
			}

			std::array<uint8_t, block_lenght> decoded;

			crypto::AES_128::decode(tkey_schedule, encoded, decoded);
			{
				const bool result2 = (memcmp(decoded.data(), testData.data(), sizeof(decoded)) == 0);

				ASSERT_TRUE(result2)
					<< "\n  Actual: " << testPrint{decoded}
					<< "\nExpected: " << testPrint{testData};
			}
		}
	}
}

TEST(codec_symmetric, AES_192)
{
	constexpr uintptr_t block_lenght	= crypto::AES_192::block_lenght;
	constexpr uintptr_t key_lenght		= crypto::AES_192::key_lenght;

	testUtils::EncodeList testList = testUtils::getSymmetricEncodeList("../test_vectors/tests.scef", U"AES_192", key_lenght);
	ASSERT_FALSE(testList.empty());

	for(const testUtils::SymmetricEncodable& testcase : testList)
	{

		std::optional<std::vector<uint8_t>> tdata = testcase.source.getData();
		EXPECT_TRUE(tdata.has_value());
		if(!tdata.has_value())
		{
			continue;
		}

		const std::vector<uint8_t> testData = std::move(tdata.value());

		EXPECT_EQ(testData.size(), block_lenght);

		if(testData.size() != block_lenght)
		{
			continue;
		}

		for(const testUtils::SymmetricEncodable::result_t& tkeyCase : testcase.encoded)
		{
			EXPECT_EQ(tkeyCase.key.size(), key_lenght);
			if(tkeyCase.key.size() != key_lenght)
			{
				continue;
			}

			std::optional<std::vector<uint8_t>> texpected = tkeyCase.source.getData();

			EXPECT_TRUE(texpected.has_value());
			if(!texpected.has_value())
			{
				continue;
			}

			EXPECT_EQ(texpected.value().size(), block_lenght);
			if(texpected.value().size() != block_lenght)
			{
				continue;
			}

			std::array<uint8_t, block_lenght> expected;
			memcpy(expected.data(), texpected.value().data(), block_lenght);


			crypto::AES_192::key_schedule_t tkey_schedule;
			crypto::AES_192::make_key_schedule(std::span<const uint8_t, key_lenght>{tkeyCase.key.data(), key_lenght}, tkey_schedule);

			std::array<uint8_t, block_lenght> encoded;
			crypto::AES_192::encode(
				tkey_schedule,
				std::span<const uint8_t, block_lenght>{testData.data(), block_lenght},
				encoded);

			{
				const bool result = (memcmp(encoded.data(), expected.data(), block_lenght) == 0);

				ASSERT_TRUE(result)
					<< "\n  Actual: " << testPrint{encoded}
					<< "\nExpected: " << testPrint{expected};
			}

			std::array<uint8_t, block_lenght> decoded;

			crypto::AES_192::decode(tkey_schedule, encoded, decoded);
			{
				const bool result2 = (memcmp(decoded.data(), testData.data(), sizeof(decoded)) == 0);

				ASSERT_TRUE(result2)
					<< "\n  Actual: " << testPrint{decoded}
					<< "\nExpected: " << testPrint{testData};
			}
		}
	}
}

TEST(codec_symmetric, AES_256)
{
	constexpr uintptr_t block_lenght	= crypto::AES_256::block_lenght;
	constexpr uintptr_t key_lenght		= crypto::AES_256::key_lenght;

	testUtils::EncodeList testList = testUtils::getSymmetricEncodeList("../test_vectors/tests.scef", U"AES_256", key_lenght);
	ASSERT_FALSE(testList.empty());

	for(const testUtils::SymmetricEncodable& testcase : testList)
	{

		std::optional<std::vector<uint8_t>> tdata = testcase.source.getData();
		EXPECT_TRUE(tdata.has_value());
		if(!tdata.has_value())
		{
			continue;
		}

		const std::vector<uint8_t> testData = std::move(tdata.value());

		EXPECT_EQ(testData.size(), block_lenght);

		if(testData.size() != block_lenght)
		{
			continue;
		}

		for(const testUtils::SymmetricEncodable::result_t& tkeyCase : testcase.encoded)
		{
			EXPECT_EQ(tkeyCase.key.size(), key_lenght);
			if(tkeyCase.key.size() != key_lenght)
			{
				continue;
			}

			std::optional<std::vector<uint8_t>> texpected = tkeyCase.source.getData();

			EXPECT_TRUE(texpected.has_value());
			if(!texpected.has_value())
			{
				continue;
			}

			EXPECT_EQ(texpected.value().size(), block_lenght);
			if(texpected.value().size() != block_lenght)
			{
				continue;
			}

			std::array<uint8_t, block_lenght> expected;
			memcpy(expected.data(), texpected.value().data(), block_lenght);


			crypto::AES_256::key_schedule_t tkey_schedule;
			crypto::AES_256::make_key_schedule(std::span<const uint8_t, key_lenght>{tkeyCase.key.data(), key_lenght}, tkey_schedule);

			std::array<uint8_t, block_lenght> encoded;
			crypto::AES_256::encode(
				tkey_schedule,
				std::span<const uint8_t, block_lenght>{testData.data(), block_lenght},
				encoded);

			{
				const bool result = (memcmp(encoded.data(), expected.data(), block_lenght) == 0);

				ASSERT_TRUE(result)
					<< "\n  Actual: " << testPrint{encoded}
					<< "\nExpected: " << testPrint{expected};
			}

			std::array<uint8_t, block_lenght> decoded;

			crypto::AES_256::decode(tkey_schedule, encoded, decoded);
			{
				const bool result2 = (memcmp(decoded.data(), testData.data(), sizeof(decoded)) == 0);

				ASSERT_TRUE(result2)
					<< "\n  Actual: " << testPrint{decoded}
				<< "\nExpected: " << testPrint{testData};
			}
		}
	}
}