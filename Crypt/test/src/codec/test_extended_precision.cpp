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

#include <cstdint>
#include <array>

#include <CoreLib/toPrint/toPrint.hpp>
#include <CoreLib/toPrint/toPrint_std_ostream.hpp>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "../../src/codec/extended_precision.hpp"

TEST(extended_precision, umul)
{
	struct TestCase
	{
		uint64_t var1;
		uint64_t var2;
		uint64_t res_low;
		uint64_t res_high;
	};

	const std::array cases{
		TestCase{.var1 = 0, .var2 = 0, .res_low = 0, .res_high = 0},
		TestCase{.var1 = 0xFFFF, .var2 = 0xFFFF, .res_low = 0xFFFE0001, .res_high = 0},
		TestCase{.var1 = 0xFFFFFFFF, .var2 = 0xFFFFFFFF, .res_low = 0xFFFFFFFE00000001, .res_high = 0},
		TestCase{.var1 = 0xFFFFFFFFFFFFFFFF, .var2 = 0xFFFFFFFFFFFFFFFF, .res_low = 0x01, .res_high = 0xFFFFFFFFFFFFFFFE},
		TestCase{.var1 = 0xC9562D608F25D51A, .var2 = 0x6666666666666658, .res_low = 0x798D72918C459CF0, .res_high = 0x5088DEf36C758865},
	};

	for(const TestCase& tcase : cases)
	{
		uint64_t res_high = 0;
		const uint64_t res_low = crypto::umul(tcase.var1, tcase.var2, res_high);

		ASSERT_EQ(res_low, tcase.res_low) << "\nCase: 0x" << core::toPrint_hex(tcase.var1) << " * 0x" << core::toPrint_hex(tcase.var2);
		ASSERT_EQ(res_high, tcase.res_high) << "\nCase: 0x" << core::toPrint_hex(tcase.var1) << " * 0x" << core::toPrint_hex(tcase.var2);
	}

}

TEST(extended_precision, udiv)
{
	struct TestCase
	{
		uint64_t num_low;
		uint64_t num_high;
		uint64_t div;
		uint64_t res;
		uint64_t rem;
	};

	const std::array cases{
		TestCase{.num_low = 0, .num_high=0, .div = 1, .res = 0, .rem = 0},
		TestCase{.num_low = 3, .num_high=0, .div = 2, .res = 1, .rem = 1},
		TestCase{.num_low = 0x123456, .num_high=0x123, .div = 0x345, .res = 0x5900EAE56403B126, .rem = 0x318},
		TestCase{.num_low = 0x01, .num_high=0xFFFFFFFFFFFFFFFE, .div = 0xFFFFFFFFFFFFFFFF, .res = 0xFFFFFFFFFFFFFFFF, .rem = 0x0},
		TestCase{.num_low = 0xFFFFFFFFFFFFFFFF, .num_high=0xFFFFFFFFFFFFFFFE, .div = 0xFFFFFFFFFFFFFFFF, .res = 0xFFFFFFFFFFFFFFFF, .rem = 0xFFFFFFFFFFFFFFFE},
	};

	for(const TestCase& tcase : cases)
	{
		uint64_t rem = 0;
		const uint64_t res = crypto::udiv(tcase.num_high, tcase.num_low, tcase.div, rem);

		ASSERT_EQ(res, tcase.res) << "\nCase: 0x" << core::toPrint_hex(tcase.num_high)  << ' ' << core::toPrint_hex(tcase.num_low) << " / 0x" << core::toPrint_hex(tcase.div);
		ASSERT_EQ(rem, tcase.rem) << "\nCase: 0x" << core::toPrint_hex(tcase.num_high)  << ' ' << core::toPrint_hex(tcase.num_low) << " / 0x" << core::toPrint_hex(tcase.div);
	}

}
