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

#include <Crypt/hash/crc.hpp>

using core::literals::operator "" _ui8;
using core::literals::operator "" _ui32;

TEST(Hash, CRC_32C)
{
	crypt::CRC_32C engine;

	std::array data =
	{
		0x00_ui8,
		0x01_ui8,
		0x02_ui8,
		0x03_ui8,
		0x04_ui8,
		0x05_ui8,
		0x06_ui8,
		0x07_ui8,
		0x08_ui8,
		0x09_ui8,
		0x0A_ui8,
		0x0B_ui8,
		0x0C_ui8,
		0x0D_ui8,
		0x0E_ui8,
		0x0F_ui8,
		0x10_ui8,
		0x11_ui8,
		0x12_ui8,
		0x13_ui8,
		0x14_ui8,
		0x15_ui8,
		0x16_ui8,
		0x17_ui8,
		0x18_ui8,
		0x19_ui8,
		0x1A_ui8,
		0x1B_ui8,
		0x1C_ui8,
		0x1D_ui8,
		0x1E_ui8,
		0x1F_ui8,
	};

	//engine.update(data);

	engine.update(
		std::span<const uint64_t>{reinterpret_cast<const uint64_t*>(data.data()),
		data.size() / 8});

	EXPECT_EQ(engine.digest(), 0xB92286B1_ui32);
}

