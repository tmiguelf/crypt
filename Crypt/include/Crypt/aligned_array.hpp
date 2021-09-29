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
///
///	\todo	Provide a comprehensive and consistent set of error codes, to give
///			extra information regarding he nature of the failure
//======== ======== ======== ======== ======== ======== ======== ========

#pragma once
#include <cstdint>
#include <array>
#include <bit>

#include <initializer_list>


namespace crypt
{

template<typename T, uintptr_t Size, uintptr_t Alignment>
requires (
	std::popcount(Alignment) == 1 &&
	std::popcount(Size) == 1 &&
	alignof(T) <= Alignment &&
	alignof(T) * sizeof(T) >= Alignment
	)
struct alignas(Alignment) aligned_array
{
	std::array<T, Size> array;
};


}
