//======== ======== ======== ======== ======== ======== ======== ========
///	\file
///
///	\copyright
///		Copyright (c) Tiago Miguel Oliveira Freire
///
///		Permission is hereby granted, free of charge, to any person obtaining a copy
///		of this software and associated documentation files (the "Software"),
///		to copy, modify, publish, and/or distribute copies of the Software,
///		and to permit persons to whom the Software is furnished to do so,
///		subject to the following conditions:
///
///		The copyright notice and this permission notice shall be included in all
///		copies or substantial portions of the Software.
///		The copyrighted work, or derived works, shall not be used to train
///		Artificial Intelligence models of any sort; or otherwise be used in a
///		transformative way that could obfuscate the source of the copyright.
///
///		THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
///		IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
///		FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
///		AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
///		LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
///		OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
///		SOFTWARE.
//======== ======== ======== ======== ======== ======== ======== ========

#pragma once

#include <cstdint>

#if defined(_M_AMD64) || defined(__amd64__)
#	ifdef _WIN32
#		include <intrin.h>
#	endif
#	include <immintrin.h>
#else
#	error "Unsuported Architecture"
#endif

namespace crypto
{

#ifdef _WIN32
	static inline uint64_t umul(const uint64_t p_1, const uint64_t p_2, uint64_t& p_out_hi)
	{
		return _umul128(p_1, p_2, &p_out_hi);
	}

	static inline uint64_t udiv(const uint64_t p_hi, const uint64_t p_low, const uint64_t p_denom, uint64_t& p_rem)
	{
		return _udiv128(p_hi, p_low, p_denom, &p_rem);
	}

	static inline uint8_t addcarry(const uint8_t p_carry, const uint64_t p_1, const uint64_t p_2, uint64_t& p_out)
	{
		return _addcarry_u64(p_carry, p_1, p_2, &p_out);
	}

	static inline uint8_t subborrow(const uint8_t p_borrow, const uint64_t p_1, const uint64_t p_2, uint64_t& p_out)
	{
		return _subborrow_u64(p_borrow, p_1, p_2, &p_out);
	}

#else
	static inline uint64_t umul(uint64_t p_1, const uint64_t p_2, uint64_t& p_out_hi)
	{
		__asm__
		(
			"mul %2;"
			: "+a"(p_1), "=d"(p_out_hi)
			: "Q"(p_2)
		);
		return p_1;
	}

	static inline uint64_t udiv(uint64_t p_hi, uint64_t p_low, const uint64_t p_denom, uint64_t& p_rem)
	{
		__asm__
		(
			"div %3;"
			: "+a"(p_low), "=d"(p_rem)
			: "d"(p_hi), "Q"(p_denom)
		);
		return p_low;
	}

	static inline uint8_t addcarry(const uint8_t p_carry, const uint64_t p_1, const uint64_t p_2, uint64_t& p_out)
	{
		return _addcarry_u64(p_carry, p_1, p_2, reinterpret_cast<unsigned long long*>(&p_out));
	}

	static inline uint8_t subborrow(const uint8_t p_borrow, const uint64_t p_1, const uint64_t p_2, uint64_t& p_out)
	{
		return _subborrow_u64(p_borrow, p_1, p_2, reinterpret_cast<unsigned long long*>(&p_out));
	}
#endif

} //namespace crypto
