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

#pragma once

#include <cstdint>
#include <array>
#include <span>

namespace crypt
{

class SHA2_256
{
public:
	using block_t  = std::array<uint32_t, 16>;

	using digest_t = std::array<uint32_t, 8>;

public:
	static inline constexpr digest_t default_init()
	{ 
		return
		{
			0x6A09E667,
			0xBB67AE85,
			0x3C6EF372,
			0xA54FF53A,
			0x510E527F,
			0x9B05688C,
			0x1F83D9AB,
			0x5BE0CD19
		};
	};

	static void trasform(digest_t& p_digest, std::span<const block_t> p_data);
	static void trasform_final(digest_t& p_digest, std::span<const uint8_t> p_data, uint64_t p_totalSize);
public:

	inline void reset() { m_context = default_init(); }
	inline void set(digest_t p_digest) { m_context = p_digest; }

	void update(std::span<const block_t> p_data);
	void update_final(std::span<const uint8_t> p_data, uint64_t p_totalSize);

private:
	alignas(8) digest_t m_context = default_init();
};

class SHA2_512
{
public:
	using digest_t = std::array<uint64_t, 8>;

private:
	alignas(8) digest_t m_data;
};

} //namespace crypt