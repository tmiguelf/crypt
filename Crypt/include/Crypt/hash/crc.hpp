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
#include <span>

namespace crypt
{

class CRC_32C
{
public:
	using digest_t = uint32_t;
	static constexpr digest_t poly = 0x1EDC6F41;
	static constexpr bool reciprocal = true;

public:
	static inline constexpr digest_t default_init() { return 0xFFFFFFFF; };
	static digest_t trasform(digest_t p_current, std::span<const uint8_t> p_data);
	static digest_t trasform(digest_t p_current, std::span<const uint64_t> p_data);

public:
	inline void reset() { m_context = default_init(); }
	inline void set(digest_t p_digest) { m_context = p_digest; }

	inline constexpr digest_t digest() const { return m_context ^ 0xFFFFFFFF; }

	inline void update(std::span<const uint8_t > p_data) { m_context = trasform(m_context, p_data); }
	inline void update(std::span<const uint64_t> p_data) { m_context = trasform(m_context, p_data); }

private:
	digest_t m_context = default_init();
};


class CRC_64
{
public:
	using digest_t = uint64_t;
	static constexpr digest_t poly = 0x42F0E1EBA9EA3693;
	static constexpr bool reciprocal = false;

public:
	static inline constexpr digest_t default_init() { return 0x0000000000000000; };
	static digest_t trasform(digest_t p_current, std::span<const uint8_t> p_data);
	static digest_t trasform(digest_t p_current, std::span<const uint64_t> p_data);

public:
	inline void reset() { m_context = default_init(); }
	inline void set(digest_t p_digest) { m_context = p_digest; }

	inline constexpr digest_t digest() const { return m_context; }

	inline void update(std::span<const uint8_t > p_data) { m_context = trasform(m_context, p_data); }
	inline void update(std::span<const uint64_t> p_data) { m_context = trasform(m_context, p_data); }

private:
	digest_t m_context = default_init();
};

} //namespace crypt
