//======== ======== ======== ======== ======== ======== ======== ========
///	\file
///		EEC - Elyptic Curve Cryptography
///			Public Key cryptography
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

#pragma once

#include <cstdint>
#include <array>
#include <span>

namespace crypto
{
	///	\brief 
	///		Edwards 22519
	///		a * x^2 + y^2 = 1 + d * x^2 * y^2 (mod P)
	///		a = -1
	///		d = -121665/121666
	///		P = 2^255-19
	class Ed25519
	{
	public:
		static constexpr uintptr_t key_lenght  = 32;

		using key_t   = std::array<uint8_t, key_lenght>;
		using coord_t = std::array<uint64_t, 4>;

		struct point_t
		{
			coord_t m_x;
			coord_t m_y;
		};

		static void hashed_private_key(std::span<const uint8_t, key_lenght> p_input, std::span<uint8_t, key_lenght> p_output);
		static void reduce_private_key(std::span<uint8_t, key_lenght> p_private_key);

		static void public_key   (std::span<const uint8_t, key_lenght> p_private_key, point_t& p_public_key);
		static void composite_key(std::span<const uint8_t, key_lenght> p_private_key, const point_t& p_public_key, point_t& p_shared_key);

		static void key_compress(const point_t& p_public_key, std::span<uint8_t, key_lenght> p_compressed_key);
		static bool key_expand  (const std::span<const uint8_t, key_lenght> p_compressed_key, point_t& p_public_key);

		static bool is_null(const point_t& p_public_key);
		static bool is_on_curve(const point_t& p_public_key);


		//	r = sha2(context| 0 | sk | M)
		//	if r == 0: r = sha2(context| 1 | sk | M)
		//	R = r*G
		//	k = sha2(context| R | M)
		//	if k == 0: k = 1
		//	S = (r + k*sk)
		static void sign(
			std::span<const uint8_t, key_lenght> p_private_key,
			std::span<const uint8_t, key_lenght> p_message_digest, std::span<const uint8_t> p_context,
			point_t& p_R, std::span<uint8_t, key_lenght> p_S);

		//	k = sha2(context| R | M)
		//	if k == 0: k = 1
		//	P1 = S*G
		//	P2 = R + k*Pk
		//	P1 == P2
		static bool verify(const point_t& p_public_key,
			std::span<const uint8_t, key_lenght> p_message_digest, std::span<const uint8_t> p_context,
			const point_t& p_R, std::span<const uint8_t, key_lenght> p_S);
	};


	///	\brief 
	///		Edwards 521
	///		a * x^2 + y^2 = 1 + d * x^2 * y^2 (mod P)
	///		a = 1
	///		d = -376014
	///		P = 2^521-1
	class Ed521
	{
	public:
		static constexpr uintptr_t key_lenght  = 66;

		using key_t   = std::array<uint8_t, key_lenght>;
		using coord_t = std::array<uint64_t, 9>;

		struct point_t
		{
			coord_t m_x;
			coord_t m_y;
		};

		static void reduce_private_key(std::span<uint8_t, key_lenght> p_private_key);

		static void public_key(std::span<const uint8_t, key_lenght> p_private_key, point_t& p_public_key);
		static void composite_key(std::span<const uint8_t, key_lenght> p_private_key, const point_t& p_public_key, point_t& p_shared_key);

		static void key_compress(const point_t& p_public_key, std::span<uint8_t, key_lenght> p_compressed_key);
		static bool key_expand  (const std::span<const uint8_t, key_lenght> p_compressed_key, point_t& p_public_key);

		static bool is_null(const point_t& p_public_key);
		static bool is_on_curve(const point_t& p_public_key);
	};

} //namespace crypto
