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

#pragma once

#include <cstdint>
#include <vector>
#include <filesystem>
#include <string_view>
#include <optional>

#include <CoreLib/core_type.hpp>
#include <CoreLib/toPrint/toPrint.hpp>
#include <CoreLib/toPrint/toPrint_std_ostream.hpp>

class testPrint: public core::toPrint_base
{
public:
	testPrint(const std::span<const uint8_t> p_data)
		: m_data(p_data)
	{
	}

	testPrint(const std::span<const uint64_t> p_data)
		: m_data(reinterpret_cast<const uint8_t*>(p_data.data()), p_data.size() * 8)
	{
	}

	template<core::_p::c_toPrint_char CharT>
	inline constexpr uintptr_t size(const CharT&) const
	{
		return (m_data.size() * 3) - 1;
	}

	template<core::_p::c_toPrint_char CharT>
	inline void get_print(CharT* p_out) const
	{
		uintptr_t tsize = m_data.size();
		if(tsize == 0) return;
		core::_p::to_chars_hex_fix_unsafe(m_data[0], p_out);
		p_out += 2;
		for(uintptr_t i = 1; i < tsize; ++i)
		{
			*(p_out++) = ' ';
			core::_p::to_chars_hex_fix_unsafe(m_data[i], p_out);
			p_out += 2;
		}
	}

private:
	const std::span<const uint8_t> m_data;
};


namespace testUtils
{
	struct data_source_t
	{
	public:
		void reset();
		void set(const std::vector<uint8_t>& p_data);
		void set(std::vector<uint8_t>&& p_data);

		void set(const std::filesystem::path& p_data);
		void set(std::filesystem::path&& p_data);

		std::optional<std::vector<uint8_t>> getData() const;

	private:
		std::vector<uint8_t> m_data;
		std::filesystem::path m_file;
		bool m_is_file = false;
		bool m_has_data = false;
	};


	struct Hashable
	{
		std::vector<uint8_t>	hash;
		data_source_t			source;
	};

	struct SymmetricEncodable
	{
		struct result_t
		{
			std::vector<uint8_t> key;
			data_source_t source;
		};
		data_source_t source;
		std::vector<result_t> encoded;
	};


	struct DataPair
	{
		std::vector<uint8_t> d0;
		std::vector<uint8_t> d1;
	};


	using HashList		= std::vector<Hashable>;
	using EncodeList	= std::vector<SymmetricEncodable>;
	using PairList		= std::vector<DataPair>;

	HashList	getHashList				(const std::filesystem::path& p_configPath, std::u32string_view p_hashName,  uint32_t p_hashSize);
	EncodeList	getSymmetricEncodeList	(const std::filesystem::path& p_configPath, std::u32string_view p_codecName, uint32_t p_keySize);
	PairList	getPrivatePublicKeyList	(const std::filesystem::path& p_configPath, std::u32string_view p_codecName, uint32_t p_privateKeySize, uint32_t p_publicKeySize);




} //namespace TestUntilities
