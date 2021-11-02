#pragma once

#include <cstdint>
#include <vector>
#include <filesystem>
#include <string_view>
#include <optional>

#include <CoreLib/Core_Type.hpp>
#include <CoreLib/toPrint/toPrint.hpp>
#include <CoreLib/toPrint/toPrint_std_ostream.hpp>

class testPrint: public core::toPrint_base
{
public:
	testPrint(const std::span<const uint8_t> p_data)
		: m_data(p_data)
	{
	}

	template<core::_p::c_toPrint_char CharT>
	inline constexpr uintptr_t size(const CharT&) const
	{
		return (m_data.size() * 3) - 1;
	}

	template<core::_p::c_toPrint_char CharT>
	inline void getPrint(CharT* p_out) const
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



	using HashList		= std::vector<Hashable>;
	using EncodeList	= std::vector<SymmetricEncodable>;

	HashList	getHashList				(const std::filesystem::path& p_configPath, std::u32string_view p_hashName,  uint32_t p_hashSize);
	EncodeList	getSymmetricEncodeList	(const std::filesystem::path& p_configPath, std::u32string_view p_codecName, uint32_t p_keySize);





} //namespace TestUntilities
