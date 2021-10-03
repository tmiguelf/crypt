#pragma once

#include <cstdint>
#include <vector>
#include <filesystem>
#include <string_view>

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

	struct Hashable
	{
		std::vector<uint8_t> hash;
		std::vector<uint8_t> data;
		std::filesystem::path file;
		bool is_file = false;
	};


	using HashList = std::vector<Hashable>;

	HashList getHashList(const std::filesystem::path& p_configPath, std::u32string_view p_hashName, uint32_t p_hashSize);

	std::vector<uint8_t> getData(const Hashable& p_hashable);
} //namespace TestUntilities