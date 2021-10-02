#include "test_utils.hpp"

#include <SCEF/SCEF.hpp>


#include <CoreLib/Core_Console.hpp>
#include <CoreLib/toPrint/toPrint.hpp>
#include <CoreLib/toPrint/toPrint_filesystem.hpp>
#include <CoreLib/string/core_string_numeric.hpp>
#include <CoreLib/string/core_string_encoding.hpp>
#include <CoreLib/Core_File.hpp>
#include <CoreLib/Core_OS.hpp>


#define PrintOut(...) core_ToPrint(char8_t, core::cout, __VA_ARGS__)


namespace testUtils
{

	static std::vector<uint8_t> get_hash(const scef::keyedValue& p_key, const uint32_t p_expectedSize)
	{
		std::u32string_view tvalue = p_key.value();
		if(tvalue.size() != 2 * p_expectedSize)
		{
			PrintOut("Invalid string hash size "sv, tvalue.size(), " expected "sv, 2 * p_expectedSize,
				" in line "sv , p_key.line());
			return {};
		}

		std::vector<uint8_t> outp;
		outp.resize(p_expectedSize);

		for(uint32_t i = 0; i < p_expectedSize; ++i)
		{
			const core::from_chars_result<uint8_t> res = core::from_chars_hex<uint8_t>(tvalue.substr(i * 2, 2));
			if(!res.has_value())
			{
				PrintOut("Invalid hash "sv, tvalue, " in line "sv , p_key.line());
				return {};
			}
			outp[i] = res.value();
		}

		return outp;
	}


	static std::filesystem::path get_path(const scef::keyedValue& p_key, const std::filesystem::path& p_basePath)
	{
		std::filesystem::path tpath{p_key.value()};

		if(tpath.empty())
		{
			PrintOut("Failed to get path line "sv, p_key.line());
			return {};
		}

		if(tpath.is_absolute())
		{
			return tpath.lexically_normal();
		}
		return (p_basePath / tpath).lexically_normal();
	}


	static std::vector<uint8_t> get_data(const scef::keyedValue& p_key)
	{
		const std::u32string_view value = p_key.view_value();
		const uintptr_t size = value.size();

		std::vector<uint8_t> out;
		for(uintptr_t i = 0; i < size; i += 2)
		{
			while((i < size) && value[i] == ' ')
			{
				++i;
			}

			if(!(i < size))
			{
				break;
			}

			if(size - i < 2)
			{
				PrintOut("Data must come in pairs of nibles, line "sv, p_key.line());
				return {};
			}

			const core::from_chars_result<uint8_t> res = core::from_chars_hex<uint8_t>(value.substr(i, 2));
			if(!res.has_value())
			{
				PrintOut("Data must come in pairs of nibles, line "sv, p_key.line());
				return {};
			}
			out.push_back(res.value());
		}
		return out;
	}

	static std::vector<uint8_t> get_string(const scef::keyedValue& p_key)
	{
		std::optional<std::u8string> data = core::UCS4_to_UTF8(p_key.view_value());
		if(data.has_value())
		{
			std::vector<uint8_t> out;
			const uintptr_t size = data.value().size();
			out.resize(size);
			memcpy(out.data(), data.value().data(), size);
			return out;
		}
		PrintOut("String \""sv, p_key.view_value(), "\" does not convert to utf8, at line"sv, p_key.line());
		return {};
	}

	HashList getHashList(const std::filesystem::path& p_configPath, const std::u32string_view p_hashName, const uint32_t p_hashSize)
	{
		if(p_hashSize == 0 || p_hashSize > 70000)
		{
			return {};
		}

		std::filesystem::path filepath;

		if(p_configPath.is_absolute())
		{
			filepath = p_configPath.lexically_normal();
		}
		else
		{
			filepath = (core::application_path().parent_path() / p_configPath).lexically_normal();
		}

		if(filepath.empty())
		{
			PrintOut("Failed to convert \""sv, p_configPath, "\" to a full path"sv);
			return {};
		}

		const std::filesystem::path basePath = filepath.parent_path();

		scef::document configFile;
		scef::Error err = configFile.load(filepath, scef::Flag::DisableSpacers | scef::Flag::DisableComments);

		if(err != scef::Error::None)
		{
			PrintOut("Error "sv, static_cast<uint8_t>(err), " while parsing file \""sv, filepath, '\"');
			return {};
		}

		const scef::itemProxy<const scef::group> usageGroup = configFile.root().find_group_by_name(U"test_vectors");

		if(usageGroup.get() == nullptr)
		{
			PrintOut("No \"test_vectors\" found in file \""sv, filepath, '\"');
			return {};
		}

		HashList list;
		for(const scef::itemProxy<const scef::item>& titem : usageGroup->proxyList(scef::ItemType::group))
		{
			const scef::group& tcase = *static_cast<const scef::group*>(titem.get());
			const scef::itemProxy<const scef::keyedValue> config_hash		= tcase.find_key_by_name(p_hashName);
			const scef::itemProxy<const scef::keyedValue> config_file		= tcase.find_key_by_name(U"file");
			const scef::itemProxy<const scef::keyedValue> config_data		= tcase.find_key_by_name(U"data");
			const scef::itemProxy<const scef::keyedValue> config_string		= tcase.find_key_by_name(U"string");

			if(!config_hash.get())
			{
				continue;
			}

			{
				uint8_t count = 0;
				if(config_file.get())
				{
					++count;
				}
				if(config_data.get())
				{
					++count;
				}
				if(config_string.get())
				{
					++count;
				}
				if(count == 0)
				{
					continue;
				}
				if(count != 1)
				{
					PrintOut("Error: Multiple data sources for case at line "sv, tcase.line(), " \""sv, filepath, '\"');
					continue;
				}
			}

			Hashable data;
			data.hash = get_hash(*config_hash, p_hashSize);

			if(data.hash.empty())
			{
				PrintOut("Failed to get hash value at "sv, config_hash->line(), " \""sv, filepath, '\"');
				continue;
			}

			if(config_file.get())
			{
				data.file = get_path(*config_file, basePath);
				data.is_file = true;
				if(data.file.empty())
				{
					PrintOut("Failed to get hash target at "sv, config_file->line(), " \""sv, filepath, '\"');
					continue;
				}
				else if(!std::filesystem::exists(data.file))
				{
					PrintOut("File  \""sv, data.file, "\" not found, line "sv, config_file->line());
					continue;
				}
			}
			else if(config_data.get())
			{
				data.data = get_data(*config_data);
			}
			else if(config_string.get())
			{
				data.data = get_string(*config_string);
			}

			list.emplace_back(std::move(data));
		}

		return list;
	}


	std::vector<uint8_t> getData(const Hashable& p_hashable)
	{
		if(p_hashable.is_file)
		{
			core::file_read file;
			if(file.open(p_hashable.file) != std::errc{})
			{
				PrintOut("Failed to open file \""sv, p_hashable.file, '\"');
				return {};
			}

			const uintptr_t file_size = file.size();

			std::vector<uint8_t> data;
			data.resize(file_size);

			if(file_size != file.read(data.data(), file_size))
			{
				PrintOut("Failed to read file \""sv, p_hashable.file, '\"');
				return {};
			}
			return data;
		}

		return p_hashable.data;
	}

} //namespace TestUntilities
