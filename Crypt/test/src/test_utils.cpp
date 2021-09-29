#include "test_utils.hpp"

#include <SCEF/SCEF.hpp>


#include <CoreLib/Core_Console.hpp>
#include <CoreLib/toPrint/toPrint.hpp>
#include <CoreLib/toPrint/toPrint_filesystem.hpp>
#include <CoreLib/string/core_string_numeric.hpp>
#include <CoreLib/Core_File.hpp>


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
			core::from_chars_result<uint8_t> res = core::from_chars_hex<uint8_t>(tvalue.substr(i * 2, 2));
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


	fileHashList getFileHashList(const std::filesystem::path& p_configPath, const std::u32string_view p_hashName, const uint32_t p_hashSize)
	{
		if(p_hashSize == 0 || p_hashSize > 70000)
		{
			return {};
		}

		std::error_code ec;
		const std::filesystem::path filepath = std::filesystem::absolute(p_configPath, ec);
		if(ec != std::error_code{})
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

		fileHashList list;
		for(const scef::itemProxy<const scef::item>& titem : usageGroup->proxyList(scef::ItemType::group))
		{
			const scef::group& tcase = *static_cast<const scef::group*>(titem.get());
			const scef::itemProxy<const scef::keyedValue> hash = tcase.find_key_by_name(p_hashName);
			const scef::itemProxy<const scef::keyedValue> file = tcase.find_key_by_name(U"file");
			if(hash.get() && file.get())
			{
				HashPair data;
				data.hash = get_hash(*hash, p_hashSize);
				data.file = get_path(*file, basePath);

				if(data.hash.empty())
				{
					PrintOut("Failed to get hash value at "sv, hash->line(), " \""sv, filepath, '\"');
					continue;
				}
				if(data.file.empty())
				{
					PrintOut("Failed to get hash target at "sv, file->line(), " \""sv, filepath, '\"');
					continue;
				}
				else if(!std::filesystem::exists(data.file))
				{
					PrintOut("File  \""sv, data.file, "\" not found, line "sv, file->line());
				}
				list.emplace_back(std::move(data));
			}
		}

		return list;
	}

	std::vector<uint8_t> getFileData(const std::filesystem::path& p_file)
	{
		core::file_read file;
		if(file.open(p_file) != std::errc{})
		{
			PrintOut("Failed to open file \""sv, p_file, '\"');
			return {};
		}

		const uintptr_t file_size = file.size();

		std::vector<uint8_t> data;
		data.resize(file_size);

		if(file_size != file.read(data.data(), file_size))
		{
			PrintOut("Failed to read file \""sv, p_file, '\"');
			return {};
		}

		return data;
	}

} //namespace TestUntilities
