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

	void data_source_t::reset()
	{
		m_has_data = false;
		m_is_file = false;
		m_data.resize(0);
		m_file = "";
	}

	void data_source_t::set(const std::vector<uint8_t>& p_data)
	{
		m_has_data = true;
		m_is_file = false;
		m_file = "";
		m_data = p_data;
	}

	void data_source_t::set(std::vector<uint8_t>&& p_data)
	{
		m_has_data = true;
		m_is_file = false;
		m_file = "";
		m_data = std::move(p_data);
	}

	void data_source_t::set(const std::filesystem::path& p_data)
	{
		m_has_data = true;
		m_is_file = true;
		m_data.resize(0);
		m_file = p_data;
	}

	void data_source_t::set(std::filesystem::path&& p_data)
	{
		m_has_data = true;
		m_is_file = true;
		m_data.resize(0);
		m_file = std::move(p_data);
	}

	std::optional<std::vector<uint8_t>> data_source_t::getData() const
	{
		if(m_has_data)
		{
			if(m_is_file)
			{
				if(!std::filesystem::exists(m_file))
				{
					PrintOut("File  \""sv, m_file, "\" not found"sv);
					return {};
				}

				core::file_read file;
				if(file.open(m_file) != std::errc{})
				{
					PrintOut("Failed to open file \""sv, m_file, '\"');
					return {};
				}

				const uintptr_t file_size = file.size();

				std::vector<uint8_t> data;
				data.resize(file_size);

				if(file_size != file.read(data.data(), file_size))
				{
					PrintOut("Failed to read file \""sv, m_file, '\"');
					return {};
				}
				return data;
			}
			return m_data;
		}
		return {};
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


	static std::optional<std::vector<uint8_t>> get_data(const std::u32string_view p_value, uintptr_t p_line)
	{
		const uintptr_t size = p_value.size();

		std::vector<uint8_t> out;
		for(uintptr_t i = 0; i < size; i += 2)
		{
			while((i < size) && p_value[i] == ' ')
			{
				++i;
			}

			if(!(i < size))
			{
				break;
			}

			if(size - i < 2)
			{
				PrintOut("Data must come in pairs of nibles, line "sv, p_line);
				return {};
			}

			const core::from_chars_result<uint8_t> res = core::from_chars_hex<uint8_t>(p_value.substr(i, 2));
			if(!res.has_value())
			{
				PrintOut("Data must come in pairs of nibles, line "sv, p_line);
				return {};
			}
			out.push_back(res.value());
		}
		return out;
	}

	static std::optional<std::vector<uint8_t>> get_string(const scef::keyedValue& p_key)
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


	static std::vector<uint8_t> get_hex_buffer(const std::u32string_view p_text)
	{
		if (p_text.size() & 1) return {};
		const uintptr_t size = p_text.size() / 2;

		std::vector<uint8_t> outp;
		outp.resize(size);

		for(uintptr_t i = 0; i < size; ++i)
		{
			const core::from_chars_result<uint8_t> res = core::from_chars_hex<uint8_t>(p_text.substr(i * 2, 2));
			if(!res.has_value())
			{
				return {};
			}
			outp[i] = res.value();
		}
		return outp;
	}

	static std::vector<uint8_t> get_hash(const scef::keyedValue& p_key, const uint32_t p_expectedSize)
	{
		std::u32string_view tvalue = p_key.value();
		if(tvalue.size() != 2 * p_expectedSize)
		{
			PrintOut("Invalid string hash size "sv, tvalue.size(), " expected "sv, 2 * p_expectedSize,
				" in line "sv , p_key.line());
			return {};
		}

		std::vector<uint8_t> outp = get_hex_buffer(tvalue);
		if(outp.empty())
		{
			PrintOut("Invalid hash "sv, tvalue, " in line "sv , p_key.line());
		}
		return outp;
	}

	std::optional<data_source_t> getDataSource(const scef::group& p_group, const std::filesystem::path& p_basePath, const std::filesystem::path& p_filePath)
	{
		const scef::itemProxy<const scef::keyedValue> config_file	= p_group.find_key_by_name(U"file");
		const scef::itemProxy<const scef::keyedValue> config_data	= p_group.find_key_by_name(U"data");
		const scef::itemProxy<const scef::keyedValue> config_string	= p_group.find_key_by_name(U"string");

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
				return {};
			}
			if(count != 1)
			{
				PrintOut("Error: Multiple data sources for case at line "sv, p_group.line(), " \""sv, p_filePath, '\"');
				return {};
			}
		}

		data_source_t data_source;
		if(config_file.get())
		{
			std::filesystem::path tpath = get_path(*config_file, p_basePath);
			if(tpath.empty())
			{
				PrintOut("Failed to get hash target at "sv, config_file->line(), " \""sv, p_filePath, '\"');
				return {};
			}

			data_source.set(std::move(tpath));
		}
		else if(config_data.get())
		{
			std::optional<std::vector<uint8_t>> rdata = get_data(config_data->value(), config_data->line());
			if(!rdata.has_value())
			{
				return {};
			}
			data_source.set(std::move(rdata.value()));
		}
		else if(config_string.get())
		{
			std::optional<std::vector<uint8_t>> rdata = get_string(*config_string);
			if(!rdata.has_value())
			{
				return {};
			}
			data_source.set(std::move(rdata.value()));
		}


		return data_source;
	}


	std::vector<SymmetricEncodable::result_t> getSymmetricEncoding(const scef::group& p_config, const uint32_t p_keySize, const std::filesystem::path& p_basePath, const std::filesystem::path& p_filePath)
	{
		std::vector<SymmetricEncodable::result_t> output;
		for(const scef::itemProxy<const scef::item>& titem : p_config.proxyList(scef::ItemType::group))
		{
			const scef::group& tcase = *static_cast<const scef::group*>(titem.get());

			std::optional<std::vector<uint8_t>> rkey = get_data(tcase.name(), tcase.line());

			if(!rkey.has_value())
			{
				continue;
			}

			if(p_keySize)
			{
				if(rkey.value().size() != p_keySize)
				{
					PrintOut("Key \""sv, tcase.name(), "\" is not of expected size (expected: "sv,
						p_keySize, " actual: "sv, rkey.value().size(), ") Line "sv, tcase.line(), " \""sv, p_filePath, '\"');
					continue;
				}
			}

			SymmetricEncodable::result_t temp_result;

			temp_result.key = std::move(rkey.value());
			std::optional<data_source_t> res_source = getDataSource(tcase, p_basePath, p_filePath);

			if(!res_source.has_value())
			{
				continue;
			}

			temp_result.source = std::move(res_source.value());

			output.emplace_back(std::move(temp_result));
		}
		return output;
	}

	static std::filesystem::path normalize_path(const std::filesystem::path& p_path)
	{
		if (p_path.is_absolute())
		{
			return p_path.lexically_normal();
		}
		else
		{
			return (core::application_path().parent_path() / p_path).lexically_normal();
		}
	}


	HashList getHashList(const std::filesystem::path& p_configPath, const std::u32string_view p_hashName, const uint32_t p_hashSize)
	{
		if(p_hashSize == 0 || p_hashSize > 70000)
		{
			return {};
		}

		const std::filesystem::path filepath = normalize_path(p_configPath);

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
			const scef::itemProxy<const scef::keyedValue> config_hash = tcase.find_key_by_name(p_hashName);

			if(!config_hash.get())
			{
				continue;
			}

			Hashable data;
			data.hash = get_hash(*config_hash, p_hashSize);

			if(data.hash.empty())
			{
				PrintOut("Failed to get hash value at "sv, config_hash->line(), " \""sv, filepath, '\"');
				continue;
			}

			std::optional<data_source_t> res_source = getDataSource(tcase, basePath, filepath);

			if(!res_source.has_value())
			{
				continue;
			}

			data.source = std::move(res_source.value());

			list.emplace_back(std::move(data));
		}

		return list;
	}


	EncodeList getSymmetricEncodeList(const std::filesystem::path& p_configPath, std::u32string_view p_codecName, uint32_t p_keySize)
	{
		if(p_keySize > 70000)
		{
			return {};
		}

		const std::filesystem::path filepath = normalize_path(p_configPath);

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


		EncodeList list;

		for(const scef::itemProxy<const scef::item>& titem : usageGroup->proxyList(scef::ItemType::group))
		{
			const scef::group& tcase = *static_cast<const scef::group*>(titem.get());
			const scef::itemProxy<const scef::group> config_encoder = tcase.find_group_by_name(p_codecName);

			if(!config_encoder.get())
			{
				continue;
			}

			SymmetricEncodable data;

			std::optional<data_source_t> res_source = getDataSource(tcase, basePath, filepath);
			if(!res_source.has_value())
			{
				continue;
			}
			data.source = std::move(res_source.value());

			data.encoded = getSymmetricEncoding(*config_encoder, p_keySize, basePath, filepath);

			if(data.encoded.empty())
			{
				continue;
			}

			list.emplace_back(std::move(data));
		}

		return list;
	}

	PairList getPrivatePublicKeyList(const std::filesystem::path& p_configPath, std::u32string_view p_codecName, uint32_t p_privateKeySize, uint32_t p_publicKeySize)
	{
		if(p_privateKeySize > 70000 || p_publicKeySize > 70000)
		{
			return {};
		}

		const std::filesystem::path filepath = normalize_path(p_configPath);

		if (filepath.empty())
		{
			PrintOut("Failed to convert \""sv, p_configPath, "\" to a full path"sv);
			return {};
		}

		scef::document configFile;
		scef::Error err = configFile.load(filepath, scef::Flag::DisableSpacers | scef::Flag::DisableComments);

		if(err != scef::Error::None)
		{
			PrintOut("Error "sv, static_cast<uint8_t>(err), " while parsing file \""sv, filepath, '\"');
			return {};
		}

		const scef::itemProxy<const scef::group> usageGroup = configFile.root().find_group_by_name(U"test_vectors_public_key");

		if(usageGroup.get() == nullptr)
		{
			PrintOut("No \"test_vectors_public_key\" found in file \""sv, filepath, '\"');
			return {};
		}

		PairList list;

		for(const scef::itemProxy<const scef::item>& titem0 : usageGroup->proxyList(scef::ItemType::group))
		{
			const scef::group& tcodec = *static_cast<const scef::group*>(titem0.get());
			if(tcodec.name() != p_codecName)
			{
				continue;
			}

			for(const scef::itemProxy<const scef::item>& titem1 : tcodec.proxyList(scef::ItemType::group))
			{
				const scef::group& tcase = *static_cast<const scef::group*>(titem1.get());

				const scef::itemProxy<const scef::keyedValue> private_key = tcase.find_key_by_name(U"private");
				const scef::itemProxy<const scef::keyedValue> public_key  = tcase.find_key_by_name(U"public");

				if(!private_key.get() || !public_key.get())
				{
					continue;
				}

				std::u32string_view tprivate = private_key->value();
				std::u32string_view tpublic  = public_key ->value();

				if(tprivate.size() != 2 * p_privateKeySize)
				{
					PrintOut("Invalid string private key size "sv, tprivate.size(), " expected "sv, 2 * p_privateKeySize,
						" in line "sv , private_key->line());
					continue;
				}

				if(tpublic.size() != 2 * p_publicKeySize)
				{
					PrintOut("Invalid string public key size "sv, tpublic.size(), " expected "sv, 2 * p_publicKeySize,
						" in line "sv , public_key->line());
					continue;
				}

				DataPair tpair;

				tpair.d0 = get_hex_buffer(tprivate);

				if(tpair.d0.empty())
				{
					PrintOut("Invalid key "sv, tprivate, " in line "sv , private_key->line());
					continue;
				}

				tpair.d1 = get_hex_buffer(tpublic);

				if(tpair.d1.empty())
				{
					PrintOut("Invalid key "sv, tpublic, " in line "sv , public_key->line());
					continue;
				}

				list.push_back(std::move(tpair));
			}
		}

		return list;
	}



} //namespace TestUntilities
