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

#include <Crypt/hash/crc.hpp>

#include <bit>

#include <CoreLib/Core_Type.hpp>

#include <Crypt/utils.hpp>


#if defined(_M_AMD64) || defined(__SSE4_2__)
#include <nmmintrin.h>
#else
#endif

namespace crypt
{
using core::literals::operator "" _ui32;
using core::literals::operator "" _uip;

#if defined(_M_AMD64) || defined(__SSE4_2__)
void CRC_32C::update(std::span<const uint8_t> const p_data)
{
	const uintptr_t			size  = p_data.size();
	const uint8_t*			pivot = p_data.data();
	const uint8_t* const	last  = pivot + size;

	uint32_t context = m_context;
	{
		const uintptr_t off_align = align_t_mod<uint64_t>(pivot);
		if((alignof(uint64_t) - off_align) < size)
		{
			for(const uint8_t tpoint : p_data)
			{
				context = _mm_crc32_u8(context, tpoint);
			}
			m_context = context;
			return;
		}

		switch(off_align)
		{
		case 1:
			context = _mm_crc32_u8(context, *pivot++);
			[[fallthrough]];
		case 2:
			context = _mm_crc32_u16(context, *reinterpret_cast<const uint16_t*>(pivot));
			pivot += 2;
			[[fallthrough]];
		case 4:
			context = _mm_crc32_u32(context, *reinterpret_cast<const uint32_t*>(pivot));
			pivot += 4;
			break;
		case 3:
			context = _mm_crc32_u8(context, *pivot++);
			context = _mm_crc32_u32(context, *reinterpret_cast<const uint32_t*>(pivot));
			pivot += 4;
			break;
		case 5:
			context = _mm_crc32_u8(context, *pivot++);
			[[fallthrough]];
		case 6:
			context = _mm_crc32_u16(context, *reinterpret_cast<const uint16_t*>(pivot));
			pivot += 2;
			break;
		case 7:
			context = _mm_crc32_u8(context, *pivot++);
			break;
		default:
		case 0:
			break;
		}
	}

	{
		uint64_t context64 = context;
		for(; (last - pivot) >= 8; pivot += 8)
		{
			context64 = _mm_crc32_u64(context64, *reinterpret_cast<const uint64_t*>(pivot));
		}
		context = static_cast<uint32_t>(context64);
	}

	switch(last - pivot)
	{
	case 7:
		context = _mm_crc32_u8(context, *pivot++);
		[[fallthrough]];
	case 6:
		context = _mm_crc32_u16(context, *reinterpret_cast<const uint16_t*>(pivot));
		pivot += 2;
		[[fallthrough]];
	case 4:
		context = _mm_crc32_u32(context, *reinterpret_cast<const uint32_t*>(pivot));
		break;
	case 5:
		context = _mm_crc32_u8(context, *pivot++);
		context = _mm_crc32_u32(context, *reinterpret_cast<const uint32_t*>(pivot));
		break;
	case 3:
		context = _mm_crc32_u8(context, *pivot++);
		[[fallthrough]];
	case 2:
		context = _mm_crc32_u16(context, *reinterpret_cast<const uint16_t*>(pivot));
		break;
	case 1:
		context = _mm_crc32_u8(context, *pivot);
		break;
	default:
	case 0:
		break;
	}

	m_context = context;
}

void CRC_32C::update(std::span<const uint64_t> p_data)
{
	uint64_t context64 = m_context;
	for(const uint64_t tpoint : p_data)
	{
		context64 = _mm_crc32_u64(context64, tpoint);
	}
	m_context = static_cast<uint32_t>(context64);
}


#else

static constexpr std::array<uint32_t, 256> CRC32C_table_f()
{
	static_assert(std::endian::native == std::endian::little, "Unsuported endianess");
	if constexpr (std::endian::native == std::endian::little)
	{
		return std::array<uint32_t, 256>
		{
			0x00000000_ui32, 0xF26B8303_ui32, 0xE13B70F7_ui32, 0x1350F3F4_ui32,
				0xC79A971F_ui32, 0x35F1141C_ui32, 0x26A1E7E8_ui32, 0xD4CA64EB_ui32,
				0x8AD958CF_ui32, 0x78B2DBCC_ui32, 0x6BE22838_ui32, 0x9989AB3B_ui32,
				0x4D43CFD0_ui32, 0xBF284CD3_ui32, 0xAC78BF27_ui32, 0x5E133C24_ui32,
				0x105EC76F_ui32, 0xE235446C_ui32, 0xF165B798_ui32, 0x030E349B_ui32,
				0xD7C45070_ui32, 0x25AFD373_ui32, 0x36FF2087_ui32, 0xC494A384_ui32,
				0x9A879FA0_ui32, 0x68EC1CA3_ui32, 0x7BBCEF57_ui32, 0x89D76C54_ui32,
				0x5D1D08BF_ui32, 0xAF768BBC_ui32, 0xBC267848_ui32, 0x4E4DFB4B_ui32,
				0x20BD8EDE_ui32, 0xD2D60DDD_ui32, 0xC186FE29_ui32, 0x33ED7D2A_ui32,
				0xE72719C1_ui32, 0x154C9AC2_ui32, 0x061C6936_ui32, 0xF477EA35_ui32,
				0xAA64D611_ui32, 0x580F5512_ui32, 0x4B5FA6E6_ui32, 0xB93425E5_ui32,
				0x6DFE410E_ui32, 0x9F95C20D_ui32, 0x8CC531F9_ui32, 0x7EAEB2FA_ui32,
				0x30E349B1_ui32, 0xC288CAB2_ui32, 0xD1D83946_ui32, 0x23B3BA45_ui32,
				0xF779DEAE_ui32, 0x05125DAD_ui32, 0x1642AE59_ui32, 0xE4292D5A_ui32,
				0xBA3A117E_ui32, 0x4851927D_ui32, 0x5B016189_ui32, 0xA96AE28A_ui32,
				0x7DA08661_ui32, 0x8FCB0562_ui32, 0x9C9BF696_ui32, 0x6EF07595_ui32,
				0x417B1DBC_ui32, 0xB3109EBF_ui32, 0xA0406D4B_ui32, 0x522BEE48_ui32,
				0x86E18AA3_ui32, 0x748A09A0_ui32, 0x67DAFA54_ui32, 0x95B17957_ui32,
				0xCBA24573_ui32, 0x39C9C670_ui32, 0x2A993584_ui32, 0xD8F2B687_ui32,
				0x0C38D26C_ui32, 0xFE53516F_ui32, 0xED03A29B_ui32, 0x1F682198_ui32,
				0x5125DAD3_ui32, 0xA34E59D0_ui32, 0xB01EAA24_ui32, 0x42752927_ui32,
				0x96BF4DCC_ui32, 0x64D4CECF_ui32, 0x77843D3B_ui32, 0x85EFBE38_ui32,
				0xDBFC821C_ui32, 0x2997011F_ui32, 0x3AC7F2EB_ui32, 0xC8AC71E8_ui32,
				0x1C661503_ui32, 0xEE0D9600_ui32, 0xFD5D65F4_ui32, 0x0F36E6F7_ui32,
				0x61C69362_ui32, 0x93AD1061_ui32, 0x80FDE395_ui32, 0x72966096_ui32,
				0xA65C047D_ui32, 0x5437877E_ui32, 0x4767748A_ui32, 0xB50CF789_ui32,
				0xEB1FCBAD_ui32, 0x197448AE_ui32, 0x0A24BB5A_ui32, 0xF84F3859_ui32,
				0x2C855CB2_ui32, 0xDEEEDFB1_ui32, 0xCDBE2C45_ui32, 0x3FD5AF46_ui32,
				0x7198540D_ui32, 0x83F3D70E_ui32, 0x90A324FA_ui32, 0x62C8A7F9_ui32,
				0xB602C312_ui32, 0x44694011_ui32, 0x5739B3E5_ui32, 0xA55230E6_ui32,
				0xFB410CC2_ui32, 0x092A8FC1_ui32, 0x1A7A7C35_ui32, 0xE811FF36_ui32,
				0x3CDB9BDD_ui32, 0xCEB018DE_ui32, 0xDDE0EB2A_ui32, 0x2F8B6829_ui32,
				0x82F63B78_ui32, 0x709DB87B_ui32, 0x63CD4B8F_ui32, 0x91A6C88C_ui32,
				0x456CAC67_ui32, 0xB7072F64_ui32, 0xA457DC90_ui32, 0x563C5F93_ui32,
				0x082F63B7_ui32, 0xFA44E0B4_ui32, 0xE9141340_ui32, 0x1B7F9043_ui32,
				0xCFB5F4A8_ui32, 0x3DDE77AB_ui32, 0x2E8E845F_ui32, 0xDCE5075C_ui32,
				0x92A8FC17_ui32, 0x60C37F14_ui32, 0x73938CE0_ui32, 0x81F80FE3_ui32,
				0x55326B08_ui32, 0xA759E80B_ui32, 0xB4091BFF_ui32, 0x466298FC_ui32,
				0x1871A4D8_ui32, 0xEA1A27DB_ui32, 0xF94AD42F_ui32, 0x0B21572C_ui32,
				0xDFEB33C7_ui32, 0x2D80B0C4_ui32, 0x3ED04330_ui32, 0xCCBBC033_ui32,
				0xA24BB5A6_ui32, 0x502036A5_ui32, 0x4370C551_ui32, 0xB11B4652_ui32,
				0x65D122B9_ui32, 0x97BAA1BA_ui32, 0x84EA524E_ui32, 0x7681D14D_ui32,
				0x2892ED69_ui32, 0xDAF96E6A_ui32, 0xC9A99D9E_ui32, 0x3BC21E9D_ui32,
				0xEF087A76_ui32, 0x1D63F975_ui32, 0x0E330A81_ui32, 0xFC588982_ui32,
				0xB21572C9_ui32, 0x407EF1CA_ui32, 0x532E023E_ui32, 0xA145813D_ui32,
				0x758FE5D6_ui32, 0x87E466D5_ui32, 0x94B49521_ui32, 0x66DF1622_ui32,
				0x38CC2A06_ui32, 0xCAA7A905_ui32, 0xD9F75AF1_ui32, 0x2B9CD9F2_ui32,
				0xFF56BD19_ui32, 0x0D3D3E1A_ui32, 0x1E6DCDEE_ui32, 0xEC064EED_ui32,
				0xC38D26C4_ui32, 0x31E6A5C7_ui32, 0x22B65633_ui32, 0xD0DDD530_ui32,
				0x0417B1DB_ui32, 0xF67C32D8_ui32, 0xE52CC12C_ui32, 0x1747422F_ui32,
				0x49547E0B_ui32, 0xBB3FFD08_ui32, 0xA86F0EFC_ui32, 0x5A048DFF_ui32,
				0x8ECEE914_ui32, 0x7CA56A17_ui32, 0x6FF599E3_ui32, 0x9D9E1AE0_ui32,
				0xD3D3E1AB_ui32, 0x21B862A8_ui32, 0x32E8915C_ui32, 0xC083125F_ui32,
				0x144976B4_ui32, 0xE622F5B7_ui32, 0xF5720643_ui32, 0x07198540_ui32,
				0x590AB964_ui32, 0xAB613A67_ui32, 0xB831C993_ui32, 0x4A5A4A90_ui32,
				0x9E902E7B_ui32, 0x6CFBAD78_ui32, 0x7FAB5E8C_ui32, 0x8DC0DD8F_ui32,
				0xE330A81A_ui32, 0x115B2B19_ui32, 0x020BD8ED_ui32, 0xF0605BEE_ui32,
				0x24AA3F05_ui32, 0xD6C1BC06_ui32, 0xC5914FF2_ui32, 0x37FACCF1_ui32,
				0x69E9F0D5_ui32, 0x9B8273D6_ui32, 0x88D28022_ui32, 0x7AB90321_ui32,
				0xAE7367CA_ui32, 0x5C18E4C9_ui32, 0x4F48173D_ui32, 0xBD23943E_ui32,
				0xF36E6F75_ui32, 0x0105EC76_ui32, 0x12551F82_ui32, 0xE03E9C81_ui32,
				0x34F4F86A_ui32, 0xC69F7B69_ui32, 0xD5CF889D_ui32, 0x27A40B9E_ui32,
				0x79B737BA_ui32, 0x8BDCB4B9_ui32, 0x988C474D_ui32, 0x6AE7C44E_ui32,
				0xBE2DA0A5_ui32, 0x4C4623A6_ui32, 0x5F16D052_ui32, 0xAD7D5351_ui32
		};
	}
}

static constexpr std::array CRC32C_table = CRC32C_table_f();

static inline uint32_t soft_CRC_32C_u8(const uint32_t p_context, const uint8_t p_new)
{
	if constexpr(std::endian::native == std::endian::little)
	{
		return CRC32C_table[static_cast<uint8_t>(p_context & 0xFF) ^ p_new] ^ (p_context >> 8);
	}
}

static inline uint32_t soft_CRC_32C_u32(uint32_t p_context, const uint32_t p_new)
{
	if constexpr(std::endian::native == std::endian::little)
	{
		p_context ^= p_new;
		p_context = CRC32C_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
		p_context = CRC32C_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
		p_context = CRC32C_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
		return CRC32C_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
	}
}

void CRC_32C::update(std::span<const uint8_t> const p_data)
{
	const uintptr_t			size  = p_data.size();
	const uint8_t*			pivot = p_data.data();
	const uint8_t* const	last  = pivot + size;

	uint32_t context = m_context;
	{
		const uintptr_t off_align = align_t_mod<uint32_t>(pivot);
		if((alignof(uint32_t) - off_align) < size)
		{
			for(const uint8_t tpoint : p_data)
			{
				context = soft_CRC_32C_u8(context, tpoint);
			}
			m_context = context;
			return;
		}

		switch(off_align)
		{
		case 1:
			context = soft_CRC_32C_u8(context, *pivot++);
			[[fallthrough]];
		case 2:
			context = soft_CRC_32C_u8(context, *pivot++);
			[[fallthrough]];
		case 3:
			context = soft_CRC_32C_u8(context, *pivot++);
			break;
		default:
		case 0:
			break;
		}
	}

	for(; (last - pivot) >= 4; pivot += 4)
	{
		context = soft_CRC_32C_u32(context, *reinterpret_cast<const uint32_t*>(pivot));
	}

	switch(last - pivot)
	{
	case 3:
		context = soft_CRC_32C_u8(context, *pivot++);
		[[fallthrough]];
	case 2:
		context = soft_CRC_32C_u8(context, *pivot++);
		[[fallthrough]];
	case 1:
		context = soft_CRC_32C_u8(context, *pivot);
		break;
	default:
	case 0:
		break;
	}

	m_context = context;
}

void CRC_32C::update(std::span<const uint64_t> p_data)
{
	uint32_t context = m_context;
	for(const uint64_t tpoint : p_data)
	{
		context = soft_CRC_32C_u32(context, *reinterpret_cast<const uint32_t*>(&tpoint));
		context = soft_CRC_32C_u32(context, *(reinterpret_cast<const uint32_t*>(&tpoint) + 1));
	}
	m_context = context;
}

#endif

} //namespace crypt
