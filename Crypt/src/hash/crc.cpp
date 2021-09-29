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

#include <array>
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
using core::literals::operator "" _ui64;
using core::literals::operator "" _uip;

#if defined(_M_AMD64) || defined(__SSE4_2__)

uint32_t CRC_32C::trasform(uint32_t p_current, const std::span<const uint8_t> p_data)
{
	const uintptr_t			size  = p_data.size();
	const uint8_t*			pivot = p_data.data();
	const uint8_t* const	last  = pivot + size;

	{
		const uintptr_t off_align = align_t_mod<uint64_t>(pivot);
		if((alignof(uint64_t) - off_align) > size)
		{
			for(const uint8_t tpoint : p_data)
			{
				p_current = _mm_crc32_u8(p_current, tpoint);
			}
			return p_current;
		}

		switch(off_align)
		{
		case 1:
			p_current = _mm_crc32_u8(p_current, *pivot++);
			[[fallthrough]];
		case 2:
			p_current = _mm_crc32_u16(p_current, *reinterpret_cast<const uint16_t*>(pivot));
			pivot += 2;
			[[fallthrough]];
		case 4:
			p_current = _mm_crc32_u32(p_current, *reinterpret_cast<const uint32_t*>(pivot));
			pivot += 4;
			break;
		case 3:
			p_current = _mm_crc32_u8(p_current, *pivot++);
			p_current = _mm_crc32_u32(p_current, *reinterpret_cast<const uint32_t*>(pivot));
			pivot += 4;
			break;
		case 5:
			p_current = _mm_crc32_u8(p_current, *pivot++);
			[[fallthrough]];
		case 6:
			p_current = _mm_crc32_u16(p_current, *reinterpret_cast<const uint16_t*>(pivot));
			pivot += 2;
			break;
		case 7:
			p_current = _mm_crc32_u8(p_current, *pivot++);
			break;
		default:
		case 0:
			break;
		}
	}

	{
		uint64_t context64 = p_current;
		for(; (last - pivot) >= 8; pivot += 8)
		{
			context64 = _mm_crc32_u64(context64, *reinterpret_cast<const uint64_t*>(pivot));
		}
		p_current = static_cast<uint32_t>(context64);
	}

	switch(last - pivot)
	{
	case 7:
		p_current = _mm_crc32_u8(p_current, *pivot++);
		[[fallthrough]];
	case 6:
		p_current = _mm_crc32_u16(p_current, *reinterpret_cast<const uint16_t*>(pivot));
		pivot += 2;
		[[fallthrough]];
	case 4:
		p_current = _mm_crc32_u32(p_current, *reinterpret_cast<const uint32_t*>(pivot));
		break;
	case 5:
		p_current = _mm_crc32_u8(p_current, *pivot++);
		p_current = _mm_crc32_u32(p_current, *reinterpret_cast<const uint32_t*>(pivot));
		break;
	case 3:
		p_current = _mm_crc32_u8(p_current, *pivot++);
		[[fallthrough]];
	case 2:
		p_current = _mm_crc32_u16(p_current, *reinterpret_cast<const uint16_t*>(pivot));
		break;
	case 1:
		p_current = _mm_crc32_u8(p_current, *pivot);
		break;
	default:
	case 0:
		break;
	}

	return p_current;
}

uint32_t CRC_32C::trasform(const uint32_t p_current, const std::span<const uint64_t> p_data)
{
	uint64_t context64 = p_current;
	for(const uint64_t tpoint : p_data)
	{
		context64 = _mm_crc32_u64(context64, tpoint);
	}
	return static_cast<uint32_t>(context64);
}

#else

static_assert(std::endian::native == std::endian::little, "Unsuported endianess");
namespace
{
	struct CRC32C_Help
	{
		static constexpr std::array<uint32_t, 256> CRC32C_table =
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

		static inline uint32_t soft_u8(const uint32_t p_context, const uint8_t p_new)
		{
			if constexpr(std::endian::native == std::endian::little)
			{
				return CRC32C_table[static_cast<uint8_t>(p_context) ^ p_new] ^ (p_context >> 8);
			}
		}

		static inline uint32_t soft_u32(uint32_t p_context, const uint32_t p_new)
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
	};

} //namespace

uint32_t CRC_32C::trasform(uint32_t p_current, const std::span<const uint8_t> p_data)
{
	const uintptr_t			size  = p_data.size();
	const uint8_t*			pivot = p_data.data();
	const uint8_t* const	last  = pivot + size;

	{
		const uintptr_t off_align = align_t_mod<uint32_t>(pivot);
		if((alignof(uint32_t) - off_align) > size)
		{
			for(const uint8_t tpoint : p_data)
			{
				p_current = CRC32C_Help::soft_u8(p_current, tpoint);
			}
			return p_current;
		}

		switch(off_align)
		{
		case 1:
			p_current = CRC32C_Help::soft_u8(p_current, *pivot++);
			[[fallthrough]];
		case 2:
			p_current = CRC32C_Help::soft_u8(p_current, *pivot++);
			[[fallthrough]];
		case 3:
			p_current = CRC32C_Help::soft_u8(p_current, *pivot++);
			break;
		default:
		case 0:
			break;
		}
	}

	for(; (last - pivot) >= 4; pivot += 4)
	{
		p_current = CRC32C_Help::soft_u32(p_current, *reinterpret_cast<const uint32_t*>(pivot));
	}

	switch(last - pivot)
	{
	case 3:
		p_current = CRC32C_Help::soft_u8(p_current, *pivot++);
		[[fallthrough]];
	case 2:
		p_current = CRC32C_Help::soft_u8(p_current, *pivot++);
		[[fallthrough]];
	case 1:
		p_current = CRC32C_Help::soft_u8(p_current, *pivot);
		break;
	default:
	case 0:
		break;
	}

	return p_current;
}

uint32_t CRC_32C::trasform(uint32_t p_current, const std::span<const uint64_t> p_data)
{
	for(const uint64_t tpoint : p_data)
	{
		p_current = CRC32C_Help::soft_u32(p_current, *reinterpret_cast<const uint32_t*>(&tpoint));
		p_current = CRC32C_Help::soft_u32(p_current, *(reinterpret_cast<const uint32_t*>(&tpoint) + 1));
	}
	return p_current;
}

#endif






static_assert(std::endian::native == std::endian::little, "Unsuported endianess");
namespace
{
	struct CRC64_Help
	{
		static constexpr std::array<uint64_t, 256> CRC64_table =
		{
			0x0000000000000000_ui64, 0xB32E4CBE03A75F6F_ui64, 0xF4843657A840A05B_ui64, 0x47AA7AE9ABE7FF34_ui64,
			0x7BD0C384FF8F5E33_ui64, 0xC8FE8F3AFC28015C_ui64, 0x8F54F5D357CFFE68_ui64, 0x3C7AB96D5468A107_ui64,
			0xF7A18709FF1EBC66_ui64, 0x448FCBB7FCB9E309_ui64, 0x0325B15E575E1C3D_ui64, 0xB00BFDE054F94352_ui64,
			0x8C71448D0091E255_ui64, 0x3F5F08330336BD3A_ui64, 0x78F572DAA8D1420E_ui64, 0xCBDB3E64AB761D61_ui64,
			0x7D9BA13851336649_ui64, 0xCEB5ED8652943926_ui64, 0x891F976FF973C612_ui64, 0x3A31DBD1FAD4997D_ui64,
			0x064B62BCAEBC387A_ui64, 0xB5652E02AD1B6715_ui64, 0xF2CF54EB06FC9821_ui64, 0x41E11855055BC74E_ui64,
			0x8A3A2631AE2DDA2F_ui64, 0x39146A8FAD8A8540_ui64, 0x7EBE1066066D7A74_ui64, 0xCD905CD805CA251B_ui64,
			0xF1EAE5B551A2841C_ui64, 0x42C4A90B5205DB73_ui64, 0x056ED3E2F9E22447_ui64, 0xB6409F5CFA457B28_ui64,
			0xFB374270A266CC92_ui64, 0x48190ECEA1C193FD_ui64, 0x0FB374270A266CC9_ui64, 0xBC9D3899098133A6_ui64,
			0x80E781F45DE992A1_ui64, 0x33C9CD4A5E4ECDCE_ui64, 0x7463B7A3F5A932FA_ui64, 0xC74DFB1DF60E6D95_ui64,
			0x0C96C5795D7870F4_ui64, 0xBFB889C75EDF2F9B_ui64, 0xF812F32EF538D0AF_ui64, 0x4B3CBF90F69F8FC0_ui64,
			0x774606FDA2F72EC7_ui64, 0xC4684A43A15071A8_ui64, 0x83C230AA0AB78E9C_ui64, 0x30EC7C140910D1F3_ui64,
			0x86ACE348F355AADB_ui64, 0x3582AFF6F0F2F5B4_ui64, 0x7228D51F5B150A80_ui64, 0xC10699A158B255EF_ui64,
			0xFD7C20CC0CDAF4E8_ui64, 0x4E526C720F7DAB87_ui64, 0x09F8169BA49A54B3_ui64, 0xBAD65A25A73D0BDC_ui64,
			0x710D64410C4B16BD_ui64, 0xC22328FF0FEC49D2_ui64, 0x85895216A40BB6E6_ui64, 0x36A71EA8A7ACE989_ui64,
			0x0ADDA7C5F3C4488E_ui64, 0xB9F3EB7BF06317E1_ui64, 0xFE5991925B84E8D5_ui64, 0x4D77DD2C5823B7BA_ui64,
			0x64B62BCAEBC387A1_ui64, 0xD7986774E864D8CE_ui64, 0x90321D9D438327FA_ui64, 0x231C512340247895_ui64,
			0x1F66E84E144CD992_ui64, 0xAC48A4F017EB86FD_ui64, 0xEBE2DE19BC0C79C9_ui64, 0x58CC92A7BFAB26A6_ui64,
			0x9317ACC314DD3BC7_ui64, 0x2039E07D177A64A8_ui64, 0x67939A94BC9D9B9C_ui64, 0xD4BDD62ABF3AC4F3_ui64,
			0xE8C76F47EB5265F4_ui64, 0x5BE923F9E8F53A9B_ui64, 0x1C4359104312C5AF_ui64, 0xAF6D15AE40B59AC0_ui64,
			0x192D8AF2BAF0E1E8_ui64, 0xAA03C64CB957BE87_ui64, 0xEDA9BCA512B041B3_ui64, 0x5E87F01B11171EDC_ui64,
			0x62FD4976457FBFDB_ui64, 0xD1D305C846D8E0B4_ui64, 0x96797F21ED3F1F80_ui64, 0x2557339FEE9840EF_ui64,
			0xEE8C0DFB45EE5D8E_ui64, 0x5DA24145464902E1_ui64, 0x1A083BACEDAEFDD5_ui64, 0xA9267712EE09A2BA_ui64,
			0x955CCE7FBA6103BD_ui64, 0x267282C1B9C65CD2_ui64, 0x61D8F8281221A3E6_ui64, 0xD2F6B4961186FC89_ui64,
			0x9F8169BA49A54B33_ui64, 0x2CAF25044A02145C_ui64, 0x6B055FEDE1E5EB68_ui64, 0xD82B1353E242B407_ui64,
			0xE451AA3EB62A1500_ui64, 0x577FE680B58D4A6F_ui64, 0x10D59C691E6AB55B_ui64, 0xA3FBD0D71DCDEA34_ui64,
			0x6820EEB3B6BBF755_ui64, 0xDB0EA20DB51CA83A_ui64, 0x9CA4D8E41EFB570E_ui64, 0x2F8A945A1D5C0861_ui64,
			0x13F02D374934A966_ui64, 0xA0DE61894A93F609_ui64, 0xE7741B60E174093D_ui64, 0x545A57DEE2D35652_ui64,
			0xE21AC88218962D7A_ui64, 0x5134843C1B317215_ui64, 0x169EFED5B0D68D21_ui64, 0xA5B0B26BB371D24E_ui64,
			0x99CA0B06E7197349_ui64, 0x2AE447B8E4BE2C26_ui64, 0x6D4E3D514F59D312_ui64, 0xDE6071EF4CFE8C7D_ui64,
			0x15BB4F8BE788911C_ui64, 0xA6950335E42FCE73_ui64, 0xE13F79DC4FC83147_ui64, 0x521135624C6F6E28_ui64,
			0x6E6B8C0F1807CF2F_ui64, 0xDD45C0B11BA09040_ui64, 0x9AEFBA58B0476F74_ui64, 0x29C1F6E6B3E0301B_ui64,
			0xC96C5795D7870F42_ui64, 0x7A421B2BD420502D_ui64, 0x3DE861C27FC7AF19_ui64, 0x8EC62D7C7C60F076_ui64,
			0xB2BC941128085171_ui64, 0x0192D8AF2BAF0E1E_ui64, 0x4638A2468048F12A_ui64, 0xF516EEF883EFAE45_ui64,
			0x3ECDD09C2899B324_ui64, 0x8DE39C222B3EEC4B_ui64, 0xCA49E6CB80D9137F_ui64, 0x7967AA75837E4C10_ui64,
			0x451D1318D716ED17_ui64, 0xF6335FA6D4B1B278_ui64, 0xB199254F7F564D4C_ui64, 0x02B769F17CF11223_ui64,
			0xB4F7F6AD86B4690B_ui64, 0x07D9BA1385133664_ui64, 0x4073C0FA2EF4C950_ui64, 0xF35D8C442D53963F_ui64,
			0xCF273529793B3738_ui64, 0x7C0979977A9C6857_ui64, 0x3BA3037ED17B9763_ui64, 0x888D4FC0D2DCC80C_ui64,
			0x435671A479AAD56D_ui64, 0xF0783D1A7A0D8A02_ui64, 0xB7D247F3D1EA7536_ui64, 0x04FC0B4DD24D2A59_ui64,
			0x3886B22086258B5E_ui64, 0x8BA8FE9E8582D431_ui64, 0xCC0284772E652B05_ui64, 0x7F2CC8C92DC2746A_ui64,
			0x325B15E575E1C3D0_ui64, 0x8175595B76469CBF_ui64, 0xC6DF23B2DDA1638B_ui64, 0x75F16F0CDE063CE4_ui64,
			0x498BD6618A6E9DE3_ui64, 0xFAA59ADF89C9C28C_ui64, 0xBD0FE036222E3DB8_ui64, 0x0E21AC88218962D7_ui64,
			0xC5FA92EC8AFF7FB6_ui64, 0x76D4DE52895820D9_ui64, 0x317EA4BB22BFDFED_ui64, 0x8250E80521188082_ui64,
			0xBE2A516875702185_ui64, 0x0D041DD676D77EEA_ui64, 0x4AAE673FDD3081DE_ui64, 0xF9802B81DE97DEB1_ui64,
			0x4FC0B4DD24D2A599_ui64, 0xFCEEF8632775FAF6_ui64, 0xBB44828A8C9205C2_ui64, 0x086ACE348F355AAD_ui64,
			0x34107759DB5DFBAA_ui64, 0x873E3BE7D8FAA4C5_ui64, 0xC094410E731D5BF1_ui64, 0x73BA0DB070BA049E_ui64,
			0xB86133D4DBCC19FF_ui64, 0x0B4F7F6AD86B4690_ui64, 0x4CE50583738CB9A4_ui64, 0xFFCB493D702BE6CB_ui64,
			0xC3B1F050244347CC_ui64, 0x709FBCEE27E418A3_ui64, 0x3735C6078C03E797_ui64, 0x841B8AB98FA4B8F8_ui64,
			0xADDA7C5F3C4488E3_ui64, 0x1EF430E13FE3D78C_ui64, 0x595E4A08940428B8_ui64, 0xEA7006B697A377D7_ui64,
			0xD60ABFDBC3CBD6D0_ui64, 0x6524F365C06C89BF_ui64, 0x228E898C6B8B768B_ui64, 0x91A0C532682C29E4_ui64,
			0x5A7BFB56C35A3485_ui64, 0xE955B7E8C0FD6BEA_ui64, 0xAEFFCD016B1A94DE_ui64, 0x1DD181BF68BDCBB1_ui64,
			0x21AB38D23CD56AB6_ui64, 0x9285746C3F7235D9_ui64, 0xD52F0E859495CAED_ui64, 0x6601423B97329582_ui64,
			0xD041DD676D77EEAA_ui64, 0x636F91D96ED0B1C5_ui64, 0x24C5EB30C5374EF1_ui64, 0x97EBA78EC690119E_ui64,
			0xAB911EE392F8B099_ui64, 0x18BF525D915FEFF6_ui64, 0x5F1528B43AB810C2_ui64, 0xEC3B640A391F4FAD_ui64,
			0x27E05A6E926952CC_ui64, 0x94CE16D091CE0DA3_ui64, 0xD3646C393A29F297_ui64, 0x604A2087398EADF8_ui64,
			0x5C3099EA6DE60CFF_ui64, 0xEF1ED5546E415390_ui64, 0xA8B4AFBDC5A6ACA4_ui64, 0x1B9AE303C601F3CB_ui64,
			0x56ED3E2F9E224471_ui64, 0xE5C372919D851B1E_ui64, 0xA26908783662E42A_ui64, 0x114744C635C5BB45_ui64,
			0x2D3DFDAB61AD1A42_ui64, 0x9E13B115620A452D_ui64, 0xD9B9CBFCC9EDBA19_ui64, 0x6A978742CA4AE576_ui64,
			0xA14CB926613CF817_ui64, 0x1262F598629BA778_ui64, 0x55C88F71C97C584C_ui64, 0xE6E6C3CFCADB0723_ui64,
			0xDA9C7AA29EB3A624_ui64, 0x69B2361C9D14F94B_ui64, 0x2E184CF536F3067F_ui64, 0x9D36004B35545910_ui64,
			0x2B769F17CF112238_ui64, 0x9858D3A9CCB67D57_ui64, 0xDFF2A94067518263_ui64, 0x6CDCE5FE64F6DD0C_ui64,
			0x50A65C93309E7C0B_ui64, 0xE388102D33392364_ui64, 0xA4226AC498DEDC50_ui64, 0x170C267A9B79833F_ui64,
			0xDCD7181E300F9E5E_ui64, 0x6FF954A033A8C131_ui64, 0x28532E49984F3E05_ui64, 0x9B7D62F79BE8616A_ui64,
			0xA707DB9ACF80C06D_ui64, 0x14299724CC279F02_ui64, 0x5383EDCD67C06036_ui64, 0xE0ADA17364673F59_ui64,
		};

		static inline uint64_t soft_u8(const uint64_t p_context, const uint8_t p_new)
		{
			if constexpr(std::endian::native == std::endian::little)
			{
				return CRC64_table[static_cast<uint8_t>(p_context) ^ p_new] ^ (p_context >> 8);
			}
		}

		static inline uint64_t soft_u64(uint64_t p_context, const uint64_t p_new)
		{
			if constexpr(std::endian::native == std::endian::little)
			{
				p_context ^= p_new;
				p_context = CRC64_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
				p_context = CRC64_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
				p_context = CRC64_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
				p_context = CRC64_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
				p_context = CRC64_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
				p_context = CRC64_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
				p_context = CRC64_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
				return CRC64_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
			}
		}
	};

} //namespace

uint64_t CRC_64::trasform(uint64_t p_current, const std::span<const uint8_t> p_data)
{
	const uintptr_t			size  = p_data.size();
	const uint8_t*			pivot = p_data.data();
	const uint8_t* const	last  = pivot + size;

	{
		const uintptr_t off_align = align_t_mod<uint64_t>(pivot);
		if((alignof(uint64_t) - off_align) > size)
		{
			for(const uint8_t tpoint : p_data)
			{
				p_current = CRC64_Help::soft_u8(p_current, tpoint);
			}
			return p_current;
		}

		switch(off_align)
		{
		case 1:
			p_current = CRC64_Help::soft_u8(p_current, *pivot++);
			[[fallthrough]];
		case 2:
			p_current = CRC64_Help::soft_u8(p_current, *pivot++);
			[[fallthrough]];
		case 3:
			p_current = CRC64_Help::soft_u8(p_current, *pivot++);
			[[fallthrough]];
		case 4:
			p_current = CRC64_Help::soft_u8(p_current, *pivot++);
			[[fallthrough]];
		case 5:
			p_current = CRC64_Help::soft_u8(p_current, *pivot++);
			[[fallthrough]];
		case 6:
			p_current = CRC64_Help::soft_u8(p_current, *pivot++);
			[[fallthrough]];
		case 7:
			p_current = CRC64_Help::soft_u8(p_current, *pivot++);
			[[fallthrough]];
		default:
		case 0:
			break;
		}
	}

	for(; (last - pivot) >= 8; pivot += 8)
	{
		p_current = CRC64_Help::soft_u64(p_current, *reinterpret_cast<const uint32_t*>(pivot));
	}

	switch(last - pivot)
	{
	case 7:
		p_current = CRC64_Help::soft_u8(p_current, *pivot++);
		[[fallthrough]];
	case 6:
		p_current = CRC64_Help::soft_u8(p_current, *pivot++);
		[[fallthrough]];
	case 5:
		p_current = CRC64_Help::soft_u8(p_current, *pivot++);
		[[fallthrough]];
	case 4:
		p_current = CRC64_Help::soft_u8(p_current, *pivot++);
		[[fallthrough]];
	case 3:
		p_current = CRC64_Help::soft_u8(p_current, *pivot++);
		[[fallthrough]];
	case 2:
		p_current = CRC64_Help::soft_u8(p_current, *pivot++);
		[[fallthrough]];
	case 1:
		p_current = CRC64_Help::soft_u8(p_current, *pivot);
		[[fallthrough]];
	default:
	case 0:
		break;
	}

	return p_current;
}

uint64_t CRC_64::trasform(uint64_t p_current, const std::span<const uint64_t> p_data)
{
	for(const uint64_t tpoint : p_data)
	{
		p_current = CRC64_Help::soft_u64(p_current, tpoint);
	}
	return p_current;
}


} //namespace crypt
