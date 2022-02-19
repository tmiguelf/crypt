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

#include <Crypt/hash/crc.hpp>

#include <array>
#include <bit>

#include <CoreLib/Core_Type.hpp>
#include <CoreLib/Core_Endian.hpp>
#include <CoreLib/Core_cpu.hpp>

#include <Crypt/utils.hpp>


#if defined(_M_AMD64) || defined(__amd64__)
#	include <nmmintrin.h>
#endif

namespace crypto
{

using core::literals::operator "" _ui32;
using core::literals::operator "" _ui64;
using core::literals::operator "" _uip;


template<typename IntT>
static constexpr IntT reflect(IntT p_in)
{
	IntT out = 0;
	for(uint8_t i = sizeof(p_in) * 8; i--;)
	{
		out |= (p_in & 1) << i; (p_in >>= 1);
	}
	return out;
}


static_assert(std::endian::native == std::endian::little, "Unsuported endianess");

template<typename IntT, bool Reciprocal>
static constexpr std::array<IntT, 256> gen_CRC_table(const IntT p_poly)
{
	std::array<IntT, 256> out{0};
	if constexpr (Reciprocal)
	{
		IntT rpoly = reflect<IntT>(p_poly);
		for(uint16_t i = 0; i < 256; ++i)
		{
			IntT r = static_cast<IntT>(i);
			for(uint8_t j = 0; j < 8; ++j)
			{
				if(r & 1)
				{
					r = (r >> 1) ^ rpoly;
				}
				else
				{
					r >>= 1;
				}
			}
			out[i] = r;
		}
	}
	else
	{
		constexpr uint8_t numBits = sizeof(IntT) * 8;
		constexpr IntT    signmask = IntT{1} << (numBits - 1);

		for(uint16_t i = 0; i < 256; ++i)
		{
			IntT r = static_cast<IntT>(i) << (numBits - 8);

			for(uint8_t j = 0; j < 8; ++j)
			{
				if(r & signmask)
				{
					r = (r << 1) ^ p_poly;
				}
				else
				{
					r <<= 1;
				}
			}

			out[i] = r;
		}
	}

	return out;
}

namespace
{
	template<typename UintT, UintT Poly, bool Reciprocal>
	struct CRC_Help
	{
	private:
		static constexpr uint8_t numBits = sizeof(UintT) * 8;
	public:
		static constexpr std::array<UintT, 256> CRC_table = gen_CRC_table<UintT, Reciprocal>(Poly);

		static inline UintT soft_byte(const UintT p_context, const uint8_t p_new)
		{
			if constexpr (std::endian::native == std::endian::little)
			{
				if constexpr (Reciprocal)
				{
					return CRC_table[static_cast<uint8_t>(p_context) ^ p_new] ^ (p_context >> 8);
				}
				else
				{
					constexpr uint8_t offset = (numBits - 8);
					return CRC_table[static_cast<uint8_t>(p_context >> offset) ^ p_new] ^ (p_context << 8);
				}
				
			}
			//else //TODO
		}

		static inline UintT soft_multi_byte(UintT p_context, const UintT p_new)
		{
			if constexpr (std::endian::native == std::endian::little)
			{
				if constexpr(Reciprocal)
				{
					p_context ^= p_new;
					for(uint8_t i = 0; i < (sizeof(UintT) - 1); ++i)
					{
						p_context = CRC_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
					}
					return CRC_table[static_cast<uint8_t>(p_context)] ^ (p_context >> 8);
				}
				else
				{
					constexpr uint8_t offset = (numBits - 8);
					p_context ^= core::endian_host2big(p_new);
					for(uint8_t i = 0; i < (sizeof(UintT) - 1); ++i)
					{
						p_context = CRC_table[static_cast<uint8_t>(p_context >> offset)] ^ (p_context << 8);
					}
					return CRC_table[static_cast<uint8_t>(p_context >> offset)] ^ (p_context << 8);
				}
			}
			//else //TODO
		}
	};

	struct CRC_32C_Help
	{
		static CRC_32C::digest_t trasform_u_soft(CRC_32C::digest_t p_current, const std::span<const uint8_t> p_data)
		{
			static_assert(std::is_same_v<CRC_32C::digest_t, uint32_t>);
			using CRC_Helper = CRC_Help<CRC_32C::digest_t, CRC_32C::poly, CRC_32C::reciprocal>;

			const uintptr_t			size  = p_data.size();
			const uint8_t*			pivot = p_data.data();
			const uint8_t* const	last  = pivot + size;

			{
				const uintptr_t off_align = align_t_mod<uint32_t>(pivot);
				if((alignof(uint32_t) - off_align) > size)
				{
					for(const uint8_t tpoint : p_data)
					{
						p_current = CRC_Helper::soft_byte(p_current, tpoint);
					}
					return p_current;
				}

				switch(off_align)
				{
				case 1:
					p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
					[[fallthrough]];
				case 2:
					p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
					[[fallthrough]];
				case 3:
					p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
					break;
				default:
				case 0:
					break;
				}
			}

			for(; (last - pivot) >= 4; pivot += 4)
			{
				p_current = CRC_Helper::soft_multi_byte(p_current, *reinterpret_cast<const uint32_t*>(pivot));
			}

			switch(last - pivot)
			{
			case 3:
				p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
				[[fallthrough]];
			case 2:
				p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
				[[fallthrough]];
			case 1:
				p_current = CRC_Helper::soft_byte(p_current, *pivot);
				break;
			default:
			case 0:
				break;
			}

			return p_current;
		}

		static CRC_32C::digest_t trasform_a_soft(CRC_32C::digest_t p_current, const std::span<const uint64_t> p_data)
		{
			static_assert(std::is_same_v<CRC_32C::digest_t, uint32_t>);
			using CRC_Helper = CRC_Help<CRC_32C::digest_t, CRC_32C::poly, CRC_32C::reciprocal>;
			for(const uint64_t tpoint : p_data)
			{
				p_current = CRC_Helper::soft_multi_byte(p_current, *reinterpret_cast<const uint32_t*>(&tpoint));
				p_current = CRC_Helper::soft_multi_byte(p_current, *(reinterpret_cast<const uint32_t*>(&tpoint) + 1));
			}
			return p_current;
		}

		
#if defined(_M_AMD64) || defined(__amd64__)
		static uint32_t trasform_u_intri(uint32_t p_current, const std::span<const uint8_t> p_data)
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
					p_current = _mm_crc32_u8(p_current, *(pivot++));
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
					p_current = _mm_crc32_u8(p_current, *(pivot++));
					p_current = _mm_crc32_u32(p_current, *reinterpret_cast<const uint32_t*>(pivot));
					pivot += 4;
					break;
				case 5:
					p_current = _mm_crc32_u8(p_current, *(pivot++));
					[[fallthrough]];
				case 6:
					p_current = _mm_crc32_u16(p_current, *reinterpret_cast<const uint16_t*>(pivot));
					pivot += 2;
					break;
				case 7:
					p_current = _mm_crc32_u8(p_current, *(pivot++));
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
				p_current = _mm_crc32_u8(p_current, *(pivot++));
				[[fallthrough]];
			case 6:
				p_current = _mm_crc32_u16(p_current, *reinterpret_cast<const uint16_t*>(pivot));
				pivot += 2;
				[[fallthrough]];
			case 4:
				p_current = _mm_crc32_u32(p_current, *reinterpret_cast<const uint32_t*>(pivot));
				break;
			case 5:
				p_current = _mm_crc32_u8(p_current, *(pivot++));
				p_current = _mm_crc32_u32(p_current, *reinterpret_cast<const uint32_t*>(pivot));
				break;
			case 3:
				p_current = _mm_crc32_u8(p_current, *(pivot++));
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

		static uint32_t trasform_a_intri(const uint32_t p_current, const std::span<const uint64_t> p_data)
		{
			uint64_t context64 = p_current;
			for(const uint64_t tpoint : p_data)
			{
				context64 = _mm_crc32_u64(context64, tpoint);
			}
			return static_cast<uint32_t>(context64);
		}


		using unaligned_cb_t = uint32_t (*)(uint32_t, const std::span<const uint8_t>);
		using aligned_cb_t =  uint32_t (*)(uint32_t, const std::span<const uint64_t>);

		static unaligned_cb_t const trasform_unaligned;// = core::amd64::CPU_feature_su::SSE42() ? trasform_u_intri : trasform_u_soft;
		static aligned_cb_t const   trasform_aligned;// = core::amd64::CPU_feature_su::SSE42() ? trasform_a_intri : trasform_a_soft;

#else
		static inline uint32_t trasform_unaligned(uint32_t p_current, const std::span<const uint8_t> p_data)
		{
			return trasform_u_soft(p_current, p_data);
		}

		static inline uint32_t trasform_aligned(const uint32_t p_current, const std::span<const uint64_t> p_data)
		{
			return trasform_a_soft(p_current, p_data);
		}
#endif
	};

#if defined(_M_AMD64) || defined(__amd64__)
	CRC_32C_Help::unaligned_cb_t const CRC_32C_Help::trasform_unaligned = core::amd64::CPU_feature_su::SSE42() ? CRC_32C_Help::trasform_u_intri : CRC_32C_Help::trasform_u_soft;
	CRC_32C_Help::aligned_cb_t const   CRC_32C_Help::trasform_aligned   = core::amd64::CPU_feature_su::SSE42() ? CRC_32C_Help::trasform_a_intri : CRC_32C_Help::trasform_a_soft;
#endif

} //namespace


uint32_t CRC_32C::trasform(uint32_t p_current, const std::span<const uint8_t> p_data)
{
	return CRC_32C_Help::trasform_unaligned(p_current, p_data);
}

uint32_t CRC_32C::trasform(const uint32_t p_current, const std::span<const uint64_t> p_data)
{
	return CRC_32C_Help::trasform_aligned(p_current, p_data);
}

CRC_64::digest_t CRC_64::trasform(digest_t p_current, const std::span<const uint8_t> p_data)
{
	static_assert(std::is_same_v<digest_t, uint64_t>);
	using CRC_Helper = CRC_Help<digest_t, poly, reciprocal>;

	const uintptr_t			size  = p_data.size();
	const uint8_t*			pivot = p_data.data();
	const uint8_t* const	last  = pivot + size;

	{
		const uintptr_t off_align = align_t_mod<uint64_t>(pivot);
		if((alignof(uint64_t) - off_align) > size)
		{
			for(const uint8_t tpoint : p_data)
			{
				p_current = CRC_Helper::soft_byte(p_current, tpoint);
			}
			return p_current;
		}

		switch(off_align)
		{
		case 1:
			p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
			[[fallthrough]];
		case 2:
			p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
			[[fallthrough]];
		case 3:
			p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
			[[fallthrough]];
		case 4:
			p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
			[[fallthrough]];
		case 5:
			p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
			[[fallthrough]];
		case 6:
			p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
			[[fallthrough]];
		case 7:
			p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
			[[fallthrough]];
		default:
		case 0:
			break;
		}
	}

	for(; (last - pivot) >= 8; pivot += 8)
	{
		p_current = CRC_Helper::soft_multi_byte(p_current, *reinterpret_cast<const uint64_t*>(pivot));
	}

	switch(last - pivot)
	{
	case 7:
		p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
		[[fallthrough]];
	case 6:
		p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
		[[fallthrough]];
	case 5:
		p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
		[[fallthrough]];
	case 4:
		p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
		[[fallthrough]];
	case 3:
		p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
		[[fallthrough]];
	case 2:
		p_current = CRC_Helper::soft_byte(p_current, *(pivot++));
		[[fallthrough]];
	case 1:
		p_current = CRC_Helper::soft_byte(p_current, *pivot);
		[[fallthrough]];
	default:
	case 0:
		break;
	}

	return p_current;
}

CRC_64::digest_t CRC_64::trasform(digest_t p_current, const std::span<const uint64_t> p_data)
{
	static_assert(std::is_same_v<digest_t, uint64_t>);
	using CRC_Helper = CRC_Help<digest_t, poly, reciprocal>;

	for(const uint64_t tpoint : p_data)
	{
		p_current = CRC_Helper::soft_multi_byte(p_current, tpoint);
	}
	return p_current;
}

} //namespace crypt
