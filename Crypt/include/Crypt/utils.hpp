#pragma once
#include <cstdint>
#include <bit>

namespace Crypt
{
	template<uintptr_t Alignment> //requires (std::popcount(Alignment) == 1)
	inline uintptr_t align_mod(const void* const p_data)
	{
		constexpr uintptr_t mask = Alignment - 1;
		return reinterpret_cast<const uintptr_t>(p_data) & mask;
	}

	template<typename T>
	inline uintptr_t align_t_mod(const void* const p_data)
	{
		return align_mod<alignof(T)>(p_data);
	}
} //namespace crypt
