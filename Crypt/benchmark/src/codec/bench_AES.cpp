//======== ======== ======== ======== ======== ======== ======== ========
///	\file
///
///	\copyright
///		Copyright (c) Tiago Miguel Oliveira Freire
///
///		Permission is hereby granted, free of charge, to any person obtaining a copy
///		of this software and associated documentation files (the "Software"),
///		to copy, modify, publish, and/or distribute copies of the Software,
///		and to permit persons to whom the Software is furnished to do so,
///		subject to the following conditions:
///
///		The copyright notice and this permission notice shall be included in all
///		copies or substantial portions of the Software.
///		The copyrighted work, or derived works, shall not be used to train
///		Artificial Intelligence models of any sort; or otherwise be used in a
///		transformative way that could obfuscate the source of the copyright.
///
///		THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
///		IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
///		FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
///		AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
///		LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
///		OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
///		SOFTWARE.
//======== ======== ======== ======== ======== ======== ======== ========

#include <array>
#include <cstdint>

#include <benchmark/benchmark.h>

#include <Crypt/codec/AES.hpp>

constexpr std::array<uint8_t, 32> test_key =
{
	0x00,
	0x01,
	0x02,
	0x03,
	0x04,
	0x05,
	0x06,
	0x07,
	0x08,
	0x09,
	0x0a,
	0x0b,
	0x0c,
	0x0d,
	0x0e,
	0x0f,
	0x10,
	0x11,
	0x12,
	0x13,
	0x14,
	0x15,
	0x16,
	0x17,
	0x18,
	0x19,
	0x1a,
	0x1b,
	0x1c,
	0x1d,
	0x1e,
	0x1f,
};

constexpr std::array<uint8_t, 16> test_data =
{
	0x00,
	0x11,
	0x22,
	0x33,
	0x44,
	0x55,
	0x66,
	0x77,
	0x88,
	0x99,
	0xaa,
	0xbb,
	0xcc,
	0xdd,
	0xee,
	0xff,
};

constexpr std::array<uint8_t, 16> test_result =
{
	0x8e,
	0xa2,
	0xb7,
	0xca,
	0x51,
	0x67,
	0x45,
	0xbf,
	0xea,
	0xfc,
	0x49,
	0x90,
	0x4b,
	0x49,
	0x60,
	0x89,
};

static inline void AES256_encode(benchmark::State& state)
{
	using AES_t = crypto::AES_256;

	constexpr uintptr_t block_lenght = AES_t::block_lenght;
	AES_t::key_schedule_t tkey_schedule;
	AES_t::make_key_schedule(test_key, tkey_schedule);

	for (auto _ : state)
	{
		std::array<uint8_t, block_lenght> decoded;
		AES_t::encode(
			tkey_schedule,
			test_data,
			decoded);
		benchmark::DoNotOptimize(decoded);
	}
}

static inline void AES256_decode(benchmark::State& state)
{
	using AES_t = crypto::AES_256;

	constexpr uintptr_t block_lenght = AES_t::block_lenght;
	for (auto _ : state)
	{
		AES_t::key_schedule_t tkey_schedule;
		AES_t::make_key_schedule(test_key, tkey_schedule);

		std::array<uint8_t, block_lenght> encoded;
		AES_t::decode(
			tkey_schedule,
			test_result,
			encoded);

		std::array<uint8_t, block_lenght> decoded;

		AES_t::decode(tkey_schedule, encoded, decoded);
		benchmark::DoNotOptimize(decoded);
	}
}

BENCHMARK(AES256_encode);
BENCHMARK(AES256_decode);
