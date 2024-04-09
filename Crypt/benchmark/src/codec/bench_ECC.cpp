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
#include <cstring>

#include <benchmark/benchmark.h>

#include <Crypt/codec/ECC.hpp>


static inline void Ed25519_compute(benchmark::State& state)
{
	crypto::Ed25519::key_t t_key;

	memset(t_key.data(), 0xFF, t_key.size());
	t_key[31] = 0x0F;

	for (auto _ : state)
	{
		crypto::Ed25519::point_t pkey;
		crypto::Ed25519::public_key(t_key, pkey);
		benchmark::DoNotOptimize(pkey);
	}
}

BENCHMARK(Ed25519_compute);


static inline void Ed521_compute(benchmark::State& state)
{
	crypto::Ed521::key_t t_key;

	memset(t_key.data(), 0xFF, t_key.size());
	t_key[65] = 0x00;
	t_key[64] = 0x0F;

	for (auto _ : state)
	{
		crypto::Ed521::point_t pkey;
		crypto::Ed521::public_key(t_key, pkey);
		benchmark::DoNotOptimize(pkey);
	}
}

BENCHMARK(Ed521_compute);
