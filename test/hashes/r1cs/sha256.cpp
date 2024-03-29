//---------------------------------------------------------------------------//
// Copyright (c) 2018-2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2020-2021 Nikita Kaskov <nbering@nil.foundation>
//
// MIT License
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//---------------------------------------------------------------------------//



#include <chrono>

#include <nil/actor/testing/test_case.hh>
#include <nil/actor/testing/thread_test_case.hh>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>
#include <nil/crypto3/algebra/curves/edwards.hpp>

#include "sha256.hpp"

using namespace nil::crypto3::algebra;
using namespace nil::crypto3;
using namespace nil::actor::zk;


ACTOR_THREAD_TEST_CASE(sha256_component_test_bls12_381_case) {
    std::cout << "Starting SHA256 component test for BLS12-381 ..." << std::endl;
    auto begin = std::chrono::high_resolution_clock::now();
    sha2_two_to_one_bp<typename curves::bls12<381>::scalar_field_type>();
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "SHA256 component test for BLS12-381 finished, time: " << elapsed.count() * 1e-9 << std::endl;
}

ACTOR_THREAD_TEST_CASE(sha256_component_test_mnt4_case) {
    std::cout << "Starting SHA256 component test for MNT4-298 ..." << std::endl;
    auto begin = std::chrono::high_resolution_clock::now();
    sha2_two_to_one_bp<typename curves::mnt4<298>::scalar_field_type>();
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "SHA256 component test for MNT4-298 finished, time: " << elapsed.count() * 1e-9 << std::endl;
}

ACTOR_THREAD_TEST_CASE(sha256_component_test_mnt6_case) {
    std::cout << "Starting SHA256 component test for MNT6-298 ..." << std::endl;
    auto begin = std::chrono::high_resolution_clock::now();
    sha2_two_to_one_bp<typename curves::mnt6<298>::scalar_field_type>();
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "SHA256 component test for MNT6-298 finished, time: " << elapsed.count() * 1e-9 << std::endl;
}

ACTOR_THREAD_TEST_CASE(sha256_component_test_edwards_183_case) {
    std::cout << "Starting SHA256 component test for Edwards-183 ..." << std::endl;
    auto begin = std::chrono::high_resolution_clock::now();
    sha2_two_to_one_bp<typename curves::edwards<183>::scalar_field_type>();
    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::nanoseconds>(end - begin);
    std::cout << "SHA256 component test for Edwards-183 finished, time: " << elapsed.count() * 1e-9 << std::endl;
}


