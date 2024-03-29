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



#include <nil/actor/testing/test_case.hh>
#include <nil/actor/testing/thread_test_case.hh>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/curves/mnt4.hpp>
#include <nil/crypto3/algebra/curves/mnt6.hpp>

#include <nil/actor_blueprint/components/boolean/r1cs/disjunction.hpp>
#include <nil/actor_blueprint/components/boolean/r1cs/conjunction.hpp>
#include <nil/actor_blueprint/components/boolean/r1cs/comparison.hpp>
#include <nil/actor_blueprint/components/boolean/r1cs/inner_product.hpp>
#include <nil/actor_blueprint/components/detail/r1cs/loose_multiplexing.hpp>

#include <nil/actor_blueprint/blueprint/r1cs/detail/r1cs/blueprint_variable.hpp>
#include <nil/actor_blueprint/blueprint/r1cs/detail/r1cs/blueprint_linear_combination.hpp>

#include <nil/actor_blueprint/blueprint/r1cs/circuit.hpp>

using namespace nil;
using namespace nil::crypto3;
using namespace nil::actor::zk;
using namespace nil::crypto3::algebra;

template<typename FieldType>
void test_disjunction_component(size_t n) {
    actor::actor_blueprint::blueprint<FieldType> bp;
    actor::actor_blueprint::detail::blueprint_variable_vector<FieldType> inputs;
    inputs.allocate(bp, n);

    actor::actor_blueprint::detail::blueprint_variable_vector<FieldType> output;
    output.allocate(bp);

    actor::actor_blueprint::components::disjunction<FieldType> d(bp, inputs, output);
    d.generate_gates();

    for (std::size_t w = 0; w < 1ul << n; ++w) {
        for (std::size_t j = 0; j < n; ++j) {
            bp.val(inputs[j]) = typename FieldType::value_type((w & (1ul << j)) ? 1 : 0);
        }

        d.generate_assignments();

        BOOST_CHECK(bp.val(output) == (w ? FieldType::value_type::one() : FieldType::value_type::zero()));
        BOOST_CHECK(bp.is_satisfied());

        bp.val(output) = (w ? FieldType::value_type::zero() : FieldType::value_type::one());
        BOOST_CHECK(!bp.is_satisfied());
    }
}

template<typename FieldType>
void test_conjunction_component(size_t n) {
    actor::actor_blueprint::blueprint<FieldType> bp;
    actor::actor_blueprint::detail::blueprint_variable_vector<FieldType> inputs;
    inputs.allocate(bp, n);

    actor::actor_blueprint::detail::blueprint_variable<FieldType> output;
    output.allocate(bp);

    actor::actor_blueprint::components::conjunction<FieldType> c(bp, inputs, output);
    c.generate_gates();

    for (std::size_t w = 0; w < 1ul << n; ++w) {
        for (std::size_t j = 0; j < n; ++j) {
            bp.val(inputs[j]) = (w & (1ul << j)) ? FieldType::value_type::one() : FieldType::value_type::zero();
        }

        c.generate_assignments();

        BOOST_CHECK(bp.val(output) ==
                    (w == (1ul << n) - 1 ? FieldType::value_type::one() : FieldType::value_type::zero()));
        BOOST_CHECK(bp.is_satisfied());

        bp.val(output) = (w == (1ul << n) - 1 ? FieldType::value_type::zero() : FieldType::value_type::one());
        BOOST_CHECK(!bp.is_satisfied());
    }
}

template<typename FieldType>
void test_comparison_component(size_t n) {
    actor::actor_blueprint::blueprint<FieldType> bp;

    actor::actor_blueprint::detail::blueprint_variable<FieldType> A, B, less, less_or_eq;
    A.allocate(bp);
    B.allocate(bp);
    less.allocate(bp);
    less_or_eq.allocate(bp);

    actor::actor_blueprint::components::comparison<FieldType> cmp(bp, n, A, B, less, less_or_eq);
    cmp.generate_gates();

    for (std::size_t a = 0; a < 1ul << n; ++a) {
        for (std::size_t b = 0; b < 1ul << n; ++b) {
            bp.val(A) = typename FieldType::value_type(a);
            bp.val(B) = typename FieldType::value_type(b);

            cmp.generate_assignments();

            BOOST_CHECK(bp.val(less) == (a < b ? FieldType::value_type::one() : FieldType::value_type::zero()));
            BOOST_CHECK(bp.val(less_or_eq) == (a <= b ? FieldType::value_type::one() : FieldType::value_type::zero()));
            BOOST_CHECK(bp.is_satisfied());
        }
    }
}

template<typename FieldType>
void test_inner_product_component(size_t n) {
    actor::actor_blueprint::blueprint<FieldType> bp;
    actor::actor_blueprint::detail::blueprint_variable_vector<FieldType> A;
    A.allocate(bp, n);
    actor::actor_blueprint::detail::blueprint_variable_vector<FieldType> B;
    B.allocate(bp, n);

    actor::actor_blueprint::detail::blueprint_variable<FieldType> result;
    result.allocate(bp);

    actor::actor_blueprint::components::inner_product<FieldType> g(bp, A, B, result);
    g.generate_gates();

    for (std::size_t i = 0; i < 1ul << n; ++i) {
        for (std::size_t j = 0; j < 1ul << n; ++j) {
            std::size_t correct = 0;
            for (std::size_t k = 0; k < n; ++k) {
                bp.val(A[k]) = (i & (1ul << k) ? FieldType::value_type::one() : FieldType::value_type::zero());
                bp.val(B[k]) = (j & (1ul << k) ? FieldType::value_type::one() : FieldType::value_type::zero());
                correct += ((i & (1ul << k)) && (j & (1ul << k)) ? 1 : 0);
            }

            g.generate_assignments();

            BOOST_CHECK(bp.val(result) == typename FieldType::value_type(correct));
            BOOST_CHECK(bp.is_satisfied());

            bp.val(result) = typename FieldType::value_type(100 * n + 19);
            BOOST_CHECK(!bp.is_satisfied());
        }
    }
}

template<typename FieldType>
void test_loose_multiplexing_component(size_t n) {
    actor::actor_blueprint::blueprint<FieldType> bp;
    actor::actor_blueprint::detail::blueprint_variable_vector<FieldType> arr;
    arr.allocate(bp, 1ul << n);
    actor::actor_blueprint::detail::blueprint_variable<FieldType> index, result, success_flag;
    index.allocate(bp);
    result.allocate(bp);
    success_flag.allocate(bp);

    nil::crypto3::actor_blueprint::components::loose_multiplexing<FieldType> g(bp, arr, index, result, success_flag);
    g.generate_gates();

    for (std::size_t i = 0; i < 1ul << n; ++i) {
        bp.val(arr[i]) = typename FieldType::value_type((19 * i) % (1ul << n));
    }

    for (int idx = -1; idx <= (int)(1ul << n); ++idx) {

        bp.val(index) = typename FieldType::value_type(idx);
        g.generate_assignments();

        if (0 <= idx && idx <= (int)(1ul << n) - 1) {
            BOOST_CHECK(bp.val(result) == typename FieldType::value_type((19 * idx) % (1ul << n)));
            BOOST_CHECK(bp.val(success_flag) == FieldType::value_type::one());
            BOOST_CHECK(bp.is_satisfied());
            bp.val(result) -= FieldType::value_type::one();
            BOOST_CHECK(!bp.is_satisfied());
        } else {
            BOOST_CHECK(bp.val(success_flag) == FieldType::value_type::zero());
            BOOST_CHECK(bp.is_satisfied());
            bp.val(success_flag) = FieldType::value_type::one();
            BOOST_CHECK(!bp.is_satisfied());
        }
    }
}



ACTOR_THREAD_TEST_CASE(basic_components_disjunction_test) {
    std::cout << "Disjunction component test started" << std::endl;
    std::cout << "Started for bls12<381>" << std::endl;
    test_disjunction_component<fields::bls12<381>>(10);
    std::cout << "Started for mnt4<298>" << std::endl;
    test_disjunction_component<fields::mnt4<298>>(10);
    std::cout << "Started for mnt6<298>" << std::endl;
    test_disjunction_component<fields::mnt6<298>>(10);
}

ACTOR_THREAD_TEST_CASE(basic_components_conjunction_test) {
    std::cout << "Conjunction component test started" << std::endl;
    std::cout << "Started for bls12<381>" << std::endl;
    test_conjunction_component<fields::bls12<381>>(10);
    std::cout << "Started for mnt4<298>" << std::endl;
    test_conjunction_component<fields::mnt4<298>>(10);
    std::cout << "Started for mnt6<298>" << std::endl;
    test_conjunction_component<fields::mnt6<298>>(10);
}

ACTOR_THREAD_TEST_CASE(basic_components_comparison_test) {
    std::cout << "Comparison component test started" << std::endl;
    std::cout << "Started for bls12<381>" << std::endl;
    test_comparison_component<fields::bls12<381>>(5);
    std::cout << "Started for mnt4<298>" << std::endl;
    test_comparison_component<fields::mnt4<298>>(5);
    std::cout << "Started for mnt6<298>" << std::endl;
    test_comparison_component<fields::mnt6<298>>(5);
}

ACTOR_THREAD_TEST_CASE(basic_components_inner_product_test) {
    std::cout << "Inner product component test started" << std::endl;
    std::cout << "Started for bls12<381>" << std::endl;
    test_inner_product_component<fields::bls12<381>>(5);
    std::cout << "Started for mnt4<298>" << std::endl;
    test_inner_product_component<fields::mnt4<298>>(5);
    std::cout << "Started for mnt6<298>" << std::endl;
    test_inner_product_component<fields::mnt6<298>>(5);
}

ACTOR_THREAD_TEST_CASE(basic_components_loose_multiplexing_test) {
    std::cout << "Loose multiplexing component test started" << std::endl;
    std::cout << "Started for bls12<381>" << std::endl;
    test_loose_multiplexing_component<fields::bls12<381>>(5);
    std::cout << "Started for mnt4<298>" << std::endl;
    test_loose_multiplexing_component<fields::mnt4<298>>(5);
    std::cout << "Started for mnt6<298>" << std::endl;
    test_loose_multiplexing_component<fields::mnt6<298>>(5);
}


