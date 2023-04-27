//---------------------------------------------------------------------------//
// Copyright (c) 2022 Polina Chernyshova <pockvokhbtra@nil.foundation>
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

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/actor_blueprint/blueprint/plonk/circuit.hpp>
#include <nil/actor_blueprint/blueprint/plonk/assignment.hpp>
#include <nil/actor_blueprint/components/algebra/curves/edwards/plonk/non_native/scalar_non_native_range.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType>
void test_scalar_non_native_range(std::vector<typename BlueprintFieldType::value_type> public_input){
    
    using ed25519_type = crypto3::algebra::curves::ed25519;
    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 2;
    using ArithmetizationParams =
        actor::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = actor::actor_blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using var = actor::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = actor::actor_blueprint::components::scalar_non_native_range<ArithmetizationType,
        ed25519_type, 9>;

    typename component_type::input_type instance_input = {var(0, 0, false, var::column_type::public_input)};

    auto result_check = [public_input](AssignmentType &assignment,
        typename component_type::result_type &real_res) {
            #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
            std::cout << std::hex << "________________________________________________________________________________________\ninput: " << public_input[0].data << std::endl;
            #endif
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{},{});

    actor::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

constexpr static const std::size_t random_tests_amount = 10;



ACTOR_THREAD_TEST_CASE(blueprint_non_native_scalar_range_test0) {
    test_scalar_non_native_range<typename crypto3::algebra::curves::pallas::base_field_type>(
        {45524});
}

ACTOR_THREAD_TEST_CASE(blueprint_non_native_scalar_range_test1) {
    using field_type = typename crypto3::algebra::curves::pallas::base_field_type;


    typename field_type::integral_type ed25519_scalar_modulus = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed_cppui255;
    typename field_type::value_type ones =                      0x0fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff_cppui255;

    test_scalar_non_native_range<field_type>(
        {typename field_type::value_type(ed25519_scalar_modulus-1)});

    test_scalar_non_native_range<field_type>(
        {typename field_type::value_type(ones)});

    test_scalar_non_native_range<field_type>({1});

    test_scalar_non_native_range<field_type>({0});

    nil::crypto3::random::algebraic_engine<field_type> rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);


    typename field_type::value_type r;
    typename field_type::integral_type r_integral;

    for (std::size_t i = 0; i < random_tests_amount; i++) {
        r = rand();
        r_integral = typename field_type::integral_type(r.data);
        r_integral = r_integral % ed25519_scalar_modulus;
        r = typename field_type::value_type(r_integral);
        test_scalar_non_native_range<field_type>({r});
    }
}

ACTOR_THREAD_TEST_CASE(blueprint_non_native_scalar_range_test_must_fail) {
    using field_type = crypto3::algebra::curves::pallas::base_field_type;

    nil::crypto3::random::algebraic_engine<field_type> rand;
    boost::random::mt19937 seed_seq;
    rand.seed(seed_seq);

    typename field_type::integral_type ed25519_scalar_modulus = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed_cppui255;
    typename field_type::integral_type zero = 0;
    typename field_type::integral_type ed25519_scalar_overage = zero - ed25519_scalar_modulus - 1;

    typename field_type::integral_type overage;

    for (std::size_t i = 0; i < random_tests_amount; i++) {
        overage = (typename field_type::integral_type(rand().data)) % ed25519_scalar_overage;
        test_scalar_non_native_range<field_type>({typename field_type::value_type(ed25519_scalar_modulus + overage)});
    }
    test_scalar_non_native_range<field_type>({-1});
}


