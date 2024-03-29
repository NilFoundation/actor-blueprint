//---------------------------------------------------------------------------//
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/actor_blueprint/components/algebra/fields/plonk/range_check.hpp>

#include <nil/actor_blueprint/blueprint/plonk/circuit.hpp>
#include <nil/actor_blueprint/blueprint/plonk/assignment.hpp>
#include "../../../test_plonk_component.hpp"

template <typename BlueprintFieldType>
auto test_range_check_inner(std::vector<typename BlueprintFieldType::value_type> public_input){
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    constexpr std::size_t R = 64;
    using ArithmetizationParams = nil::actor::zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::actor::actor_blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using component_type = nil::actor::actor_blueprint::components::range_check<ArithmetizationType, R, 15>;
	using var = nil::actor::zk::snark::plonk_variable<BlueprintFieldType>;

    var x(0, 0, false, var::column_type::public_input);

    typename component_type::input_type instance_input = {x};

    #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
    std::cout << "range_check_test_input: " << std::hex << public_input[0].data << "\n";
    #endif

    auto result_check = [](AssignmentType &assignment, 
	    typename component_type::result_type &real_res) {
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},{0},{0});

    return std::make_tuple(component_instance, instance_input, result_check);
}

template <typename BlueprintFieldType>
void test_range_check(std::vector<typename BlueprintFieldType::value_type> public_input){
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    constexpr std::size_t R = 64;
    using ArithmetizationParams = nil::actor::zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::actor::actor_blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using component_type = nil::actor::actor_blueprint::components::range_check<ArithmetizationType, R, 15>;

    auto [component_instance, instance_input, result_check] = test_range_check_inner<BlueprintFieldType>(public_input);

	nil::actor::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>
        (component_instance, public_input, result_check, instance_input);
}

template <typename BlueprintFieldType>
void test_range_check_to_fail(std::vector<typename BlueprintFieldType::value_type> public_input){
    constexpr std::size_t WitnessColumns = 15;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    constexpr std::size_t R = 64;
    using ArithmetizationParams = nil::actor::zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = nil::actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::actor::actor_blueprint::assignment<ArithmetizationType>;
	using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using component_type = nil::actor::actor_blueprint::components::range_check<ArithmetizationType, R, 15>;
	
    auto [component_instance, instance_input, result_check] = test_range_check_inner<BlueprintFieldType>(public_input);

    nil::actor::test_component_to_fail<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>
        (component_instance, public_input, result_check, instance_input);
}

template<typename FieldType>
void test_range_check_specific_inputs(){
    test_range_check<FieldType>({0});
    test_range_check<FieldType>({1});
    test_range_check<FieldType>({35000});
    test_range_check<FieldType>({0xFFFFFFFFFFFFFFFF_cppui256});
}

template<typename FieldType, std::size_t RandomTestsAmount>
void test_range_check_random_inputs(){

    nil::crypto3::random::algebraic_engine<FieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        typename FieldType::value_type input = generate_random();
    	typename FieldType::integral_type input_integral = typename FieldType::integral_type(input.data);
        input_integral = input_integral & 0xFFFFFFFFFFFFFFFF_cppui255;
    	typename FieldType::value_type input_scalar =  input_integral;
        test_range_check<FieldType>({input_scalar});
	}
}

constexpr static const std::size_t random_tests_amount = 10;

ACTOR_THREAD_TEST_CASE(blueprint_plonk_fields_range_check_bls12) {
    using field_type = nil::crypto3::algebra::fields::bls12_fr<381>;
    test_range_check_specific_inputs<field_type>();
    test_range_check_random_inputs<field_type, random_tests_amount>();
}

ACTOR_THREAD_TEST_CASE(blueprint_plonk_fields_range_check_pallas) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_range_check_specific_inputs<field_type>();
    test_range_check_random_inputs<field_type, random_tests_amount>();
}

ACTOR_THREAD_TEST_CASE(blueprint_plonk_fields_range_check_vesta) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_specific_inputs<field_type>();
    test_range_check_random_inputs<field_type, random_tests_amount>();
}



template<typename FieldType>
void test_range_check_fail_specific_inputs(){
    test_range_check_to_fail<FieldType>({-1});
    test_range_check_to_fail<FieldType>({0x10000000000000000_cppui256});
    test_range_check_to_fail<FieldType>({0x4000000000000000000000000000000000000000000000000000000000000000_cppui256});
}

template<typename FieldType, std::size_t RandomTestsAmount>
void test_range_check_fail_random_inputs(){

    nil::crypto3::random::algebraic_engine<FieldType> generate_random;
    boost::random::mt19937 seed_seq;
    generate_random.seed(seed_seq);

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        typename FieldType::value_type input = generate_random();
        if (input < 0x10000000000000000_cppui255) {
            continue;
        }
    	typename FieldType::integral_type input_integral = typename FieldType::integral_type(input.data);
    	typename FieldType::value_type input_scalar =  input_integral;
        test_range_check_to_fail<FieldType>({input_scalar});
	}
}



ACTOR_THREAD_TEST_CASE(blueprint_plonk_fields_range_check_fail_bls12) {
    using field_type = nil::crypto3::algebra::fields::bls12_fr<381>;
    test_range_check_fail_specific_inputs<field_type>();
    test_range_check_fail_random_inputs<field_type, random_tests_amount>();
}

ACTOR_THREAD_TEST_CASE(blueprint_plonk_fields_range_check_fail_pallas) {
    using field_type = nil::crypto3::algebra::curves::pallas::scalar_field_type;
    test_range_check_fail_specific_inputs<field_type>();
    test_range_check_fail_random_inputs<field_type, random_tests_amount>();
}

ACTOR_THREAD_TEST_CASE(blueprint_plonk_fields_range_check_fail_vesta) {
    using field_type = nil::crypto3::algebra::curves::vesta::scalar_field_type;
    test_range_check_fail_specific_inputs<field_type>();
    test_range_check_fail_random_inputs<field_type, random_tests_amount>();
}

