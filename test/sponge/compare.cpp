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

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/actor/zk/blueprint/plonk.hpp>
#include <nil/actor/zk/assignment/plonk.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/detail/compare.hpp>

#include "test_plonk_component.hpp"

using namespace nil::crypto3;



ACTOR_THREAD_TEST_CASE(blueprint_plonk_compare_0) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = crypto3::algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 3;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 5;
    using ArithmetizationParams = actor::zk::snark::plonk_arithmetization_params<WitnessColumns,
        PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = actor::zk::snark::plonk_constraint_system<BlueprintFieldType,
                ArithmetizationParams>;
    using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = actor::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = zk::components::compare_with_const<ArithmetizationType, curve_type, 0, 1, 2>;
    
    typename component_type::params_type params = {var(0, 0, false, var::column_type::public_input)};
    typename BlueprintFieldType::value_type value = nil::crypto3::algebra::random_element<BlueprintFieldType>();
    std::vector<typename BlueprintFieldType::value_type> public_input = {value};
    typename BlueprintFieldType::value_type result = 0;
    if (value < 0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui255) {
        result = 1;
    }

    auto result_check = [&result](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(result == assignment.var_value(real_res.output));
    };
    test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "compare with constant: " << duration.count() << "ms" << std::endl;
}

// ACTOR_THREAD_TEST_CASE(blueprint_plonk_compare_1) {
//     auto start = std::chrono::high_resolution_clock::now();

//     using curve_type = crypto3::algebra::curves::vesta;
//     using BlueprintFieldType = typename curve_type::base_field_type;
//     constexpr std::size_t WitnessColumns = 3;
//     constexpr std::size_t PublicInputColumns = 1;
//     constexpr std::size_t ConstantColumns = 1;
//     constexpr std::size_t SelectorColumns = 5;
//     using ArithmetizationParams = actor::zk::snark::plonk_arithmetization_params<WitnessColumns,
//         PublicInputColumns, ConstantColumns, SelectorColumns>;
//     using ArithmetizationType = actor::zk::snark::plonk_constraint_system<BlueprintFieldType,
//                 ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;

//     using var = actor::zk::snark::plonk_variable<BlueprintFieldType>;

//     using component_type = zk::components::compare_with_const<ArithmetizationType, curve_type, 0, 1, 2>;
    
//     typename component_type::params_type params = {var(0, 0, false, var::column_type::public_input)};
//     std::vector<typename BlueprintFieldType::value_type> public_input = {0x40000000000000000000000000000000224698fc094cf91b992d30ed00000001_cppui255};
//     typename BlueprintFieldType::value_type result = 0;

//     auto result_check = [&result](AssignmentType &assignment, 
//         component_type::result_type &real_res) {
//         assert(result == assignment.var_value(real_res.output));
//     };
//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

//     auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
//     std::cout << "compare with constant: " << duration.count() << "ms" << std::endl;
// }

// ACTOR_THREAD_TEST_CASE(blueprint_plonk_compare_to_fail) {
//     auto start = std::chrono::high_resolution_clock::now();

//     using curve_type = crypto3::algebra::curves::vesta;
//     using BlueprintFieldType = typename curve_type::base_field_type;
//     constexpr std::size_t WitnessColumns = 3;
//     constexpr std::size_t PublicInputColumns = 1;
//     constexpr std::size_t ConstantColumns = 1;
//     constexpr std::size_t SelectorColumns = 5;
//     using ArithmetizationParams = actor::zk::snark::plonk_arithmetization_params<WitnessColumns,
//         PublicInputColumns, ConstantColumns, SelectorColumns>;
//     using ArithmetizationType = actor::zk::snark::plonk_constraint_system<BlueprintFieldType,
//                 ArithmetizationParams>;
//     using AssignmentType = zk::blueprint_assignment_table<ArithmetizationType>;
//     using hash_type = nil::crypto3::hashes::keccak_1600<256>;
//     constexpr std::size_t Lambda = 40;

//     using var = actor::zk::snark::plonk_variable<BlueprintFieldType>;

//     using component_type = zk::components::compare_with_const<ArithmetizationType, curve_type, 0, 1, 2>;
    
//     typename component_type::params_type params = {var(0, 0, false, var::column_type::public_input)};
//     std::vector<typename BlueprintFieldType::value_type> public_input = {0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000_cppui255};
//     typename BlueprintFieldType::value_type result = 1;
    
//     auto result_check = [&result](AssignmentType &assignment, 
//         component_type::result_type &real_res) {
//         assert(result == assignment.var_value(real_res.output));
//     };
//     test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (params, public_input, result_check);

//     auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
//     std::cout << "compare with constant: " << duration.count() << "ms" << std::endl;
// }


