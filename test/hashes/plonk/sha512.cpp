//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/hash/keccak.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/actor_blueprint/blueprint/plonk/circuit.hpp>
#include <nil/actor_blueprint/blueprint/plonk/assignment.hpp>
#include <nil/actor_blueprint/components/hashes/sha256/plonk/sha512.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/ed25519.hpp>

#include "../../test_plonk_component.hpp"

using namespace nil;

template <typename BlueprintFieldType>
void test_sha512(std::vector<typename BlueprintFieldType::value_type> public_input){

    constexpr std::size_t WitnessColumns = 9;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 5;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    using ArithmetizationParams =
        actor::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = actor::actor_blueprint::assignment<ArithmetizationType>;

    using component_type = actor::actor_blueprint::components::sha512<ArithmetizationType, 9>;
    
    using var = actor::zk::snark::plonk_variable<BlueprintFieldType>;


    std::array<var, 4> e_R_x = {
        var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input),
        var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)};
    std::array<var, 4> e_R_y = {
        var(0, 4, false, var::column_type::public_input), var(0, 5, false, var::column_type::public_input),
        var(0, 6, false, var::column_type::public_input), var(0, 7, false, var::column_type::public_input)};
    std::array<var, 4> pk_x = {
        var(0, 8, false, var::column_type::public_input), var(0, 9, false, var::column_type::public_input),
        var(0, 10, false, var::column_type::public_input), var(0, 11, false, var::column_type::public_input)};
    std::array<var, 4> pk_y = {
        var(0, 12, false, var::column_type::public_input), var(0, 13, false, var::column_type::public_input),
        var(0, 14, false, var::column_type::public_input), var(0, 15, false, var::column_type::public_input)};
    std::array<var, 4> M = {
        var(0, 16, false, var::column_type::public_input), var(0, 17, false, var::column_type::public_input),
        var(0, 18, false, var::column_type::public_input), var(0, 19, false, var::column_type::public_input)};
    typename component_type::input_type instance_input = {{e_R_x, e_R_y}, {pk_x, pk_y}, M};


    auto result_check = [](AssignmentType &assignment, 
	    typename component_type::result_type &real_res) {};

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8},{0},{});
	
    nil::actor::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda> (component_instance, public_input, result_check, instance_input);
}



ACTOR_THREAD_TEST_CASE(blueprint_plonk_sha512) {
    using curve_type = crypto3::algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;

    using ed25519_type = crypto3::algebra::curves::ed25519;

    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type B =
        ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type::one();
    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type R = 2 * B;
    ed25519_type::scalar_field_type::value_type b = crypto3::algebra::random_element<ed25519_type::scalar_field_type>();
    ed25519_type::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type T = b * R;

    ed25519_type::base_field_type::integral_type Tx = ed25519_type::base_field_type::integral_type(T.X.data);
    ed25519_type::base_field_type::integral_type Ty = ed25519_type::base_field_type::integral_type(T.Y.data);
    ed25519_type::base_field_type::integral_type Rx = ed25519_type::base_field_type::integral_type(R.X.data);
    ed25519_type::base_field_type::integral_type Ry = ed25519_type::base_field_type::integral_type(R.Y.data);
    typename ed25519_type::base_field_type::integral_type base = 1;
    typename ed25519_type::base_field_type::integral_type mask = (base << 66) - 1;
    std::vector<typename BlueprintFieldType::value_type> public_input = {Tx & mask,
                                                                         (Tx >> 66) & mask,
                                                                         (Tx >> 132) & mask,
                                                                         (Tx >> 198) & (mask >> 9),
                                                                         Ty & mask,
                                                                         (Ty >> 66) & mask,
                                                                         (Ty >> 132) & mask,
                                                                         (Ty >> 198) & (mask >> 9),
                                                                         Rx & mask,
                                                                         (Rx >> 66) & mask,
                                                                         (Rx >> 132) & mask,
                                                                         (Rx >> 198) & (mask >> 9),
                                                                         Ry & mask,
                                                                         (Ry >> 66) & mask,
                                                                         (Ry >> 132) & mask,
                                                                         (Ry >> 198) & (mask >> 9),
                                                                         mask,
                                                                         mask,
                                                                         mask,
                                                                         (mask >> 8)};
    

    test_sha512<BlueprintFieldType>(public_input);
}


