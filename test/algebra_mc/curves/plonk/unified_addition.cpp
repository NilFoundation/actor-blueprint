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

#include <nil/crypto3/algebra/curves/vesta.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/vesta.hpp>
#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>
#include <nil/crypto3/random/algebraic_engine.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/params.hpp>

#include <nil/actor_blueprint/blueprint/plonk/circuit.hpp>
#include <nil/actor_blueprint/blueprint/plonk/assignment.hpp>
#include <nil/actor_blueprint/components/algebra/curves/pasta/plonk/unified_addition.hpp>

#include <nil/actor_blueprint_mc/blueprint/plonk.hpp>
#include <nil/actor_blueprint_mc/assignment/plonk.hpp>
#include <nil/actor_blueprint_mc/components/algebra/curves/pasta/plonk/unified_addition.hpp>

#include "../../../test_plonk_component.hpp"
#include "../../../test_plonk_component_mc.hpp"

using namespace nil;

template <typename CurveType>
void test_unified_addition(std::vector<typename CurveType::base_field_type::value_type> public_input,
    typename CurveType::template g1_type<crypto3::algebra::curves::coordinates::affine>::value_type expected_res){
    
    using curve_type = CurveType;
    using BlueprintFieldType = typename curve_type::base_field_type;

    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        actor::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = actor_blueprint::assignment<ArithmetizationType>;
    using hash_type = crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = actor::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = actor_blueprint::components::unified_addition<ArithmetizationType, curve_type, 11>;

    typename component_type::input_type instance_input = {
        {var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)},
        {var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)}};

    auto result_check = [&expected_res, public_input](AssignmentType &assignment, 
        typename component_type::result_type &real_res) {
        #ifdef BLUEPRINT_PLONK_PROFILING_ENABLED
        std::cout << "unified_addition test: " << "\n";
        std::cout << "input   : " << public_input[0].data << " " << public_input[1].data << "\n"; 
        std::cout << "input   : " << public_input[2].data << " " << public_input[3].data << "\n"; 
        std::cout << "expected: " << expected_res.X.data << " " << expected_res.Y.data << "\n";
        std::cout << "real    : " << var_value(assignment, real_res.X).data << " " << var_value(assignment, real_res.Y).data << "\n\n";
        #endif
        assert(expected_res.X == var_value(assignment, real_res.X));
        assert(expected_res.Y == var_value(assignment, real_res.Y));
    };

    component_type component_instance({0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10},{},{});

    actor::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(
        component_instance, public_input, result_check, instance_input);
}

template<typename CurveType>
void test_unified_addition_with_zeroes() {
    nil::crypto3::random::algebraic_engine<typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> generate_random_point;
    boost::random::mt19937 seed_seq;
    generate_random_point.seed(seed_seq);

    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type zero_algebraic = {0, 1};
    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type zero_circuits  = {0, 0};
    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P = generate_random_point();
    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type Q = -P;

    std::vector<typename CurveType::base_field_type::value_type> public_input;

    public_input = {zero_circuits.X, zero_circuits.Y, zero_circuits.X, zero_circuits.Y};
    test_unified_addition<CurveType>(public_input, zero_circuits);

    public_input = {zero_circuits.X, zero_circuits.Y, P.X, P.Y};
    test_unified_addition<CurveType>(public_input, P);

    public_input = {P.X, P.Y, zero_circuits.X, zero_circuits.Y};
    test_unified_addition<CurveType>(public_input, P);

    public_input = {P.X, P.Y, Q.X, Q.Y};
    test_unified_addition<CurveType>(public_input, zero_circuits);

    public_input = {Q.X, Q.Y, P.X, P.Y};
    test_unified_addition<CurveType>(public_input, zero_circuits);
}

template<typename CurveType>
void test_unified_addition_doubling() {
    nil::crypto3::random::algebraic_engine<typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> generate_random_point;
    boost::random::mt19937 seed_seq;
    generate_random_point.seed(seed_seq);

    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P = generate_random_point();
    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type Q(P);

    std::vector<typename CurveType::base_field_type::value_type> public_input;

    public_input = {P.X, P.Y, Q.X, Q.Y};
    test_unified_addition<CurveType>(public_input, P+Q);

    public_input = {Q.X, Q.Y, P.X, P.Y};
    test_unified_addition<CurveType>(public_input, P+Q);
}

template<typename CurveType, std::size_t RandomTestsAmount>
void test_unified_addition_random_data() {
    nil::crypto3::random::algebraic_engine<typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>> generate_random_point;
    boost::random::mt19937 seed_seq;
    generate_random_point.seed(seed_seq);

    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type P = generate_random_point();
    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type Q = generate_random_point();
    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type zero = {0, 0};
    typename CurveType::template g1_type<nil::crypto3::algebra::curves::coordinates::affine>::value_type expected_res;

    std::vector<typename CurveType::base_field_type::value_type> public_input;

    for (std::size_t i = 0; i < RandomTestsAmount; i++){
        P = generate_random_point();
        Q = generate_random_point();
        
        if (Q.X == zero.X && Q.Y == zero.Y) {
            expected_res = P;
        } else {
            if (P.X == zero.X && P.Y == zero.Y) {
                expected_res = Q;
            } else {
                if (P.X == Q.X && P.Y == -Q.Y) {
                    expected_res = {0, 0};
                } else {
                    expected_res = P + Q;
                }
            }
        }

        public_input = {P.X, P.Y, Q.X, Q.Y};
        test_unified_addition<CurveType>(public_input, expected_res);
    }
}


constexpr static const std::size_t random_tests_amount = 10;



ACTOR_THREAD_TEST_CASE(blueprint_plonk_unified_addition_pallas) {
    using curve_type = crypto3::algebra::curves::pallas;
    test_unified_addition_with_zeroes<curve_type>();
    test_unified_addition_doubling<curve_type>();
    test_unified_addition_random_data<curve_type, random_tests_amount>();
}

ACTOR_THREAD_TEST_CASE(blueprint_plonk_unified_addition_vesta) {
    using curve_type = crypto3::algebra::curves::vesta;
    test_unified_addition_with_zeroes<curve_type>();
    test_unified_addition_doubling<curve_type>();
    test_unified_addition_random_data<curve_type, random_tests_amount>();
}





using namespace nil::crypto3;
ACTOR_THREAD_TEST_CASE(blueprint_mc_plonk_unified_addition_double) {

    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 0;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        actor::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::actor_blueprint_mc::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = actor::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = nil::actor_blueprint_mc::components::curve_element_unified_addition<ArithmetizationType, curve_type, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8, 9, 10>;

    auto P = algebra::random_element<curve_type::template g1_type<>>().to_affine();
    auto Q(P);

    typename component_type::params_type params = {
        {var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)},
        {var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)}};

    std::vector<typename BlueprintFieldType::value_type> public_input = {P.X, P.Y, Q.X, Q.Y};

    typename curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type expected_res = P + Q;

    auto result_check = [&expected_res](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(expected_res.X == assignment.var_value(real_res.X));
        assert(expected_res.Y == assignment.var_value(real_res.Y));
    };

    nil::actor_blueprint_mc::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "unified_addition: " << duration.count() << "ms" << std::endl;
}

ACTOR_THREAD_TEST_CASE(blueprint_mc_plonk_unified_addition_addition) {
    auto start = std::chrono::high_resolution_clock::now();

    using curve_type = algebra::curves::pallas;
    using BlueprintFieldType = typename curve_type::base_field_type;
    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;
    using ArithmetizationParams =
        actor::zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using ArithmetizationType = actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
    using AssignmentType = nil::actor_blueprint_mc::blueprint_assignment_table<ArithmetizationType>;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 40;

    using var = actor::zk::snark::plonk_variable<BlueprintFieldType>;

    using component_type = nil::actor_blueprint_mc::components::curve_element_unified_addition<ArithmetizationType, curve_type, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8, 9, 10>;

    auto P = algebra::random_element<curve_type::template g1_type<>>().to_affine();
    auto Q = algebra::random_element<curve_type::template g1_type<>>().to_affine();
    typename curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type zero = {0, 0};
    typename curve_type::template g1_type<algebra::curves::coordinates::affine>::value_type expected_res;
    P.X = Q.X;
    P.Y = -Q.Y;
    if (Q.X == zero.X && Q.Y == zero.Y) {
        expected_res = P;
    } else {
        if (P.X == zero.X && P.Y == zero.Y) {
            expected_res = Q;
        } else {
            if (P.X == Q.X && P.Y == -Q.Y) {
                expected_res = {0, 0};
            } else {
                expected_res = P + Q;
            }
        }
    }
    typename component_type::params_type params = {
        {var(0, 0, false, var::column_type::public_input), var(0, 1, false, var::column_type::public_input)},
        {var(0, 2, false, var::column_type::public_input), var(0, 3, false, var::column_type::public_input)}};

    std::vector<typename BlueprintFieldType::value_type> public_input = {P.X, P.Y, Q.X, Q.Y};

    auto result_check = [&expected_res](AssignmentType &assignment, 
        component_type::result_type &real_res) {
        assert(expected_res.X == assignment.var_value(real_res.X));
        assert(expected_res.Y == assignment.var_value(real_res.Y));
    };

    nil::actor_blueprint_mc::test_component<component_type, BlueprintFieldType, ArithmetizationParams, hash_type, Lambda>(params, public_input, result_check);

    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::high_resolution_clock::now() - start);
    std::cout << "unified_addition: " << duration.count() << "ms" << std::endl;
}
