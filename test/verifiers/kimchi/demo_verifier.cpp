//---------------------------------------------------------------------------//
// Copyright (c) 2021-2022 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021-2022 Nikita Kaskov <nbering@nil.foundation>
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

#define BOOST_TEST_MODULE blueprint_plonk_kimchi_basic_verifier_test

#include <boost/test/unit_test.hpp>
#include <fstream>

#include <nil/crypto3/algebra/curves/pallas.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/pallas.hpp>
#include <nil/crypto3/algebra/random_element.hpp>

#include <nil/crypto3/math/algorithms/calculate_domain_set.hpp>

#include <nil/crypto3/hash/algorithm/hash.hpp>
#include <nil/crypto3/hash/sha2.hpp>
#include <nil/crypto3/hash/keccak.hpp>

#include <nil/actor/zk/commitments/polynomial/lpc.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/params.hpp>
#include <nil/actor/zk/snark/systems/plonk/pickles/proof.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/proof.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/prover.hpp>
#include <nil/actor/zk/snark/systems/plonk/placeholder/verifier.hpp>

#include <nil/actor/zk/blueprint/plonk.hpp>
#include <nil/actor/zk/assignment/plonk.hpp>
#include <nil/actor/zk/algorithms/allocate.hpp>
#include <nil/actor/zk/algorithms/generate_circuit.hpp>

#include <nil/actor/zk/components/algebra/curves/pasta/plonk/unified_addition.hpp>

#include "proof_data.hpp"

using namespace nil::crypto3;

template<typename TIter>
void print_byteblob(std::ostream &os, TIter iter_begin, TIter iter_end) {
    os << std::hex;
    for (TIter it = iter_begin; it != iter_end; it++) {
        os << std::setfill('0') << std::setw(2) << std::right << int(*it);
    }
    os << std::endl << std::dec;
}

template<typename fri_type, typename FieldType>
typename fri_type::params_type create_fri_params(std::size_t degree_log) {
    typename fri_type::params_type params;
    math::polynomial<typename FieldType::value_type> q = {0, 0, 1};

    constexpr std::size_t expand_factor = 0;
    std::size_t r = degree_log - 1;

    std::vector<std::shared_ptr<math::evaluation_domain<FieldType>>> domain_set =
        math::calculate_domain_set<FieldType>(degree_log + expand_factor, r);

    params.r = r;
    params.D = domain_set;
    params.max_degree = (1 << degree_log) - 1;

    return params;
}

BOOST_AUTO_TEST_SUITE(blueprint_plonk_kimchi_demo_verifier_test_suite)

BOOST_AUTO_TEST_CASE(blueprint_plonk_kimchi_demo_verifier_test) {
    constexpr std::size_t complexity = 4000;

    using curve_type = algebra::curves::vesta;
    using BlueprintFieldType = typename curve_type::base_field_type;
    using hash_type = nil::crypto3::hashes::keccak_1600<256>;
    constexpr std::size_t Lambda = 1;

    constexpr std::size_t WitnessColumns = 11;
    constexpr std::size_t PublicInputColumns = 1;
    constexpr std::size_t ConstantColumns = 1;
    constexpr std::size_t SelectorColumns = 1;

    using ArithmetizationParams =
        zk::snark::plonk_arithmetization_params<WitnessColumns, PublicInputColumns, ConstantColumns, SelectorColumns>;
    using ArithmetizationType = zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

    nil::crypto3::zk::snark::pickles_proof<curve_type> kimchi_proof = test_proof();

    using component_type = zk::components::curve_element_unified_addition<ArithmetizationType, curve_type, 0, 1, 2, 3,
                                                                          4, 5, 6, 7, 8, 9, 10>;
    using var = zk::snark::plonk_variable<BlueprintFieldType>;

    auto P = kimchi_proof.commitments.w_comm[0].unshifted[0];
    auto Q = kimchi_proof.commitments.w_comm[1].unshifted[0];
    std::vector<BlueprintFieldType::value_type> public_input = {P.X, P.Y, Q.X, Q.Y};

    auto expected_result = P + Q;
    std::cout << "exprected result: (" << expected_result.X.data << ", " << expected_result.Y.data << ")" << std::endl;

    zk::snark::plonk_table_description<BlueprintFieldType, ArithmetizationParams> desc;

    zk::blueprint<ArithmetizationType> bp(desc);
    zk::blueprint_private_assignment_table<ArithmetizationType> private_assignment(desc);
    zk::blueprint_public_assignment_table<ArithmetizationType> public_assignment(desc);
    zk::blueprint_assignment_table<ArithmetizationType> assignment_bp(private_assignment, public_assignment);

    std::size_t start_row = zk::components::allocate<component_type>(bp, complexity);

    std::vector<component_type::result_type> result(complexity);

    bp.allocate_rows(public_input.size());
    component_type::params_type component_params = {
        {assignment_bp.allocate_public_input(public_input[0]), assignment_bp.allocate_public_input(public_input[1])},
        {assignment_bp.allocate_public_input(public_input[2]), assignment_bp.allocate_public_input(public_input[3])}};

    for (std::size_t i = 0; i < complexity; i++) {

        std::size_t row = start_row + i * component_type::rows_amount;
        result[i] = component_type::result_type(component_params, row);

        zk::components::generate_circuit<component_type>(bp, public_assignment, component_params, row);

        component_type::generate_assignments(assignment_bp, component_params, row);
    }

    // std::cout << "actual result: " << std::endl;
    // for (std::size_t i = 0; i < complexity; i++) {
    //     std::cout << "(" << assignment_bp.var_value(result[i].X).data << ", "
    //               << assignment_bp.var_value(result[i].Y).data << ")" << std::endl;
    // }

    assignment_bp.padding();

    zk::snark::plonk_assignment_table<BlueprintFieldType, ArithmetizationParams> assignments(private_assignment,
                                                                                             public_assignment);

    // profiling(assignments);
    using params =
        zk::snark::placeholder_params<BlueprintFieldType, ArithmetizationParams, hash_type, hash_type, Lambda>;

    using fri_type = typename zk::commitments::fri<BlueprintFieldType, typename params::merkle_hash_type,
                                                   typename params::transcript_hash_type, 2>;

    std::size_t table_rows_log = std::ceil(std::log2(desc.rows_amount));

    typename fri_type::params_type fri_params = create_fri_params<fri_type, BlueprintFieldType>(table_rows_log);

    std::size_t permutation_size = desc.witness_columns + desc.public_input_columns + desc.constant_columns;

    typename zk::snark::placeholder_public_preprocessor<BlueprintFieldType, params>::preprocessed_data_type
        public_preprocessed_data = zk::snark::placeholder_public_preprocessor<BlueprintFieldType, params>::process(
            bp, public_assignment, desc, fri_params, permutation_size);
    typename zk::snark::placeholder_private_preprocessor<BlueprintFieldType, params>::preprocessed_data_type
        private_preprocessed_data = zk::snark::placeholder_private_preprocessor<BlueprintFieldType, params>::process(
            bp, private_assignment, desc, fri_params);

    auto placeholder_proof = zk::snark::placeholder_prover<BlueprintFieldType, params>::process(
        public_preprocessed_data, private_preprocessed_data, desc, bp, assignments, fri_params);

    bool verifier_res = zk::snark::placeholder_verifier<BlueprintFieldType, params>::process(
        public_preprocessed_data, placeholder_proof, bp, fri_params);
    std::cout << "Proof check: " << verifier_res << std::endl;
}

BOOST_AUTO_TEST_SUITE_END()
