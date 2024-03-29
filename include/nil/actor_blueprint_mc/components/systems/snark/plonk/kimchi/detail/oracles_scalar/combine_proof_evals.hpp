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

#ifndef ACTOR_BLUEPRINT_MC_PLONK_KIMCHI_DETAIL_COMBINE_PROOF_EVALS_HPP
#define ACTOR_BLUEPRINT_MC_PLONK_KIMCHI_DETAIL_COMBINE_PROOF_EVALS_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor_blueprint_mc/blueprint/plonk.hpp>
#include <nil/actor_blueprint_mc/component.hpp>
#include <nil/actor_blueprint_mc/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/types/verifier_index.hpp>
#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/actor_blueprint_mc/components/algebra/fields/plonk/field_operations.hpp>

#include <nil/actor_blueprint_mc/algorithms/generate_circuit.hpp>

namespace nil {
    namespace actor_blueprint_mc {
        namespace components {

            // Proof evals are element of the finite field, so combine works just as scalar multiplication
            // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/proof.rs#L105
            // Input: x, proof_evaluations (see kimchi_proof_evaluations): {w_0, ... w_14, z, ...,
            // poseidon_selector} Output: proof_evaluations: {x * w_0, ... x * w_14, x * z, ..., x *
            // poseidon_selector}
            template<typename ArithmetizationType, typename KimchiParamsType, std::size_t... WireIndexes>
            class combine_proof_evals;

            template<typename BlueprintFieldType, typename ArithmetizationParams, typename KimchiParamsType,
                        std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                        std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                        std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
            class combine_proof_evals<nil::actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                        KimchiParamsType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13,
                                        W14> {

                typedef nil::actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using var = nil::actor::zk::snark::plonk_variable<BlueprintFieldType>;

                using mul_component = components::multiplication<ArithmetizationType, W0, W1, W2>;

                constexpr static const std::size_t selector_seed = 0x0f23;

                constexpr static const std::size_t rows() {
                    std::size_t rows = 0;
                    rows += KimchiParamsType::witness_columns * mul_component::rows_amount;        // w
                    rows += mul_component::rows_amount;                                          // z
                    rows += (KimchiParamsType::permut_size - 1) * mul_component::rows_amount;    // s 

                    if (KimchiParamsType::circuit_params::lookup_columns > 0) {
                        rows += KimchiParamsType::circuit_params::lookup_columns * mul_component::rows_amount;

                        rows += 2 * mul_component::rows_amount;

                        if (KimchiParamsType::circuit_params::lookup_runtime) {
                            rows += mul_component::rows_amount;
                        }
                    }

                    if (KimchiParamsType::generic_gate) {
                        rows += mul_component::rows_amount;
                    }
                    if (KimchiParamsType::poseidon_gate) {
                        rows += mul_component::rows_amount;
                    }
                    return rows;
                }

            public:
                constexpr static const std::size_t rows_amount = rows();
                constexpr static const std::size_t gates_amount = 0;

                struct params_type {
                    kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType> evals;
                    var x;
                };

                struct result_type {
                    kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType> output;

                    result_type(std::size_t component_start_row) {
                        std::size_t row = component_start_row;

                        // w
                        for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
                            output.w[i] = typename mul_component::result_type(row).output;
                            row += mul_component::rows_amount;
                        }
                        // z
                        output.z = typename mul_component::result_type(row).output;
                        row += mul_component::rows_amount;
                        // s
                        for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                            output.s[i] = typename mul_component::result_type(row).output;
                            row += mul_component::rows_amount;
                        }
                        // lookup
                        if (KimchiParamsType::circuit_params::lookup_columns > 0) {
                            for (std::size_t i = 0; i < KimchiParamsType::circuit_params::lookup_columns; i++) {
                                output.lookup.sorted[i] = typename mul_component::result_type(row).output;
                                row += mul_component::rows_amount;
                            }

                            output.lookup.aggreg = typename mul_component::result_type(row).output;
                            row += mul_component::rows_amount;

                            output.lookup.table = typename mul_component::result_type(row).output;
                            row += mul_component::rows_amount;

                            if (KimchiParamsType::circuit_params::lookup_runtime) {
                                output.lookup.runtime = typename mul_component::result_type(row).output;
                                row += mul_component::rows_amount;
                            }
                        }
                        // generic_selector
                        if (KimchiParamsType::generic_gate) {
                            output.generic_selector = typename mul_component::result_type(row).output;
                            row += mul_component::rows_amount;
                        }
                        // poseidon_selector
                        if (KimchiParamsType::poseidon_gate) {
                            output.poseidon_selector = typename mul_component::result_type(row).output;
                            row += mul_component::rows_amount;
                        }
                    }
                };

                static result_type
                    generate_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        const params_type &params,
                                        const std::size_t start_row_index) {

                    std::size_t row = start_row_index;

                    // w
                    for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
                        components::generate_circuit<mul_component>(bp, assignment,
                                                                        {params.evals.w[i], params.x}, row);
                        row += mul_component::rows_amount;
                    }
                    // z
                    components::generate_circuit<mul_component>(bp, assignment, {params.evals.z, params.x},
                                                                    row);
                    row += mul_component::rows_amount;
                    // s
                    for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                        components::generate_circuit<mul_component>(bp, assignment,
                                                                        {params.evals.s[i], params.x}, row);
                        row += mul_component::rows_amount;
                    }
                    // lookup
                    if (KimchiParamsType::circuit_params::lookup_columns > 0) {
                        for (std::size_t i = 0; i < KimchiParamsType::circuit_params::lookup_columns; i++) {
                            components::generate_circuit<mul_component>(
                                bp, assignment, {params.evals.lookup.sorted[i], params.x}, row);
                            row += mul_component::rows_amount;
                        }

                        components::generate_circuit<mul_component>(
                            bp, assignment, {params.evals.lookup.aggreg, params.x}, row);
                        row += mul_component::rows_amount;

                        components::generate_circuit<mul_component>(bp, assignment,
                                                                        {params.evals.lookup.table, params.x}, row);
                        row += mul_component::rows_amount;

                        if (KimchiParamsType::circuit_params::lookup_runtime) {
                            components::generate_circuit<mul_component>(
                                bp, assignment, {params.evals.lookup.runtime, params.x}, row);
                            row += mul_component::rows_amount;
                        }
                    }
                    // generic_selector
                    if (KimchiParamsType::generic_gate) {
                        components::generate_circuit<mul_component>(bp, assignment,
                                                                        {params.evals.generic_selector, params.x}, row);
                        row += mul_component::rows_amount;
                    }
                    // poseidon_selector
                    if (KimchiParamsType::poseidon_gate) {
                        components::generate_circuit<mul_component>(
                            bp, assignment, {params.evals.poseidon_selector, params.x}, row);
                        row += mul_component::rows_amount;
                    }

                    assert(row == start_row_index + rows_amount);

                    return result_type(start_row_index);
                }

                static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        const std::size_t start_row_index) {

                    std::size_t row = start_row_index;

                    // w
                    for (std::size_t i = 0; i < KimchiParamsType::witness_columns; i++) {
                        mul_component::generate_assignments(assignment, {params.evals.w[i], params.x}, row);
                        row += mul_component::rows_amount;
                    }
                    // z
                    mul_component::generate_assignments(assignment, {params.evals.z, params.x}, row);
                    row += mul_component::rows_amount;
                    // s
                    for (std::size_t i = 0; i < KimchiParamsType::permut_size - 1; i++) {
                        mul_component::generate_assignments(assignment, {params.evals.s[i], params.x}, row);
                        row += mul_component::rows_amount;
                    }
                    // lookup
                    if (KimchiParamsType::circuit_params::lookup_columns > 0) {
                        for (std::size_t i = 0; i < KimchiParamsType::circuit_params::lookup_columns; i++) {
                            mul_component::generate_assignments(assignment,
                                                                {params.evals.lookup.sorted[i], params.x}, row);
                            row += mul_component::rows_amount;
                        }

                        mul_component::generate_assignments(assignment, {params.evals.lookup.aggreg, params.x},
                                                            row);
                        row += mul_component::rows_amount;

                        mul_component::generate_assignments(assignment, {params.evals.lookup.table, params.x}, row);
                        row += mul_component::rows_amount;

                        if (KimchiParamsType::circuit_params::lookup_runtime) {
                            mul_component::generate_assignments(assignment, {params.evals.lookup.runtime, params.x},
                                                                row);
                            row += mul_component::rows_amount;
                        }
                    }
                    // generic_selector
                    if (KimchiParamsType::generic_gate) {
                        mul_component::generate_assignments(assignment, {params.evals.generic_selector, params.x}, row);
                        row += mul_component::rows_amount;
                    }
                    // poseidon_selector
                    if (KimchiParamsType::poseidon_gate) {
                        mul_component::generate_assignments(assignment, {params.evals.poseidon_selector, params.x},
                                                            row);
                        row += mul_component::rows_amount;
                    }

                    assert(row == start_row_index + rows_amount);

                    return result_type(start_row_index);
                }
            };
        }    // namespace components
    }        // namespace actor_blueprint_mc
}    // namespace nil

#endif    // ACTOR_BLUEPRINT_MC_PLONK_KIMCHI_DETAIL_COMBINE_PROOF_EVALS_HPP