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

#ifndef ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_FT_EVAL_HPP
#define ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_FT_EVAL_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor/zk/blueprint/plonk.hpp>
#include <nil/actor/zk/component.hpp>

#include <nil/actor/zk/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/verifier_index.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>
#include <nil/actor/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace actor {
        namespace zk {
            namespace components {

                // ft polynomial at zeta
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L320-L384
                // Input:
                // Output: ft(zeta)
                template<typename ArithmetizationType,
                    typename CurveType,
                    typename KimchiParamsType,
                    std::size_t... WireIndexes>
                class ft_eval;

                template<typename BlueprintFieldType, 
                         typename ArithmetizationParams,
                         typename CurveType,
                         typename KimchiParamsType,
                         std::size_t W0,
                         std::size_t W1,
                         std::size_t W2,
                         std::size_t W3,
                         std::size_t W4,
                         std::size_t W5,
                         std::size_t W6,
                         std::size_t W7,
                         std::size_t W8,
                         std::size_t W9,
                         std::size_t W10,
                         std::size_t W11,
                         std::size_t W12,
                         std::size_t W13,
                         std::size_t W14>
                class ft_eval<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    CurveType,
                    KimchiParamsType,
                    W0,
                    W1,
                    W2,
                    W3,
                    W4,
                    W5,
                    W6,
                    W7,
                    W8,
                    W9,
                    W10,
                    W11,
                    W12,
                    W13,
                    W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using mul_component = zk::components::multiplication<ArithmetizationType, W0, W1, W2>;

                    constexpr static const std::size_t selector_seed = 0x0f22;
                    constexpr static const std::size_t eval_points_amount = 2;

                public:
                    constexpr static const std::size_t rows_amount = mul_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        kimchi_verifier_index_scalar<BlueprintFieldType> verifier_index;
                        var zeta_pow_n;
                        std::array<var, KimchiParamsType::alpha_powers_n> alpha_powers;
                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>, eval_points_amount> combined_evals;
                        var gamma;
                        var beta;
                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>, eval_points_amount> p_evals;
                        var zeta;
                        var joint_combiner;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t component_start_row) {
                            std::size_t row = component_start_row;
                            output = typename mul_component::result_type(row).output;
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        zk::components::generate_circuit<mul_component>(bp, assignment, 
                            {params.zeta_pow_n, params.gamma}, row);
                        row += mul_component::rows_amount;


                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;
                        mul_component::generate_assignments(assignment, 
                            {params.zeta_pow_n, params.gamma}, row);
                        row += mul_component::rows_amount;

                        return result_type(start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                    }

                    static void generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_FT_EVAL_HPP