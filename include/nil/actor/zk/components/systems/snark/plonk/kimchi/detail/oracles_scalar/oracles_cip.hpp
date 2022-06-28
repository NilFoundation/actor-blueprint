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

#ifndef ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ORACLES_CIP_HPP
#define ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ORACLES_CIP_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor/zk/blueprint/plonk.hpp>
#include <nil/actor/zk/component.hpp>

#include <nil/actor/zk/components/systems/snark/plonk/kimchi/verifier_index.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/detail/proof.hpp>

#include <nil/actor/zk/components/algebra/fields/plonk/combined_inner_product.hpp>

#include <nil/actor/zk/algorithms/generate_circuit.hpp>

namespace nil {
    namespace actor {
        namespace zk {
            namespace components {

                // combined inner product from oracles data
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/kimchi/src/verifier.rs#L386-L441
                // Input:  
                // Output: 
                template<typename ArithmetizationType, typename KimchiCommitmentParamsType,
                    typename KimchiParamsType,
                    std::size_t... WireIndexes>
                class oracles_cip;

                template<typename BlueprintFieldType, 
                         typename ArithmetizationParams,
                         typename KimchiCommitmentParamsType,
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
                class oracles_cip<
                    snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    KimchiCommitmentParamsType,
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

                    constexpr static const std::size_t cip_size = 1;
                    constexpr static const std::size_t eval_points_amount = 2;

                    using component_type = zk::components::combined_inner_product<ArithmetizationType, cip_size, 
                                                        W0, W1, W2, W3,
                                                        W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>; 

                    constexpr static const std::size_t selector_seed = 0xf2e;

                public:
                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        var ft_eval0;
                        var ft_eval1;
                        std::array<
                            std::array<
                            std::array<var, KimchiCommitmentParamsType::size_for_max_poly>, 
                            eval_points_amount>,
                            KimchiParamsType::prev_challenges_size> polys;
                        std::array<var, eval_points_amount> p_eval;
                        std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>,
                            eval_points_amount> evals;
                    };

                    struct result_type {
                        var output;

                        result_type(std::size_t start_row_index) {
                            
                        }

                        result_type(const params_type &params,
                            std::size_t start_row_index) {
                            output = params.ft_eval0;
                        }
                    };

                    static result_type generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        return result_type(params, start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            const std::size_t start_row_index) {

                        std::size_t row = start_row_index;

                        return result_type(params, start_row_index);
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

#endif    // ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_DETAIL_ORACLES_CIP_HPP