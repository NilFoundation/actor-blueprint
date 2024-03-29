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
// @file Declaration of interfaces for auxiliary components for the SHA256 component.
//---------------------------------------------------------------------------//

#ifndef ACTOR_BLUEPRINT_MC_PLONK_PICKLES_VERIFY_HETEROGENOUS_BASE_HPP
#define ACTOR_BLUEPRINT_MC_PLONK_PICKLES_VERIFY_HETEROGENOUS_BASE_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor_blueprint_mc/blueprint/plonk.hpp>
#include <nil/actor_blueprint_mc/assignment/plonk.hpp>
#include <nil/actor_blueprint_mc/component.hpp>

#include <nil/actor_blueprint_mc/algorithms/generate_circuit.hpp>

#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/verifier_base_field.hpp>


#include <nil/actor_blueprint_mc/components/systems/snark/plonk/pickles/scalar_details/batch_dlog_accumulator_check_scalar.hpp>
#include <nil/actor_blueprint_mc/components/systems/snark/plonk/pickles/types/instance.hpp>

namespace nil {
    namespace actor_blueprint_mc {
        namespace components {

            // base field part of verify_generogenous
            // https://github.com/MinaProtocol/mina/blob/09348bccf281d54e6fa9dd2d8bbd42e3965e1ff5/src/lib/pickles/verify.ml#L30
            template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType, 
                std::size_t BatchSize, std::size_t CommsLen, std::size_t... WireIndexes>
            class verify_heterogenous_base;

            template<typename ArithmetizationParams, typename CurveType, typename KimchiParamsType,  
                        std::size_t BatchSize, std::size_t CommsLen, std::size_t W0, std::size_t W1,
                        std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5, std::size_t W6, std::size_t W7,
                        std::size_t W8, std::size_t W9, std::size_t W10, std::size_t W11, std::size_t W12,
                        std::size_t W13, std::size_t W14>
            class verify_heterogenous_base<
                nil::actor::zk::snark::plonk_constraint_system<typename CurveType::base_field_type, ArithmetizationParams>,
                CurveType, KimchiParamsType, BatchSize, CommsLen,
                W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                using BlueprintFieldType = typename CurveType::base_field_type;

                using ArithmetizationType = nil::actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;

                using KimchiCommitmentParamsType = typename KimchiParamsType::commitment_params_type;

                using var = nil::actor::zk::snark::plonk_variable<BlueprintFieldType>;

                using var_ec_point = typename nil::actor_blueprint_mc::components::var_ec_point<BlueprintFieldType>;

                using batch_verify_component =
                    nil::actor_blueprint_mc::components::batch_dlog_accumulator_check_scalar<ArithmetizationType, CurveType, KimchiParamsType,
                                                            CommsLen, W0, W1, W2, W3,
                                                            W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;
                
                using kimchi_verify_component = nil::actor_blueprint_mc::components::base_field<ArithmetizationType,
                    CurveType, KimchiParamsType, KimchiCommitmentParamsType, BatchSize,
                    W0, W1, W2, W3,
                            W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                using proof_binding =
                    typename nil::actor_blueprint_mc::components::binding<ArithmetizationType, BlueprintFieldType, KimchiParamsType>;

                using verifier_index_type = kimchi_verifier_index_base<CurveType, KimchiParamsType>;
                using proof_type = kimchi_proof_base<BlueprintFieldType, KimchiParamsType>;
                using pickles_instance_type = instance_type<BlueprintFieldType, CurveType, KimchiParamsType>;

                constexpr static std::size_t rows() {
                    std::size_t row = 0;

                    row += batch_verify_component::rows_amount;

                    row += kimchi_verify_component::rows_amount;

                    return row;
                }

            public:
                constexpr static const std::size_t rows_amount = rows();
                constexpr static const std::size_t gates_amount = 0;

                struct params_type {
                    std::array<pickles_instance_type, BatchSize> ts;

                    typename proof_binding::template fr_data<var, BatchSize> fr_data;
                    typename proof_binding::template fq_data<var> fq_data;
                };

                struct result_type {
                    var output;
                };

                static result_type
                    generate_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        const params_type &params,
                                        const std::size_t start_row_index) {
                    std::size_t row = start_row_index;

                    std::vector<var_ec_point> comms;
                    std::vector<var> bulletproof_challenges; 
                    for (std::size_t i = 0; i < BatchSize; ++i) {
                        var_ec_point comms_i = 
                            params.ts[i].statement.proof_state.messages_for_next_wrap_proof.challenge_polynomial_commitment;
                        comms.push_back(comms_i);

                        std::vector<var> bulletproof_challenges_i = 
                            params.fr_data.step_bulletproof_challenges[i];
                        bulletproof_challenges.insert(bulletproof_challenges.end(), bulletproof_challenges_i.begin(), bulletproof_challenges_i.end());
                    }
                    batch_verify_component::generate_circuit(bp, assignment,
                        {comms, bulletproof_challenges, params.ts[0].verifier_index}, row);
                    row += batch_verify_component::rows_amount;

                    std::array<proof_type, BatchSize> proofs;
                    for (std::size_t i = 0; i < BatchSize; ++i) {
                        proofs[i] = params.ts[i].kimchi_proof;
                    }

                    /*kimchi_verify_component::generate_circuit(bp, assignment,
                        {proofs, params.ts[0].verifier_index, params.fr_data, params.fq_data}, row);
                    row += kimchi_verify_component::rows_amount;*/

                    return result_type();
                }

                static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const params_type &params,
                                                        std::size_t start_row_index) {

                    std::size_t row = start_row_index;

                    std::vector<var_ec_point> comms;
                    std::vector<var> bulletproof_challenges; 
                    for (std::size_t i = 0; i < BatchSize; ++i) {
                        var_ec_point comms_i = 
                            params.ts[i].statement.proof_state.messages_for_next_wrap_proof.challenge_polynomial_commitment;
                        comms.push_back(comms_i);

                        std::vector<var> bulletproof_challenges_i = 
                            params.fr_data.step_bulletproof_challenges[i];
                        bulletproof_challenges.insert(bulletproof_challenges.end(), bulletproof_challenges_i.begin(), bulletproof_challenges_i.end());
                    }
                    batch_verify_component::generate_assignments(assignment,
                        {comms, bulletproof_challenges, params.ts[0].verifier_index}, row);
                    row += batch_verify_component::rows_amount;

                    std::array<proof_type, BatchSize> proofs;
                    for (std::size_t i = 0; i < BatchSize; ++i) {
                        proofs[i] = params.ts[i].kimchi_proof;
                    }

                    /*kimchi_verify_component::generate_assignments(assignment,
                        {proofs, params.ts[0].verifier_index, params.fr_data, params.fq_data}, row);
                    row += kimchi_verify_component::rows_amount;*/
                    
                    return result_type();
                }
            };
        }    // namespace components
    }            // namespace actor_blueprint_mc
}    // namespace nil

#endif    // ACTOR_BLUEPRINT_MC_PLONK_PICKLES_VERIFY_HETEROGENOUS_BASE_HPP