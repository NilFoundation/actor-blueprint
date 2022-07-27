//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
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

#ifndef ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_PROOF_HPP
#define ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_PROOF_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor/zk/blueprint/plonk.hpp>
#include <nil/actor/zk/component.hpp>

#include <nil/actor/zk/components/algebra/curves/pasta/plonk/types.hpp>

#include <nil/actor/zk/components/systems/snark/plonk/kimchi/types/evaluation_proof.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/detail/binding.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/detail/commitment.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/detail/transcript_fq.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/detail/transcript_fr.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>

namespace nil {
    namespace actor {
        namespace zk {
            namespace components {

                template<typename BlueprintFieldType>
                struct kimchi_opening_proof_scalar {
                    using var = snark::plonk_variable<BlueprintFieldType>;

                    var z1;
                    var z2;
                };

                template<typename BlueprintFieldType, typename KimchiParamsType,
                    std::size_t EvalRounds>
                struct kimchi_proof_scalar {
                    using var = snark::plonk_variable<BlueprintFieldType>;

                    std::array<kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>, 2> proof_evals;
                    var ft_eval;
                    std::array<var, KimchiParamsType::public_input_size> public_input;
                    std::array<std::array<var, EvalRounds>, KimchiParamsType::prev_challenges_size> prev_challenges;

                    kimchi_opening_proof_scalar<BlueprintFieldType> 
                        opening;
                };

                template<typename BlueprintFieldType,
                         typename ArithmetizationType,
                         typename KimchiParamsType,
                         typename KimchiCommitmentParamsType>
                struct batch_evaluation_proof_scalar {
                    using proof_binding = typename zk::components::binding<ArithmetizationType,
                        BlueprintFieldType, KimchiParamsType>;
                    using var = snark::plonk_variable<BlueprintFieldType>;

                    var cip;
                    typename proof_binding::fq_sponge_output fq_output;
                    std::array<var, KimchiParamsType::eval_points_amount> eval_points;
                    // scaling factor for polynomials
                    var r;
                    // scaling factor for evaluation point powers
                    var xi;

                    kimchi_opening_proof_scalar<BlueprintFieldType> 
                        opening;

                    using transcript_type = kimchi_transcript<ArithmetizationType, typename KimchiParamsType::curve_type,
                                        KimchiParamsType,
                                        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                        11, 12, 13, 14>;
                    transcript_type transcript;
                };

                template<typename BlueprintFieldType,
                    std::size_t EvalRounds>
                struct kimchi_opening_proof_base {
                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using var_ec_point = typename zk::components::var_ec_point<BlueprintFieldType>;

                    std::array<var_ec_point, EvalRounds> L;
                    std::array<var_ec_point, EvalRounds> R;
                    var_ec_point delta;
                    var_ec_point G;
                };

                template<typename BlueprintFieldType, typename KimchiParamsType>
                struct kimchi_proof_base {
                    using var = snark::plonk_variable<BlueprintFieldType>;
                    using commitment_params_type = typename 
                        KimchiParamsType::commitment_params_type;

                    using shifted_commitment_type = typename 
                        zk::components::kimchi_shifted_commitment_type<BlueprintFieldType, 
                            commitment_params_type::shifted_commitment_split>;

                    using opening_proof_type = typename 
                        zk::components::kimchi_opening_proof_base<BlueprintFieldType,
                        commitment_params_type::eval_rounds>;

                    struct commitments {
                        std::array<shifted_commitment_type,
                            KimchiParamsType::witness_columns> witness_comm;
                        shifted_commitment_type lookup_runtime_comm;
                        shifted_commitment_type table_comm;
                        std::vector<shifted_commitment_type> lookup_sorted_comm;
                        shifted_commitment_type lookup_agg_comm;
                        shifted_commitment_type z_comm;
                        shifted_commitment_type t_comm;
                        std::array<shifted_commitment_type, 
                            KimchiParamsType::prev_challenges_size>
                            prev_challenges; // to-do: get in the component from oracles
                    };

                    constexpr static const std::size_t f_comm_base_size = 1 // permuation-argument
                        + 5 // generic gate
                        + KimchiParamsType::index_term_size();

                    commitments comm;
                    opening_proof_type o;
                    std::array<var, f_comm_base_size> scalars;
                };

                template<typename BlueprintFieldType,
                         typename ArithmetizationType,
                         typename KimchiParamsType,
                         typename KimchiCommitmentParamsType>
                struct batch_evaluation_proof_base {
                    using proof_binding = typename zk::components::binding<ArithmetizationType,
                        BlueprintFieldType, KimchiParamsType>;
                    using var = snark::plonk_variable<BlueprintFieldType>;

                    using shifted_commitment_type = typename 
                        zk::components::kimchi_shifted_commitment_type<BlueprintFieldType, 
                            KimchiCommitmentParamsType::shifted_commitment_split>;

                    using opening_proof_type = typename 
                        zk::components::kimchi_opening_proof_base<BlueprintFieldType, 
                        KimchiCommitmentParamsType::eval_rounds>;

                    using kimchi_constants = zk::components::kimchi_inner_constants<KimchiParamsType>;

                    // using transcript_type = typename 
                    //     zk::components::kimchi_transcript_fq<ArithmetizationType, typename KimchiParamsType::curve_type,
                    //                 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                    //                 11, 12, 13, 14>;

                    //typename proof_binding::fq_sponge_output fq_output;
                    std::array<shifted_commitment_type, 
                        kimchi_constants::evaluations_in_batch_size> comm;
                    opening_proof_type opening_proof;

                    // transcript_type transcript;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_PROOF_HPP