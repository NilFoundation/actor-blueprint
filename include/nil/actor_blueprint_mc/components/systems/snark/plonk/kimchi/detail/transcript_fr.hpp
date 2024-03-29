//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
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

#ifndef ACTOR_BLUEPRINT_MC_PLONK_KIMCHI_TRANSCRIPT_HPP
#define ACTOR_BLUEPRINT_MC_PLONK_KIMCHI_TRANSCRIPT_HPP

#include <vector>
#include <array>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor_blueprint_mc/blueprint/plonk.hpp>
#include <nil/actor_blueprint_mc/assignment/plonk.hpp>
#include <nil/actor_blueprint_mc/component.hpp>
#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/detail/limbs.hpp>
#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/detail/sponge.hpp>
#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/types/evaluation_proof.hpp>

namespace nil {
    namespace actor_blueprint_mc {
        namespace components {

            // Fiat-Shamir transfotmation (scalar field part)
            // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/sponge.rs#L81
            template<typename ArithmetizationType,
                        typename CurveType,
                        typename KimchiParamsType,
                        std::size_t... WireIndexes>
            class kimchi_transcript_fr;

            template<typename BlueprintFieldType,
                        typename ArithmetizationParams, typename CurveType,  typename KimchiParamsType,
                        std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4,
                        std::size_t W5, std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9,
                        std::size_t W10, std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
            class kimchi_transcript_fr<nil::actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                        CurveType,
                                        KimchiParamsType,
                                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                typedef nil::actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                    ArithmetizationType;

                using var = nil::actor::zk::snark::plonk_variable<BlueprintFieldType>;

                static const std::size_t CHALLENGE_LENGTH_IN_LIMBS = 2;
                static const std::size_t HIGH_ENTROPY_LIMBS = 2;

                using sponge_component = kimchi_sponge<ArithmetizationType,
                                                        CurveType,
                                                        W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                sponge_component sponge;
                using pack = from_limbs<ArithmetizationType, W0, W1, W2>;
                using unpack =
                    to_limbs<ArithmetizationType, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                std::vector<var> last_squeezed;

                var pack_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                    const std::size_t component_start_row,
                                    std::array<var, 2>
                                        limbs) {
                    auto pack_res = pack::generate_assignments(assignment, limbs, component_start_row);
                    return pack_res.result;
                }

                var pack_circuit(blueprint<ArithmetizationType> &bp,
                                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                    const std::size_t component_start_row,
                                    std::array<var, 2>
                                        limbs) {
                    auto pack_res = pack::generate_circuit(bp, assignment, limbs, component_start_row);
                    return pack_res.result;
                }

                std::array<var, 4> unpack_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                        const std::size_t component_start_row,
                                                        var elem) {
                    auto unpack_res = unpack::generate_assignments(assignment, {elem}, component_start_row);
                    return unpack_res.result;
                }

                std::array<var, 4>
                    unpack_circuit(blueprint<ArithmetizationType> &bp,
                                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                    const std::size_t component_start_row,
                                    var elem) {
                    auto unpack_res = unpack::generate_circuit(bp, assignment, {elem}, component_start_row);
                    return unpack_res.result;
                }

                constexpr static std::size_t absorb_evals_rows() {
                    std::size_t res = 22 * absorb_rows;
                    if (KimchiParamsType::public_input_size) {
                        res += sponge_component::absorb_rows;
                    }
                    if (KimchiParamsType::generic_gate) {
                        res += sponge_component::absorb_rows;
                    }
                    if (KimchiParamsType::poseidon_gate) {
                        res += sponge_component::absorb_rows;
                    }
                    if (KimchiParamsType::use_lookup) {
                        res += sponge_component::absorb_rows * KimchiParamsType::lookup_comm_size;
                        res += sponge_component::absorb_rows * 2;
                        if (KimchiParamsType::lookup_runtime) {
                            res += sponge_component::absorb_rows;
                        }
                    }
                    return res;
                }
                
            public:
                constexpr static const std::size_t rows_amount = 0;
                constexpr static const std::size_t init_rows = sponge_component::init_rows;
                constexpr static const std::size_t absorb_rows = sponge_component::absorb_rows;
                constexpr static const std::size_t challenge_rows = 
                    sponge_component::squeeze_rows + unpack::rows_amount 
                    + pack::rows_amount;
                constexpr static const std::size_t absorb_evaluations_rows = absorb_evals_rows();

                constexpr static const std::size_t state_size = sponge_component::state_size;

                std::array<var, sponge_component::state_size> state() {
                    return sponge._inner_state();
                }

                void init_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                        var zero,
                                        const std::size_t component_start_row) {
                    sponge.init_assignment(assignment, zero, component_start_row);
                    last_squeezed = {};
                }

                void init_circuit(blueprint<ArithmetizationType> &bp,
                                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                    const var &zero,
                                    const std::size_t component_start_row) {
                    sponge.init_circuit(bp, assignment, zero, component_start_row);
                    last_squeezed = {};
                }

                void absorb_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                        var absorbing_value,
                                        const std::size_t component_start_row) {
                    last_squeezed = {};
                    sponge.absorb_assignment(assignment, absorbing_value, component_start_row);
                }

                void absorb_circuit(blueprint<ArithmetizationType> &bp,
                                    blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                    const var &input,
                                    const std::size_t component_start_row) {
                    last_squeezed = {};
                    sponge.absorb_circuit(bp, assignment, input, component_start_row);
                }

                void absorb_evaluations_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                    var public_eval,
                                                    kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>
                                                        private_eval,
                                                    const std::size_t component_start_row) {
                    last_squeezed = {};
                    std::size_t row = component_start_row;

                    if (KimchiParamsType::public_input_size != 0) {
                        sponge.absorb_assignment(assignment, public_eval, row);
                        row += sponge_component::absorb_rows;
                    }

                    sponge.absorb_assignment(assignment, private_eval.z, row);
                    row += sponge_component::absorb_rows;

                    if (KimchiParamsType::generic_gate) {
                        sponge.absorb_assignment(assignment, private_eval.generic_selector, row);
                        row += sponge_component::absorb_rows;
                    }
                    if (KimchiParamsType::poseidon_gate) {
                        sponge.absorb_assignment(assignment, private_eval.poseidon_selector, row);
                        row += sponge_component::absorb_rows;
                    }

                    std::vector<var> points = {private_eval.w[0], private_eval.w[1], private_eval.w[2], private_eval.w[3], private_eval.w[4],
                                            private_eval.w[5], private_eval.w[6], private_eval.w[7], private_eval.w[8], private_eval.w[9],
                                            private_eval.w[10], private_eval.w[11], private_eval.w[12], private_eval.w[13], private_eval.w[14],
                                            private_eval.s[0], private_eval.s[1], private_eval.s[2], private_eval.s[3], private_eval.s[4], private_eval.s[5]};
                    for (auto p : points) {
                        sponge.absorb_assignment(assignment, p, row);
                        row += sponge_component::absorb_rows;
                    }

                    if (KimchiParamsType::use_lookup) {
                        for (auto ls : private_eval.lookup.sorted) {
                            sponge.absorb_assignment(assignment, ls, row);
                            row += sponge_component::absorb_rows;
                        }
                        sponge.absorb_assignment(assignment, private_eval.lookup.aggreg, row);
                        row += sponge_component::absorb_rows;
                        sponge.absorb_assignment(assignment, private_eval.lookup.table, row);
                        row += sponge_component::absorb_rows;
                        if (KimchiParamsType::lookup_runtime) {
                            sponge.absorb_assignment(assignment, private_eval.lookup.runtime, row);
                            row += sponge_component::absorb_rows;
                        }
                    }
                }

                void absorb_evaluations_circuit(blueprint<ArithmetizationType> &bp,
                                                blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                var public_eval,
                                                kimchi_proof_evaluations<BlueprintFieldType, KimchiParamsType>
                                                    private_eval,
                                                const std::size_t component_start_row) {
                    last_squeezed = {};
                    std::size_t row = component_start_row;

                    if (KimchiParamsType::public_input_size) {
                        sponge.absorb_circuit(bp, assignment, public_eval, row);
                        row += sponge_component::absorb_rows;
                    }

                    sponge.absorb_circuit(bp, assignment, private_eval.z, row);
                    row += sponge_component::absorb_rows;

                    if (KimchiParamsType::generic_gate) {
                        sponge.absorb_circuit(bp, assignment, private_eval.generic_selector, row);
                        row += sponge_component::absorb_rows;
                    }
                    if (KimchiParamsType::poseidon_gate) {
                        sponge.absorb_circuit(bp, assignment, private_eval.poseidon_selector, row);
                        row += sponge_component::absorb_rows;
                    }
                    
                    std::vector<var> points = {private_eval.w[0], private_eval.w[1], private_eval.w[2], private_eval.w[3], private_eval.w[4],
                                            private_eval.w[5], private_eval.w[6], private_eval.w[7], private_eval.w[8], private_eval.w[9],
                                            private_eval.w[10], private_eval.w[11], private_eval.w[12], private_eval.w[13], private_eval.w[14],
                                            private_eval.s[0], private_eval.s[1], private_eval.s[2], private_eval.s[3], private_eval.s[4], private_eval.s[5]};
                    for (auto p : points) {
                        sponge.absorb_circuit(bp, assignment, p, row);
                        row += sponge_component::absorb_rows;
                    }

                    if (KimchiParamsType::use_lookup) {
                        for (auto ls : private_eval.lookup.sorted) {
                            sponge.absorb_circuit(bp, assignment, ls, row);
                            row += sponge_component::absorb_rows;
                        }
                        sponge.absorb_circuit(bp, assignment, private_eval.lookup.aggreg, row);
                        row += sponge_component::absorb_rows;
                        sponge.absorb_circuit(bp, assignment, private_eval.lookup.table, row);
                        row += sponge_component::absorb_rows;
                        if (KimchiParamsType::lookup_runtime) {
                            sponge.absorb_circuit(bp, assignment, private_eval.lookup.runtime, row);
                            row += sponge_component::absorb_rows;
                        }
                    }
                }

                var challenge_assignment(blueprint_assignment_table<ArithmetizationType> &assignment,
                                            const std::size_t component_start_row) {
                    std::size_t row = component_start_row;
                    if (last_squeezed.size() >= CHALLENGE_LENGTH_IN_LIMBS) {
                        std::array<var, 2> limbs = {last_squeezed[0], last_squeezed[1]};
                        std::vector<var> remaining = {last_squeezed.begin() + CHALLENGE_LENGTH_IN_LIMBS,
                                                        last_squeezed.end()};
                        last_squeezed = remaining;
                        return pack_assignment(assignment, row, limbs);
                    }
                    var sq = sponge.squeeze_assignment(assignment, row);
                    row += sponge_component::squeeze_rows;
                    auto x = unpack_assignment(assignment, row, sq);
                    row += unpack::rows_amount;
                    for (int i = 0; i < HIGH_ENTROPY_LIMBS; ++i) {
                        last_squeezed.push_back(x[i]);
                    }
                    return challenge_assignment(assignment, row);
                }

                var challenge_circuit(blueprint<ArithmetizationType> &bp,
                                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                        const std::size_t component_start_row) {
                    std::size_t row = component_start_row;
                    if (last_squeezed.size() >= CHALLENGE_LENGTH_IN_LIMBS) {
                        std::array<var, 2> limbs = {last_squeezed[0], last_squeezed[1]};
                        std::vector<var> remaining = {last_squeezed.begin() + CHALLENGE_LENGTH_IN_LIMBS,
                                                        last_squeezed.end()};
                        last_squeezed = remaining;
                        return pack_circuit(bp, assignment, row, limbs);
                    }
                    var sq = sponge.squeeze_circuit(bp, assignment, row);
                    row += sponge_component::squeeze_rows;
                    auto x = unpack_circuit(bp, assignment, row, sq);
                    row += unpack::rows_amount;
                    for (int i = 0; i < HIGH_ENTROPY_LIMBS; ++i) {
                        last_squeezed.push_back(x[i]);
                    }
                    return challenge_circuit(bp, assignment, row);
                }
            };
        }    // namespace components
    }            // namespace actor_blueprint_mc
}    // namespace nil

#endif    // ACTOR_BLUEPRINT_MC_PLONK_KIMCHI_TRANSCRIPT_HPP
