//---------------------------------------------------------------------------//
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
// @file Declaration of interfaces for auxiliary components for the BATCH_VERIFY_SCALAR_FIELD component.
//---------------------------------------------------------------------------//

#ifndef ACTOR_BLUEPRINT_MC_BATCH_VERIFY_SCALAR_FIELD_HPP
#define ACTOR_BLUEPRINT_MC_BATCH_VERIFY_SCALAR_FIELD_HPP

#include <nil/actor_blueprint_mc/blueprint/plonk.hpp>
#include <nil/actor_blueprint_mc/assignment/plonk.hpp>

#include <nil/actor_blueprint_mc/algorithms/generate_circuit.hpp>

#include <nil/actor_blueprint_mc/components/algebra/fields/plonk/field_operations.hpp>
#include <nil/actor_blueprint_mc/components/algebra/fields/plonk/combined_inner_product.hpp>
#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/types/proof.hpp>
#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/detail/inner_constants.hpp>

#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/detail/batch_scalar/random.hpp>
#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/detail/batch_scalar/prepare_scalars.hpp>

#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly.hpp>
#include <nil/actor_blueprint_mc/components/systems/snark/plonk/kimchi/detail/oracles_scalar/b_poly_coefficients.hpp>

#include <nil/actor_blueprint_mc/components/algebra/curves/pasta/plonk/endo_scalar.hpp>

namespace nil {
    namespace actor_blueprint_mc {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/f01d3925a273ded939a80e1de9afcd9f913a7c17/src/lib/crypto/kimchi_bindings/stubs/src/urs_utils.rs#L10
                template<typename ArithmetizationType, typename CurveType, typename KimchiParamsType,
                        std::size_t CommsLen,
                         std::size_t... WireIndexes>
                class batch_dlog_accumulator_check_scalar;

                template<typename BlueprintFieldType, typename CurveType, typename ArithmetizationParams,
                         typename KimchiParamsType, std::size_t CommsLen,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class batch_dlog_accumulator_check_scalar<
                    nil::actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, CurveType,
                    KimchiParamsType, CommsLen, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9,
                    W10, W11, W12, W13, W14> {

                    typedef nil::actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = nil::actor::zk::snark::plonk_variable<BlueprintFieldType>;

                    using KimchiCommitmentParamsType = typename KimchiParamsType::commitment_params_type;

                    using mul_component = nil::actor_blueprint_mc::components::multiplication<ArithmetizationType, W0, W1, W2>;
                    using sub_component = nil::actor_blueprint_mc::components::subtraction<ArithmetizationType, W0, W1, W2>;
                    using div_component = nil::actor_blueprint_mc::components::division<ArithmetizationType, W0, W1, W2, W3>;

                    using b_poly_coeff_component =
                        nil::actor_blueprint_mc::components::b_poly_coefficients<ArithmetizationType,
                                                            KimchiCommitmentParamsType::eval_rounds, W0, W1, W2, W3, W4,
                                                            W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using kimchi_constants = nil::actor_blueprint_mc::components::kimchi_inner_constants<KimchiParamsType>;

                    constexpr static const std::size_t srs_len = KimchiCommitmentParamsType::srs_len;
                    constexpr static const std::size_t eval_rounds = KimchiCommitmentParamsType::eval_rounds;
                    constexpr static const std::size_t challenges_len = CommsLen * eval_rounds;

                    constexpr static std::size_t scalars_len() {
                        return srs_len + kimchi_constants::srs_padding_size() + CommsLen;
                    }

                    using prepare_scalars_component =
                        nil::actor_blueprint_mc::components::prepare_scalars<ArithmetizationType, CurveType, scalars_len(), W0, W1, W2, W3,
                                                        W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14>;

                    using batch_proof = batch_evaluation_proof_scalar<BlueprintFieldType, ArithmetizationType,
                                                                      KimchiParamsType, KimchiCommitmentParamsType>;

                    constexpr static std::size_t rows() {
                        std::size_t row = 0;

                        for (std::size_t i = 0; i < CommsLen; i++) {
                            row += mul_component::rows_amount;
                        }

                        for (std::size_t i = 0; i < challenges_len; i++) {
                            row += div_component::rows_amount;
                        }

                        for (std::size_t i = 0; i < eval_rounds; i++) {
                            for (std::size_t j = 0; j < CommsLen; j++) {
                                row += b_poly_coeff_component::rows_amount;

                                for (std::size_t k = 0; k < b_poly_coeff_component::polynomial_len; k++) {
                                    row += mul_component::rows_amount;
                                }
                            }
                        }

                        for (std::size_t i = 0; i < eval_rounds; i++) {
                            for (std::size_t j = 0;
                                j < KimchiCommitmentParamsType::srs_len + kimchi_constants::srs_padding_size();
                                j++) {

                                row += sub_component::rows_amount;
                            }
                        }

                        return row;
                    }

                public:
                    constexpr static const std::size_t rows_amount = rows();

                    constexpr static const std::size_t gates_amount = 0;

                    struct params_type {
                        std::vector<var> challenges;
                        var rand_base;
                    };

                    struct result_type {
                        std::array<var, scalars_len()> output;

                        result_type(std::size_t start_row_index) {
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         const std::size_t start_row_index) {

                        generate_assignments_constant(bp, assignment, params, start_row_index);

                        assert(params.challenges.size() == challenges_len);

                        std::size_t row = start_row_index;

                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);

                        std::array<var, scalars_len()> scalars;
                        std::size_t scalar_idx =
                            KimchiCommitmentParamsType::srs_len + kimchi_constants::srs_padding_size();

                        for (std::size_t i = 0;
                             i < KimchiCommitmentParamsType::srs_len + kimchi_constants::srs_padding_size();
                             i++) {
                            scalars[i] = zero;
                        }

                        var rand_base =
                            params.rand_base;

                        var rand_base_i = one;

                        std::array<var, CommsLen> rs;

                        for (std::size_t i = 0; i < CommsLen; i++) {
                            rs[i] = rand_base_i;
                            scalars[scalar_idx++] = rand_base_i;

                            rand_base_i =
                                nil::actor_blueprint_mc::components::generate_circuit<mul_component>(bp, assignment, {rand_base_i, rand_base}, row).output;
                            row += mul_component::rows_amount;
                        }

                        std::vector<var> challenges_inv(params.challenges.size());

                        for (std::size_t i = 0; i < params.challenges.size(); i++) {
                            challenges_inv[i] = nil::actor_blueprint_mc::components::generate_circuit<div_component>(bp, assignment,
                                                                                    {one, params.challenges[i]}, row)
                                                    .output;
                            row += div_component::rows_amount;
                        }

                        std::array<std::array<var, CommsLen>, eval_rounds> termss;

                        for (std::size_t i = 0; i < eval_rounds; i++) {
                            for (std::size_t j = 0; j < CommsLen; j++) {
                                auto s = b_poly_coeff_component::generate_circuit(bp, assignment, {params.challenges[0], one}, row)
                                         .output;
                                row += b_poly_coeff_component::rows_amount;

                                for (std::size_t k = 0; k < s.size(); k++) {
                                    s[k] = nil::actor_blueprint_mc::components::generate_circuit<mul_component>(bp, assignment, {s[k], rs[j]}, row)
                                           .output;
                                    row += mul_component::rows_amount;

                                    termss[i][k] = s[k];
                                }
                            }
                        }

                        for (std::size_t i = 0; i < termss.size(); i++) {
                            for (std::size_t j = 0;
                                j < KimchiCommitmentParamsType::srs_len + kimchi_constants::srs_padding_size();
                                j++) {

                                scalars[j] = nil::actor_blueprint_mc::components::generate_circuit<sub_component>(bp, assignment, {scalars[i], termss[i][j]}, row).output;
                                row += sub_component::rows_amount;
                            }
                        }

                        result_type res(start_row_index);
                        res.output = scalars;
                        return res;
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {
                        std::size_t row = start_row_index;

                        var zero = var(0, start_row_index, false, var::column_type::constant);
                        var one = var(0, start_row_index + 1, false, var::column_type::constant);

                        std::array<var, scalars_len()> scalars;
                        std::size_t scalar_idx =
                            KimchiCommitmentParamsType::srs_len + kimchi_constants::srs_padding_size();

                        for (std::size_t i = 0;
                             i < KimchiCommitmentParamsType::srs_len + kimchi_constants::srs_padding_size();
                             i++) {
                            scalars[i] = zero;
                        }

                        var rand_base = params.rand_base;

                        var rand_base_i = one;

                        std::array<var, CommsLen> rs;

                        for (std::size_t i = 0; i < CommsLen; i++) {
                            rs[i] = rand_base_i;
                            scalars[scalar_idx++] = rand_base_i;

                            rand_base_i =
                                mul_component::generate_assignments(assignment, {rand_base_i, rand_base}, row).output;
                            row += mul_component::rows_amount;
                        }

                        std::vector<var> challenges_inv(params.challenges.size());

                        for (std::size_t i = 0; i < params.challenges.size(); i++) {
                            challenges_inv[i] = div_component::generate_assignments(assignment,
                                                                                    {one, params.challenges[i]}, row)
                                                    .output;
                            row += div_component::rows_amount;
                        }

                        std::array<std::array<var, CommsLen>, eval_rounds> termss;

                        for (std::size_t i = 0; i < eval_rounds; i++) {
                            for (std::size_t j = 0; j < CommsLen; j++) {
                                auto s = b_poly_coeff_component::generate_assignments(assignment, {params.challenges[0], one}, row)
                                         .output;
                                row += b_poly_coeff_component::rows_amount;

                                for (std::size_t k = 0; k < s.size(); k++) {
                                    s[k] = mul_component::generate_assignments(assignment, {s[k], rs[j]}, row)
                                           .output;
                                    row += mul_component::rows_amount;

                                    termss[i][k] = s[k];
                                }
                            }
                        }

                        for (std::size_t i = 0; i < termss.size(); i++) {
                            for (std::size_t j = 0;
                                j < KimchiCommitmentParamsType::srs_len + kimchi_constants::srs_padding_size();
                                j++) {

                                scalars[j] = sub_component::generate_assignments(assignment, {scalars[i], termss[i][j]}, row).output;
                                row += sub_component::rows_amount;
                            }
                        }

                        result_type res(start_row_index);
                        res.output = scalars;
                        return res;
                    }

                private:

                    static void generate_assignments_constant(
                        blueprint<ArithmetizationType> &bp,
                        blueprint_public_assignment_table<ArithmetizationType> &assignment,
                        const params_type &params,
                        std::size_t component_start_row) {
                        std::size_t row = component_start_row;
                        assignment.constant(0)[row] = 0;
                        row++;
                        assignment.constant(0)[row] = 1;
                        row++;
                    }
                };

            }    // namespace components
    }            // namespace actor_blueprint_mc
}    // namespace nil

#endif    // ACTOR_BLUEPRINT_MC_BATCH_VERIFY_SCALAR_FIELD_HPP