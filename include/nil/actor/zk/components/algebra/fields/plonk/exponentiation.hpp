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
// @file Declaration of interfaces for PLONK unified addition component.
//---------------------------------------------------------------------------//

#ifndef ACTOR_ZK_BLUEPRINT_PLONK_FIELD_EXPONENTIATION_HPP
#define ACTOR_ZK_BLUEPRINT_PLONK_FIELD_EXPONENTIATION_HPP

#include <cmath>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor/zk/blueprint/plonk.hpp>
#include <nil/actor/zk/assignment/plonk.hpp>
#include <nil/actor/zk/component.hpp>

namespace nil {
    namespace actor {
        namespace zk {
            namespace components {

                // Input: scalar, base \in Fp
                // Output: base**scalar
                template<typename ArithmetizationType, std::size_t ExponentSize, std::size_t... WireIndexes>
                class exponentiation;

                // res = base.pow(scalar)
                // W0     | W1            | W2            | W3                   | W4  | W5  | W6  | W7  | W8  | W9  |
                // W10 | W11 | W12 | W13  | W14  | base   | n = [b0...b8] | base^[b0b1b2] | W1^8 + base^[b3b4b5] | ... |
                // - | - | b_8 | b_7 | b_6 | b_5 | b_4 | b_3 | b_2 | b_1 |
                // ...    | ...           | ...           | ...                  | ... | - | - | ... | ... | ...
                // base   | n = scalar    | res           | ...                  | ... | - | - | ...
                // ....
                template<typename BlueprintFieldType, typename ArithmetizationParams, std::size_t ExponentSize,
                         std::size_t W0, std::size_t W1, std::size_t W2, std::size_t W3, std::size_t W4, std::size_t W5,
                         std::size_t W6, std::size_t W7, std::size_t W8, std::size_t W9, std::size_t W10,
                         std::size_t W11, std::size_t W12, std::size_t W13, std::size_t W14>
                class exponentiation<snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                                     ExponentSize, W0, W1, W2, W3, W4, W5, W6, W7, W8, W9, W10, W11, W12, W13, W14> {

                    typedef snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>
                        ArithmetizationType;

                    using var = snark::plonk_variable<BlueprintFieldType>;

                    constexpr static const std::size_t selector_seed = 0x0f09;

                    constexpr static const std::size_t witness_amount = 15;
                    constexpr static const std::size_t reserved_witnesses = 2;    // base, accumulated_n
                    constexpr static const std::size_t intermediate_start = W0 + reserved_witnesses;
                    constexpr static const std::size_t bits_per_intermediate_result =
                        2;    // defines
                              // max degree of the constraints
                              // 2 ** bits_per_intermediate_result
                    constexpr static const std::size_t intermediate_results_per_row =
                        (witness_amount - reserved_witnesses) / (bits_per_intermediate_result + 1);
                    constexpr static const std::size_t bits_per_row =
                        intermediate_results_per_row * bits_per_intermediate_result;
                    constexpr static const std::size_t padded_exponent_size =
                        ExponentSize + ((bits_per_row - ExponentSize % bits_per_row) %
                                        bits_per_row);    // for ExponentSize % bits_per_row = 0
                    constexpr static const std::size_t main_rows = (ExponentSize % bits_per_row == 0) ?
                                                                       (ExponentSize / bits_per_row) :
                                                                       (ExponentSize / bits_per_row) + 1;

                public:
                    constexpr static const std::size_t rows_amount = 1 + main_rows;
                    constexpr static const std::size_t gates_amount = 1;

                    struct params_type {
                        var base;
                        var exponent;
                    };

                    struct result_type {
                        var output = var(0, 0);

                        result_type(const params_type &params, std::size_t component_start_row) {
                            output = var(intermediate_start + intermediate_results_per_row - 1,
                                         component_start_row + rows_amount - 1, false);
                        }

                        result_type(std::size_t component_start_row) {
                            output = var(intermediate_start + intermediate_results_per_row - 1,
                                         component_start_row + rows_amount - 1, false);
                        }
                    };

                    static result_type
                        generate_circuit(blueprint<ArithmetizationType> &bp,
                                         blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                         const params_type &params,
                                         std::size_t start_row_index) {

                        auto selector_iterator = assignment.find_selector(selector_seed);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(selector_seed, gates_amount);
                            generate_gates(bp, assignment, params, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        assignment.enable_selector(first_selector_index, start_row_index + 1,
                                                   start_row_index + 1 + main_rows - 1);

                        generate_copy_constraints(bp, assignment, params, start_row_index);
                        generate_assignments_constants(assignment, params, start_row_index);

                        return result_type(params, start_row_index);
                    }

                    static result_type generate_assignments(blueprint_assignment_table<ArithmetizationType> &assignment,
                                                            const params_type &params,
                                                            std::size_t start_row_index) {

                        typename BlueprintFieldType::value_type base = assignment.var_value(params.base);
                        typename BlueprintFieldType::value_type exponent = assignment.var_value(params.exponent);

                        typename BlueprintFieldType::integral_type integral_exp =
                            typename BlueprintFieldType::integral_type(exponent.data);

                        std::array<bool, padded_exponent_size> bits = {false};
                        {
                            nil::marshalling::status_type status;
                            std::array<bool, 255> bits_all = nil::marshalling::pack<nil::marshalling::option::big_endian>(integral_exp, status);
                            std::copy(bits_all.end() - padded_exponent_size, bits_all.end(), bits.begin());
                        }

                        typename ArithmetizationType::field_type::value_type accumulated_n = 0;
                        typename BlueprintFieldType::value_type acc1 = 1;

                        // we use first empty row to unify first row gate woth others
                        assignment.witness(W1)[start_row_index] = 0;
                        assignment.witness(intermediate_start + intermediate_results_per_row - 1)[start_row_index] = 1;
                        std::size_t start_row_padded = start_row_index + 1;

                        std::size_t current_bit = 0;
                        for (std::size_t row = start_row_padded; row < start_row_padded + main_rows; row++) {
                            assignment.witness(W0)[row] = base;

                            for (std::size_t j = 0; j < intermediate_results_per_row; j++) {
                                typename ArithmetizationType::field_type::value_type intermediate_exponent = 0;
                                for (std::size_t bit_column = 0; bit_column < bits_per_intermediate_result;
                                     bit_column++) {
                                    std::size_t column_idx = W14 - j * (bits_per_intermediate_result)-bit_column;
                                    assignment.witness(column_idx)[row] = bits[current_bit];

                                    intermediate_exponent = 2 * intermediate_exponent + bits[current_bit];

                                    acc1 = acc1 * acc1;
                                    if (bits[current_bit]) {
                                        acc1 = acc1 * base;
                                    }

                                    current_bit++;
                                }
                                accumulated_n =
                                    (accumulated_n * (1 << bits_per_intermediate_result)) + intermediate_exponent;
                                assignment.witness(intermediate_start + j)[row] = acc1;
                            }
                            assignment.witness(W1)[row] = accumulated_n;
                        }

                        return result_type(params, start_row_index);
                    }

                private:
                    static void generate_gates(blueprint<ArithmetizationType> &bp,
                                               blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                               const params_type &params,
                                               const std::size_t first_selector_index) {

                        typename ArithmetizationType::field_type::value_type exponent_shift = 2;
                        exponent_shift = power(exponent_shift, bits_per_row);

                        std::vector<snark::plonk_constraint<BlueprintFieldType>> constraints;

                        snark::plonk_constraint<BlueprintFieldType> accumulated_n_constraint;
                        for (std::size_t j = 0; j < intermediate_results_per_row; j++) {
                            snark::plonk_constraint<BlueprintFieldType> intermediate_result_constraint =
                                j == 0 ? var(intermediate_start + intermediate_results_per_row - 1, -1) :
                                         var(intermediate_start + j - 1, 0);

                            for (std::size_t bit_column = 0; bit_column < bits_per_intermediate_result; bit_column++) {
                                std::size_t column_idx = W14 - j * (bits_per_intermediate_result)-bit_column;
                                snark::plonk_constraint<BlueprintFieldType> bit_check_constraint = bp.add_bit_check(var(column_idx, 0));
                                constraints.push_back(bit_check_constraint);

                                snark::plonk_constraint<BlueprintFieldType> bit_res = var(W0, 0) * var(column_idx, 0);
                                if (j == 0 && bit_column == 0) {
                                    accumulated_n_constraint = var(column_idx, 0);
                                } else {
                                    accumulated_n_constraint = 2 * accumulated_n_constraint + var(column_idx, 0);
                                }
                                intermediate_result_constraint = intermediate_result_constraint *
                                                                 intermediate_result_constraint *
                                                                 (bit_res + (1 - var(column_idx, 0)));
                            }

                            intermediate_result_constraint =
                                intermediate_result_constraint - var(intermediate_start + j, 0);
                            constraints.push_back(intermediate_result_constraint);
                        }

                        accumulated_n_constraint = accumulated_n_constraint + exponent_shift * var(W1, -1) - var(W1, 0);

                        constraints.push_back(accumulated_n_constraint);

                        snark::plonk_gate<BlueprintFieldType, snark::plonk_constraint<BlueprintFieldType>> gate(
                            first_selector_index, constraints);
                        bp.add_gate(gate);
                    }

                    static void
                        generate_copy_constraints(blueprint<ArithmetizationType> &bp,
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  std::size_t component_start_row) {

                        var zero(0, component_start_row, false, var::column_type::constant);
                        var one(0, component_start_row + 1, false, var::column_type::constant);

                        for (std::size_t row = component_start_row + 1; row < component_start_row + rows_amount; row++) {
                            bp.add_copy_constraint({{W0, static_cast<int>(row), false}, params.base});
                        }
                        bp.add_copy_constraint({{W1, static_cast<int>(component_start_row), false}, zero});
                        bp.add_copy_constraint({{intermediate_start + intermediate_results_per_row - 1,
                                                 static_cast<int>(component_start_row), false},
                                                one});
                        // check that the recalculated n is equal to the input challenge
                        bp.add_copy_constraint(
                           {{W1, static_cast<int>(component_start_row + rows_amount - 1), false}, params.exponent});
                    }

                    static void generate_assignments_constants(
                                                  blueprint_public_assignment_table<ArithmetizationType> &assignment,
                                                  const params_type &params,
                                                  const std::size_t start_row_index) {
                        std::size_t row = start_row_index;
                        assignment.constant(0)[row] = 0;
                        row++;
                        assignment.constant(0)[row] = 1;
                        row++;
                    }
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace actor
}    // namespace nil

#endif    // ACTOR_ZK_BLUEPRINT_PLONK_FIELD_EXPONENTIATION_HPP