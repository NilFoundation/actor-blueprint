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

#ifndef ACTOR_BLUEPRINT_COMPONENTS_PLONK_LIMBS_HPP
#define ACTOR_BLUEPRINT_COMPONENTS_PLONK_LIMBS_HPP

#include <vector>
#include <array>
#include <iostream>

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor_blueprint/blueprint/plonk/circuit.hpp>
#include <nil/actor_blueprint/blueprint/plonk/assignment.hpp>
#include <nil/actor_blueprint/component.hpp>

#include <nil/actor/zk/components/algebra/fields/plonk/range_check.hpp>

namespace nil {
    namespace actor {
        namespace actor_blueprint {
            namespace components {

                ///////////////// From Limbs ////////////////////////////////
                // Recalculate field element from two 64-bit chunks
                // It's a part of transcript functionality
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/sponge.rs#L87
                // Input: x1 = [a_0, ..., a_63], x2 = [b_0, ..., b_63]
                // Output: y = [a_0, ...., a_63, b_0, ..., b_63]
                template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
                class from_limbs;

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                class from_limbs<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 3>:
                    public plonk_component<BlueprintFieldType, ArithmetizationParams, 3, 0, 0> {

                    using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 3, 0, 0>;

                public:

                    using var = typename component_type::var;

                    constexpr static const std::size_t rows_amount = 1;
                    constexpr static const std::size_t gates_amount = 1;

                    struct input_type {
                        var first_limb = var(0, 0, false);
                        var second_limb = var(0, 0, false);
                        input_type(std::array<var, 2> input) : first_limb(input[0]), second_limb(input[1]) {
                        }
                        input_type(var first, var second) : first_limb(first), second_limb(second) {
                        }
                    };

                    struct result_type {
                        var result = var(0, 0);

                        result_type(const from_limbs &component, std::size_t start_row_index) {
                            result = var(component.W(2), static_cast<int>(start_row_index), false, var::column_type::witness);
                        }
                    };

                    template <typename ContainerType>
                        from_limbs(ContainerType witness):
                            component_type(witness, {}, {}){};

                    template <typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                        from_limbs(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input):
                            component_type(witness, constant, public_input){};

                    from_limbs(
                        std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs):
                            component_type(witnesses, constants, public_inputs){};

                };

                    template<typename BlueprintFieldType, typename ArithmetizationParams>
                    using plonk_from_limbs = from_limbs<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 3>;

                    template<typename BlueprintFieldType, typename ArithmetizationParams>
                    typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::result_type
                        generate_circuit(
                        const plonk_from_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                        circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                        const std::uint32_t start_row_index) {

                        auto selector_iterator = assignment.find_selector(component);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                            generate_gates(component, bp, assignment, instance_input, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        assignment.enable_selector(first_selector_index, start_row_index);

                        generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                        return typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams>
                    typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::result_type
                        generate_assignments(
                        const plonk_from_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                        const std::uint32_t start_row_index) {

                        std::size_t row = start_row_index;
                        typename BlueprintFieldType::value_type first_limb =  var_value(assignment, instance_input.first_limb);
                        typename BlueprintFieldType::value_type second_limb = var_value(assignment, instance_input.second_limb);
                        assignment.witness(component.W(0), row) = first_limb;
                        assignment.witness(component.W(1), row) = second_limb;
                        typename BlueprintFieldType::value_type scalar = 2;
                        scalar = scalar.pow(64) * second_limb + first_limb;
                        assignment.witness(component.W(2), row) = scalar;

                        return typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams>
                        void generate_gates(
                        const plonk_from_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                        circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                        const std::size_t first_selector_index) {

                        using var = typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::var;

                        typename BlueprintFieldType::value_type scalar = 2;
                        auto constraint_1 = bp.add_constraint(var(component.W(0), 0) + var(component.W(1), 0) * scalar.pow(64) - var(component.W(2), 0));

                        bp.add_gate(first_selector_index, {constraint_1});
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams>
                        void generate_copy_constraints(
                        const plonk_from_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                        circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_from_limbs<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                        const std::uint32_t start_row_index) {

                        bp.add_copy_constraint(
                            {{component.W(0), static_cast<int>(start_row_index), false},
                             {instance_input.first_limb.index, instance_input.first_limb.rotation, false, instance_input.first_limb.type}});
                        bp.add_copy_constraint(
                            {{component.W(1), static_cast<int>(start_row_index), false},
                             {instance_input.second_limb.index, instance_input.second_limb.rotation, false, instance_input.second_limb.type}});
                    }

                /////////////// To Limbs ////////////////////////////////
                // Split field element into four 64-bit chunks
                // It's a part of transcript functionality
                // https://github.com/o1-labs/proof-systems/blob/1f8532ec1b8d43748a372632bd854be36b371afe/oracle/src/sponge.rs#L110
                // Input: x = [a_0, ...., a255]
                // Output: y0 = [a_0, ..., a_63], y1 = [a_64, ..., a_127], y2 = [a_128, ..., a_191], y3 = [a_192, ...,
                // a_255]
                template<typename ArithmetizationType, std::uint32_t WitnessesAmount>
                class to_limbs;

                template<typename BlueprintFieldType, typename ArithmetizationParams>
                class to_limbs<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 15>:
                    public plonk_component<BlueprintFieldType, ArithmetizationParams, 15, 1, 0> {

                    using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, 15, 1, 0>;

                    constexpr static const std::size_t chunk_size = 64;
                    using range_check_component = nil::actor::actor_blueprint::components::range_check<
                        actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                        chunk_size, 15>;

                public:
                    using var = typename component_type::var;

                    constexpr static const std::size_t chunk_size_public = chunk_size;
                    constexpr static const std::size_t chunk_amount = 4;
                    constexpr static const std::size_t rows_amount =
                        1 + 2 * chunk_amount * range_check_component::rows_amount;
                    constexpr static const std::size_t gates_amount = 1;

                    struct input_type {
                        var param;

                        input_type(var value) : param(value) {
                        }
                    };

                    struct result_type {
                        std::array<var, 4> result;

                        result_type(const to_limbs &component, std::size_t start_row_index) {
                            result = {var(component.W(1), static_cast<int>(start_row_index), false, var::column_type::witness),
                                      var(component.W(2), static_cast<int>(start_row_index), false, var::column_type::witness),
                                      var(component.W(3), static_cast<int>(start_row_index), false, var::column_type::witness),
                                      var(component.W(4), static_cast<int>(start_row_index), false, var::column_type::witness)};
                        }
                    };

                    template <typename ContainerType>
                        to_limbs(ContainerType witness):
                            component_type(witness, {}, {}){};

                    template <typename WitnessContainerType, typename ConstantContainerType, typename PublicInputContainerType>
                        to_limbs(WitnessContainerType witness, ConstantContainerType constant, PublicInputContainerType public_input):
                            component_type(witness, constant, public_input){};

                    to_limbs(
                        std::initializer_list<typename component_type::witness_container_type::value_type> witnesses,
                        std::initializer_list<typename component_type::constant_container_type::value_type> constants,
                        std::initializer_list<typename component_type::public_input_container_type::value_type> public_inputs):
                            component_type(witnesses, constants, public_inputs){};
                };

                    template<typename BlueprintFieldType, typename ArithmetizationParams>
                    using plonk_to_limbs = to_limbs<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>, 15>;

                    template<typename BlueprintFieldType, typename ArithmetizationParams>
                    typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::result_type
                        generate_circuit(
                        const plonk_to_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                        circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                        const std::uint32_t start_row_index) {

                        using var = typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::var;

                        using ArithmetizationType = actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        range_check<ArithmetizationType, component.chunk_size_public, 15> range_check_instance(
                                {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                                    component.W(5), component.W(6), component.W(7), component.W(8), component.W(9),
                                        component.W(10), component.W(11), component.W(12), component.W(13), component.W(14)},{component.C(0)},{});

                        auto selector_iterator = assignment.find_selector(component);
                        std::size_t first_selector_index;

                        if (selector_iterator == assignment.selectors_end()) {
                            first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                            generate_gates(component, bp, assignment, instance_input, first_selector_index);
                        } else {
                            first_selector_index = selector_iterator->second;
                        }

                        assignment.enable_selector(first_selector_index, start_row_index);

                        std::size_t row = start_row_index;
                        std::array<var, component.chunk_amount> chunks = {
                            var(component.W(1), row, false),
                            var(component.W(2), row, false),
                            var(component.W(3), row, false),
                            var(component.W(4), row, false)
                        };
                        std::array<var, component.chunk_amount> b_chunks_vars = {
                            var(component.W(5), row, false),
                            var(component.W(6), row, false),
                            var(component.W(7), row, false),
                            var(component.W(8), row, false)
                        };

                        row++;

                        for (std::size_t i = 0; i < component.chunk_amount; i++) {
                            generate_circuit(range_check_instance, bp, assignment, {chunks[i]}, row);
                            row += range_check<ArithmetizationType, component.chunk_size_public, 15>::rows_amount;
                            generate_circuit(range_check_instance, bp, assignment, {b_chunks_vars[i]}, row);
                            row += range_check<ArithmetizationType, component.chunk_size_public, 15>::rows_amount;
                        }

                        generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);

                        return typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);

                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams>
                    typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::result_type
                        generate_assignments(
                        const plonk_to_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::input_type instance_input,
                        const std::uint32_t start_row_index) {

                        using var = typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::var;

                        using ArithmetizationType = actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>;
                        range_check<ArithmetizationType, component.chunk_size_public, 15> range_check_instance(
                                {component.W(0), component.W(1), component.W(2), component.W(3), component.W(4),
                                    component.W(5), component.W(6), component.W(7), component.W(8), component.W(9),
                                        component.W(10), component.W(11), component.W(12), component.W(13), component.W(14)},{component.C(0)},{});

                        std::size_t row = start_row_index;
                        typename BlueprintFieldType::value_type value = var_value(assignment, instance_input.param);
                        auto value_data = value.data;
                        auto shifted_data = value_data >> 64 << 64;
                        assignment.witness(component.W(0), row) = value_data;
                        assignment.witness(component.W(1), row) = value_data - shifted_data;
                        value_data = value_data >> 64;
                        shifted_data = shifted_data >> 64 >> 64 << 64;
                        assignment.witness(component.W(2), row) = value_data - shifted_data;
                        value_data = value_data >> 64;
                        shifted_data = shifted_data >> 64 >> 64 << 64;
                        assignment.witness(component.W(3), row) = value_data - shifted_data;
                        value_data = value_data >> 64;
                        assignment.witness(component.W(4), row) = value_data;

                        typename BlueprintFieldType::extended_integral_type modulus_p = BlueprintFieldType::modulus;
                        typename BlueprintFieldType::extended_integral_type one = 1;
                        typename BlueprintFieldType::extended_integral_type power = (one << 256);
                        typename BlueprintFieldType::extended_integral_type c = power - modulus_p;
                        typename BlueprintFieldType::extended_integral_type mask = (one << 64) - 1;
                        std::array<typename BlueprintFieldType::extended_integral_type, 4> c_chunks = {
                            c & mask, (c >> 64) & mask, (c >> 128) & mask, (c >> 192) & mask};

                        typename BlueprintFieldType::extended_integral_type b =
                            typename BlueprintFieldType::extended_integral_type(value.data) + c;
                        std::array<typename BlueprintFieldType::extended_integral_type, 4> b_chunks = {
                            b & mask, (b >> 64) & mask, (b >> 128) & mask, (b >> 192) & mask};
                        assignment.witness(component.W(5), row) = b_chunks[0];
                        assignment.witness(component.W(6), row) = b_chunks[1];
                        assignment.witness(component.W(7), row) = b_chunks[2];
                        assignment.witness(component.W(8), row) = b_chunks[3];
                        assignment.witness(component.W(9), row) =
                            (typename BlueprintFieldType::extended_integral_type(assignment.witness(component.W(1), row).data) +
                             c_chunks[0] - b_chunks[0]) >>
                            64;
                        assignment.witness(component.W(10), row) =
                            (typename BlueprintFieldType::extended_integral_type(assignment.witness(component.W(2), row).data) +
                             c_chunks[1] - b_chunks[1] +
                             typename BlueprintFieldType::extended_integral_type(assignment.witness(component.W(9), row).data)) >>
                            64;
                        assignment.witness(component.W(11), row) =
                            (typename BlueprintFieldType::extended_integral_type(assignment.witness(component.W(3), row).data) +
                             c_chunks[2] - b_chunks[2] +
                             typename BlueprintFieldType::extended_integral_type(assignment.witness(component.W(10), row).data)) >>
                            64;
                        std::array<var, component.chunk_amount> chunks = {
                            var(component.W(1), row, false),
                            var(component.W(2), row, false),
                            var(component.W(3), row, false),
                            var(component.W(4), row, false)};

                        std::array<var, component.chunk_amount> b_chunks_vars = {
                            var(component.W(5), row, false),
                            var(component.W(6), row, false),
                            var(component.W(7), row, false),
                            var(component.W(8), row, false)};

                        row++;

                        for (std::size_t i = 0; i < component.chunk_amount; i++) {
                            generate_assignments(range_check_instance, assignment, {chunks[i]}, row);
                            row += range_check<ArithmetizationType, component.chunk_size_public, 15>::rows_amount;
                            generate_assignments(range_check_instance, assignment, {b_chunks_vars[i]}, row);
                            row += range_check<ArithmetizationType, component.chunk_size_public, 15>::rows_amount;
                        }

                        return typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::result_type(component, start_row_index);
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams>
                        void generate_gates(
                        const plonk_to_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                        circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                        const std::size_t first_selector_index) {

                        using var = typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::var;

                        typename BlueprintFieldType::value_type scalar = 2;
                        typename BlueprintFieldType::extended_integral_type modulus_p = BlueprintFieldType::modulus;
                        typename BlueprintFieldType::extended_integral_type one = 1;
                        typename BlueprintFieldType::extended_integral_type power = (one << 256);
                        typename BlueprintFieldType::extended_integral_type c = power - modulus_p;
                        typename BlueprintFieldType::extended_integral_type mask = (one << 64) - 1;
                        std::array<typename BlueprintFieldType::extended_integral_type, 4> c_chunks = {
                            c & mask, (c >> 64) & mask, (c >> 128) & mask, (c >> 192) & mask};
                        auto constraint_1 =
                            bp.add_constraint(var(component.W(1), 0) + var(component.W(2), 0) * scalar.pow(64) + var(component.W(3), 0) * scalar.pow(128) +
                                              var(component.W(4), 0) * scalar.pow(192) - var(component.W(0), 0));
                        auto constraint_2 =
                            bp.add_constraint(-var(component.W(1), 0) - typename BlueprintFieldType::value_type(c_chunks[0]) +
                                              var(component.W(5), 0) + var(component.W(9), 0) * (one << 64));
                        auto constraint_3 =
                            bp.add_constraint(-var(component.W(2), 0) - typename BlueprintFieldType::value_type(c_chunks[1]) -
                                              var(component.W(9), 0) + var(component.W(6), 0) + var(component.W(10), 0) * (one << 64));
                        auto constraint_4 =
                            bp.add_constraint(-var(component.W(3), 0) - typename BlueprintFieldType::value_type(c_chunks[2]) -
                                              var(component.W(10), 0) + var(component.W(7), 0) + var(component.W(11), 0) * (one << 64));
                        auto constraint_5 =
                            bp.add_constraint(-var(component.W(4), 0) - typename BlueprintFieldType::value_type(c_chunks[3]) -
                                              var(component.W(11), 0) + var(component.W(8), 0));

                        auto constraint_6 = bp.add_constraint(var(component.W(9), 0) * (var(component.W(9), 0) - 1));
                        auto constraint_7 = bp.add_constraint(var(component.W(10), 0) * (var(component.W(10), 0) - 1));
                        auto constraint_8 = bp.add_constraint(var(component.W(11), 0) * (var(component.W(11), 0) - 1));

                        bp.add_gate(first_selector_index,
                                    {constraint_1, constraint_2, constraint_3, constraint_4, constraint_5, constraint_6,
                                     constraint_7, constraint_8});
                    }

                    template<typename BlueprintFieldType, typename ArithmetizationParams>
                        void generate_copy_constraints(
                        const plonk_to_limbs<BlueprintFieldType, ArithmetizationParams> &component,
                        circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_to_limbs<BlueprintFieldType, ArithmetizationParams>::input_type &instance_input,
                        const std::uint32_t start_row_index) {

                        bp.add_copy_constraint({{component.W(0), static_cast<int>(start_row_index), false},
                                                {instance_input.param.index, instance_input.param.rotation, false, instance_input.param.type}});
                    }

            }    // namespace components
        }        // namespace blueprint
    }            // namespace actor
}    // namespace nil

#endif    // ACTOR_BLUEPRINT_COMPONENTS_PLONK_CURVE_ELEMENT_ORACLES_DETAIL_COMPONENT_15_WIRES_HPP
