//---------------------------------------------------------------------------//
// Copyright (c) 2021 Mikhail Komarov <nemo@nil.foundation>
// Copyright (c) 2021 Nikita Kaskov <nbering@nil.foundation>
// Copyright (c) 2022 Ilia Shirobokov <i.shirobokov@nil.foundation>
// Copyright (c) 2022 Alisa Cherniaeva <a.cherniaeva@nil.foundation>
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
// @file Declaration of interfaces for PLONK field element multiplication by constant component.
//---------------------------------------------------------------------------//

#ifndef ACTOR_BLUEPRINT_COMPONENTS_PLONK_FIELD_MULTIPLICATION_BY_CONSTANT_HPP
#define ACTOR_BLUEPRINT_COMPONENTS_PLONK_FIELD_MULTIPLICATION_BY_CONSTANT_HPP

#include <cmath>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor_blueprint/blueprint/plonk/assignment.hpp>
#include <nil/actor_blueprint/blueprint/plonk/circuit.hpp>
#include <nil/actor_blueprint/component.hpp>

namespace nil {
    namespace actor {
        namespace actor_blueprint {
            namespace components {
    
                // Input: x, c \in F_p, c is fixed public parameter
                // Output: z = c * y, z \in F_p
                template<typename ArithmetizationType, typename FieldType, std::uint32_t WitnessesAmount>
                class mul_by_constant;
    
                template<typename BlueprintFieldType,
                         typename ArithmetizationParams>
                class mul_by_constant<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, 2>:
                    public plonk_component<BlueprintFieldType, ArithmetizationParams, 2, 1, 0> {
    
                    constexpr static const std::int32_t WitnessAmount = 2;
                
                    using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessAmount, 1, 0>;
    
                public:
    
                    const std::size_t gates_amount = 1;
    
                    using var = typename component_type::var;
    
                    struct input_type {
                        var x = var(0, 0, false);
                        typename BlueprintFieldType::value_type constant;
                    };
    
                    struct result_type {
                        var output = var(0, 0, false);
                        result_type(const mul_by_constant &component, std::uint32_t start_row_index) {
                            output = var(component.W(1), start_row_index, false, var::column_type::witness);
                        }
    
                        result_type(const mul_by_constant &component, std::size_t start_row_index) {
                            output = var(component.W(1), start_row_index, false, var::column_type::witness);
                        }
                    };
    
                    template <typename ContainerType>
                    mul_by_constant(ContainerType witness):
                        component_type(witness, {}, {}){};
    
                    template <typename WitnessContainerType, typename ConstantContainerType,
                        typename PublicInputContainerType>
                    mul_by_constant(WitnessContainerType witness, ConstantContainerType constant,
                            PublicInputContainerType public_input):
                        component_type(witness, constant, public_input){};
    
                    mul_by_constant(std::initializer_list<
                            typename component_type::witness_container_type::value_type> witnesses,
                                   std::initializer_list<
                            typename component_type::constant_container_type::value_type> constants,
                                   std::initializer_list<
                            typename component_type::public_input_container_type::value_type> public_inputs):
                        component_type(witnesses, constants, public_inputs){};
                };
    
                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         std::int32_t WitnessAmount>
                using plonk_mul_by_constant =
                    mul_by_constant<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    BlueprintFieldType, WitnessAmount>;
    
                template<typename BlueprintFieldType,
                         typename ArithmetizationParams>
                typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2>::result_type
                    generate_assignments(
                        const plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2> &component,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2>::input_type instance_input,
                        const std::uint32_t start_row_index) {
    
                    const std::size_t j = start_row_index;
    
                    assignment.witness(component.W(0), j) = var_value(assignment, instance_input.x);
                    assignment.witness(component.W(1), j) = instance_input.constant *
                        var_value(assignment, instance_input.x);
    
                    assignment.constant(0, j) = instance_input.constant;
    
                    return typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2>::result_type(component, start_row_index);
                }
    
                template<typename BlueprintFieldType,
                         typename ArithmetizationParams>
                void generate_gates(
                    const plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2> &component,
                    circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2>::input_type &instance_input,
                    const std::size_t first_selector_index) {
    
                    using var = typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2>::var;
    
                    auto constraint_1 = bp.add_constraint(
                        var(component.W(0), 0) * var(0, 0, true, var::column_type::constant) - var(component.W(1), 0));
    
                    bp.add_gate(first_selector_index, {constraint_1});
                }
    
                template<typename BlueprintFieldType,
                         typename ArithmetizationParams>
                void generate_copy_constraints(
                    const plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2> &component,
                    circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2>::input_type &instance_input,
                    const std::size_t start_row_index) {
    
                    using var = typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2>::var;
    
                    const std::size_t j = start_row_index;
                    var component_x = var(component.W(0), static_cast<int>(j), false);
                    bp.add_copy_constraint({instance_input.x, component_x});
                }
    
                template<typename BlueprintFieldType,
                         typename ArithmetizationParams>
                typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2>::result_type
                    generate_circuit(
                        const plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2> &component,
                        circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2>::input_type &instance_input,
                        const std::size_t start_row_index){
    
                    auto selector_iterator = assignment.find_selector(component);
                    std::size_t first_selector_index;
    
                    if (selector_iterator == assignment.selectors_end()){
                        first_selector_index = assignment.allocate_selector(component,
                            component.gates_amount);
                        generate_gates(component, bp, assignment, instance_input, first_selector_index);
                    } else {
                        first_selector_index = selector_iterator->second;
                    }
    
                    assignment.enable_selector(first_selector_index, start_row_index);
    
                    generate_copy_constraints(component, bp, assignment, instance_input, start_row_index);
    
                    return typename plonk_mul_by_constant<BlueprintFieldType, ArithmetizationParams, 2>::result_type(component, start_row_index);
                }
            }    // namespace components
        }        // namespace actor_blueprint
    }            // namespace actor
}    // namespace nil

#endif    // ACTOR_BLUEPRINT_COMPONENTS_PLONK_FIELD_MULTIPLICATION_BY_CONSTANT_HPP
