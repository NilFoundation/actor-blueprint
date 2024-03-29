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
// @file Declaration of interfaces for auxiliary components for the RANGE component.
//---------------------------------------------------------------------------//

#ifndef ACTOR_BLUEPRINT_COMPONENTS_SCALAR_RANGE_EDWARD25519_HPP
#define ACTOR_BLUEPRINT_COMPONENTS_SCALAR_RANGE_EDWARD25519_HPP

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/crypto3/algebra/curves/ed25519.hpp>

#include <nil/actor_blueprint/blueprint/plonk/circuit.hpp>
#include <nil/actor_blueprint/blueprint/plonk/assignment.hpp>

namespace nil {
    namespace actor {
        namespace actor_blueprint {
            namespace components {
    
                template<typename ArithmetizationType, typename Ed25519Type, std::uint32_t WitnessesAmount>
                class scalar_non_native_range;
    
                template<typename BlueprintFieldType, typename ArithmetizationParams>
                class scalar_non_native_range<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    typename crypto3::algebra::curves::ed25519, 9>:
                    public plonk_component<BlueprintFieldType, ArithmetizationParams, 9, 0, 0> {
    
                    constexpr static const std::uint32_t WitnessesAmount = 9;
                
                    using component_type = plonk_component<BlueprintFieldType, ArithmetizationParams, WitnessesAmount, 0, 0>;
    
                public:
                    using var = typename component_type::var;
    
                    constexpr static const std::size_t rows_amount = 3;
                    constexpr static const std::size_t gates_amount = 1;
    
                    struct input_type {
                        var k; 
                    };
    
                    struct result_type {
                        std::array<var, 12> output;
                        result_type(const scalar_non_native_range &component, std::uint32_t start_row_index) {
                            output = { var(component.W(1), start_row_index, false), var(component.W(2), start_row_index, false), var(component.W(3), start_row_index, false),
                            var(component.W(4), start_row_index, false), var(component.W(5), start_row_index, false), var(component.W(6), start_row_index, false),
                            var(component.W(7), start_row_index, false), var(component.W(8), start_row_index, false), var(component.W(0), start_row_index + 1, false),
                            var(component.W(1), start_row_index + 1, false), var(component.W(2), start_row_index + 1, false), var(component.W(3), start_row_index + 1, false)
                            };
                        }
                    };
    
                    template <typename ContainerType>
                    scalar_non_native_range(ContainerType witness):
                        component_type(witness, {}, {}){};
    
                    template <typename WitnessContainerType, typename ConstantContainerType,
                        typename PublicInputContainerType>
                    scalar_non_native_range(WitnessContainerType witness, ConstantContainerType constant,
                            PublicInputContainerType public_input):
                        component_type(witness, constant, public_input){};
    
                    scalar_non_native_range(std::initializer_list<
                            typename component_type::witness_container_type::value_type> witnesses,
                                   std::initializer_list<
                            typename component_type::constant_container_type::value_type> constants,
                                   std::initializer_list<
                            typename component_type::public_input_container_type::value_type> public_inputs):
                        component_type(witnesses, constants, public_inputs){};
    
                };
    
                template<typename BlueprintFieldType,
                         typename ArithmetizationParams,
                         std::int32_t WitnessesAmount>
                using plonk_scalar_range =
                    scalar_non_native_range<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>,
                    typename crypto3::algebra::curves::ed25519,
                    WitnessesAmount>;
    
                template<typename BlueprintFieldType, typename ArithmetizationParams>
                typename plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9>::result_type
                    generate_assignments(
                        const plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9> &component,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_scalar_range<BlueprintFieldType,
                            ArithmetizationParams, 9>::input_type instance_input,
                        const std::uint32_t start_row_index) {
                    using Ed25519Type = typename crypto3::algebra::curves::ed25519;
                    using var = typename plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9>::var;
                    
                    std::size_t row = start_row_index;
                    typename Ed25519Type::scalar_field_type::integral_type base = 1;
                    typename Ed25519Type::scalar_field_type::extended_integral_type extended_base = 1;
                    typename Ed25519Type::scalar_field_type::integral_type mask = (base << 22) - 1;
                    typename BlueprintFieldType::integral_type pasta_k = typename BlueprintFieldType::integral_type(var_value(assignment, instance_input.k).data);
                    typename Ed25519Type::scalar_field_type::integral_type k = typename Ed25519Type::scalar_field_type::integral_type(pasta_k);
                    typename Ed25519Type::scalar_field_type::extended_integral_type q = Ed25519Type::scalar_field_type::modulus;
                    typename Ed25519Type::scalar_field_type::extended_integral_type d = (extended_base << 253) - q;
                    typename Ed25519Type::scalar_field_type::integral_type dk = k + typename Ed25519Type::scalar_field_type::integral_type(d);
                    std::array<typename Ed25519Type::scalar_field_type::integral_type, 12> k_chunks;
                    std::array<typename Ed25519Type::scalar_field_type::integral_type, 12> dk_chunks;
                    for (std::size_t i = 0; i < 12 ; i++){
                        k_chunks[i] = (k >> i*22) & mask;
                        dk_chunks[i] = (dk >> i*22) & mask;
                    }
                    assignment.witness(component.W(0), row) = k;
                    assignment.witness(component.W(1), row) = k_chunks[0];
                    assignment.witness(component.W(2), row) = k_chunks[1];
                    assignment.witness(component.W(3), row) = k_chunks[2];
                    assignment.witness(component.W(4), row) = k_chunks[3];
                    assignment.witness(component.W(5), row) = k_chunks[4];
                    assignment.witness(component.W(6), row) = k_chunks[5];
                    assignment.witness(component.W(7), row) = k_chunks[6];
                    assignment.witness(component.W(8), row) = k_chunks[7];
                    row++;
                    assignment.witness(component.W(0), row) = k_chunks[8];
                    assignment.witness(component.W(1), row) = k_chunks[9];
                    assignment.witness(component.W(2), row) = k_chunks[10];
                    assignment.witness(component.W(3), row) = k_chunks[11];
                    assignment.witness(component.W(4), row) = dk;
                    assignment.witness(component.W(5), row) = dk_chunks[0];
                    assignment.witness(component.W(6), row) = dk_chunks[1];
                    assignment.witness(component.W(7), row) = dk_chunks[2];
                    assignment.witness(component.W(8), row) = dk_chunks[3];
                    row++;
                    assignment.witness(component.W(0), row) = dk_chunks[4];
                    assignment.witness(component.W(1), row) = dk_chunks[5];
                    assignment.witness(component.W(2), row) = dk_chunks[6];
                    assignment.witness(component.W(3), row) = dk_chunks[7];
                    assignment.witness(component.W(4), row) = dk_chunks[8];
                    assignment.witness(component.W(5), row) = dk_chunks[9];
                    assignment.witness(component.W(6), row) = dk_chunks[10];
                    assignment.witness(component.W(7), row) = dk_chunks[11];
    
                    return typename plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9>::result_type(
                        component, start_row_index);
                }
    
                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_gates(
                    const plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9> &component,
                    circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9>::input_type &instance_input,
                    const std::size_t first_selector_index) {
                    using Ed25519Type = typename crypto3::algebra::curves::ed25519;
                    using var = typename plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9>::var;
    
                    typename BlueprintFieldType::integral_type base = 1;
                    typename Ed25519Type::scalar_field_type::extended_integral_type extended_base = 1;
                    typename Ed25519Type::scalar_field_type::extended_integral_type q = Ed25519Type::scalar_field_type::modulus;
                    typename Ed25519Type::scalar_field_type::extended_integral_type d = (extended_base << 253) - q;
                    auto constraint_1 = bp.add_constraint(var(component.W(0), -1) - (var(component.W(1), -1) + var(component.W(2), -1) * (base<< 22) + var(component.W(3), -1) * (base << 44) +
                    var(component.W(4), -1)* (base << 66) + var(component.W(5), -1) * (base <<88) + var(component.W(6), -1) * (base << 110) + var(component.W(7), -1) * (base << 132) + 
                    var(component.W(8), -1) * (base << 154) + var(component.W(0), 0)* (base << 176) + var(component.W(1), 0) * (base << 198) + var(component.W(2), 0) * (base << 220) +
                    var(component.W(3), 0) * (base << 242))); 
                    auto constraint_2 = bp.add_constraint(var(component.W(4), 0) - var(component.W(0), -1) - d);
                    auto constraint_3 = bp.add_constraint(var(component.W(4), 0) - (var(component.W(5), 0) + var(component.W(6), 0) * (base<< 22) + var(component.W(7), 0) * (base << 44) +
                    var(component.W(8), 0)* (base << 66) + var(component.W(0), +1) * (base <<88) + var(component.W(1), +1) * (base << 110) + var(component.W(2), +1) * (base << 132) + 
                    var(component.W(3), +1) * (base << 154) + var(component.W(4), +1)* (base << 176) + var(component.W(5), +1) * (base << 198) + var(component.W(6), +1) * (base << 220) +
                    var(component.W(7), +1) * (base << 242))); 
                    bp.add_gate(first_selector_index, {constraint_1, constraint_2, constraint_3});
                }
    
                template<typename BlueprintFieldType, typename ArithmetizationParams>
                void generate_copy_constraints(
                    const plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9> &component,
                    circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                    assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                    const typename plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9>::input_type &instance_input,
                    const std::size_t start_row_index) {
                    std::size_t row = start_row_index;
                    bp.add_copy_constraint({{component.W(0), static_cast<int>(row), false},
                        instance_input.k});
                }
    
                template<typename BlueprintFieldType, typename ArithmetizationParams>
                typename plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9>::result_type
                    generate_circuit(
                        const plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9> &component,
                        circuit<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &bp,
                        assignment<actor::zk::snark::plonk_constraint_system<BlueprintFieldType, ArithmetizationParams>> &assignment,
                        const typename plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9>::input_type &instance_input,
                        const std::size_t start_row_index) {
    
                    auto selector_iterator = assignment.find_selector(component);
                    std::size_t first_selector_index;
                    if (selector_iterator == assignment.selectors_end()) {
                        first_selector_index = assignment.allocate_selector(component, component.gates_amount);
                        generate_gates(component, bp, assignment, instance_input, first_selector_index);
                    } else {
                        first_selector_index = selector_iterator->second;
                    }
                    std::size_t j = start_row_index;
                    assignment.enable_selector(first_selector_index, j + 1);
                    generate_copy_constraints(component, bp, assignment, instance_input, j);
                    
                    return typename plonk_scalar_range<BlueprintFieldType, ArithmetizationParams, 9>::result_type(
                        component, start_row_index);
                }
    
            }    // namespace components
        }        // namespace actor_blueprint
    }            // namespace actor
}    // namespace nil

#endif    // ACTOR_BLUEPRINT_COMPONENTS_REDUCTION_HPP
