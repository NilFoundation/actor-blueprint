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

#ifndef ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_VERIFIER_INDEX_HPP
#define ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_VERIFIER_INDEX_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor/zk/blueprint/plonk.hpp>
#include <nil/actor/zk/component.hpp>

#include <nil/actor/zk/components/systems/snark/plonk/kimchi/kimchi_params.hpp>
#include <nil/actor/zk/components/systems/snark/plonk/kimchi/detail/commitment.hpp>

namespace nil {
    namespace actor {
        namespace zk {
            namespace components {
                typedef std::array<uint64_t, 2> kimchi_scalar_limbs;

                struct constraint_description {};

                template<typename BlueprintFieldType, std::size_t Permuts = 7>
                struct kimchi_verifier_index_scalar {
                    using var = snark::plonk_variable<BlueprintFieldType>;

                    enum argument_type {
                        Permutation,
                        Generic,
                    };

                    constexpr static const std::size_t constraints_amount = 2;

                    // nil::crypto3::math::evaluation_domain<Fr> domain;
                    std::size_t max_quot_size;
                    std::size_t domain_size;
                    std::array<typename BlueprintFieldType::value_type, Permuts> shift;

                    var omega;
                    std::map<argument_type, std::pair<int, int>> alpha_map;

                    std::array<constraint_description, constraints_amount> constraints;

                    kimchi_verifier_index_scalar() {
                        alpha_map[argument_type::Permutation] = {0, 0};
                        alpha_map[argument_type::Generic] = {1, 1};
                    }
                };

                template<typename CurveType,
                    typename KimchiParamsType>
                struct kimchi_verifier_index_base {
                    using FieldType = typename CurveType::base_field_type;
                    using commitment_params_type = typename KimchiParamsType::commitment_params_type;

                    using shifted_commitment_type = typename 
                        zk::components::kimchi_shifted_commitment_type<FieldType, 
                            commitment_params_type::shifted_commitment_split>;

                    using var = snark::plonk_variable<FieldType>;
                    using var_ec_point = typename zk::components::var_ec_point<FieldType>;

                    struct commitments {
                        std::array<shifted_commitment_type,
                            KimchiParamsType::permut_size> sigma_comm;
                        std::array<shifted_commitment_type,
                            KimchiParamsType::witness_columns> coefficient_comm;
                        shifted_commitment_type generic_comm;
                        shifted_commitment_type psm_comm;
                        std::vector<shifted_commitment_type> selectors_comm;
                        std::vector<shifted_commitment_type> lookup_selectors_comm;
                    };

                    var_ec_point H;
                    std::array<var_ec_point, commitment_params_type::srs_len> G;
                    std::array<var_ec_point, KimchiParamsType::public_input_size> lagrange_bases;
                    commitments comm;
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // ACTOR_ZK_BLUEPRINT_PLONK_KIMCHI_VERIFIER_INDEX_HPP