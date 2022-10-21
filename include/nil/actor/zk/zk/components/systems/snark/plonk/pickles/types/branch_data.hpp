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

#ifndef ACTOR_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_PLONK_HPP
#define ACTOR_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_PLONK_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor/zk/blueprint/plonk.hpp>
#include <nil/actor/zk/component.hpp>

namespace nil {
    namespace actor {
        namespace zk {
            namespace components {

                // https://github.com/MinaProtocol/mina/blob/develop/src/lib/mina_wire_types/pickles/pickles_composition_types.ml#L3-L15
                template<typename FieldType>
                struct branch_data {
                    using var = snark::plonk_variable<FieldType>;

                    enum proofs_verified_type {
                        N0, N1, N2
                    };

                    proofs_verified_type proofs_verified;
                    std::size_t domain_log2;
                };
                };
            }    // namespace components
        }        // namespace zk
    }            // namespace crypto3
}    // namespace nil

#endif    // ACTOR_ZK_BLUEPRINT_PLONK_PICKLES_TYPES_PLONK_HPP