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

#ifndef ACTOR_BLUEPRINT_MC_PLONK_PICKLES_TYPES_STATEMENT_HPP
#define ACTOR_BLUEPRINT_MC_PLONK_PICKLES_TYPES_STATEMENT_HPP

#include <nil/marshalling/algorithms/pack.hpp>

#include <nil/actor/zk/snark/arithmetization/plonk/constraint_system.hpp>

#include <nil/actor_blueprint_mc/blueprint/plonk.hpp>
#include <nil/actor_blueprint_mc/component.hpp>

#include <nil/actor_blueprint_mc/components/systems/snark/plonk/pickles/types/messages.hpp>
#include <nil/actor_blueprint_mc/components/systems/snark/plonk/pickles/types/proof_state.hpp>

namespace nil {
    namespace actor_blueprint_mc {
            namespace components {

                // TODO: link
                template<typename FieldType>
                struct statement_type {
                    using var = nil::actor::zk::snark::plonk_variable<FieldType>;
                    
                    pickles_proof_state_type<FieldType> proof_state;
                    messages_for_next_step_proof_type<FieldType> messages_for_next_step_proof;
                };
            }    // namespace components
    }            // namespace actor_blueprint_mc
}    // namespace nil

#endif    // ACTOR_BLUEPRINT_MC_PLONK_PICKLES_TYPES_STATEMENT_HPP