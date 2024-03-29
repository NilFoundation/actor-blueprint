#include <stdlib.h>
#include <iostream>

#include <nil/actor_blueprint/components/blueprint.hpp>

#include <nil/actor/zk/snark/algorithms/generate.hpp>
#include <nil/actor/zk/snark/algorithms/verify.hpp>
#include <nil/actor/zk/snark/algorithms/prove.hpp>
#include <nil/actor/zk/snark/schemes/ppzksnark/r1cs_gg_ppzksnark.hpp>

#include <nil/crypto3/algebra/curves/bls12.hpp>
#include <nil/crypto3/algebra/fields/bls12/base_field.hpp>
#include <nil/crypto3/algebra/fields/bls12/scalar_field.hpp>
#include <nil/crypto3/algebra/fields/arithmetic_params/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/multiexp/bls12.hpp>
#include <nil/crypto3/algebra/curves/params/wnaf/bls12.hpp>

#include <nil/crypto3/algebra/fields/detail/element/fp.hpp>
#include <nil/crypto3/algebra/fields/detail/element/fp2.hpp>

#include "test_component.hpp"

using namespace nil::actor::zk;
using namespace nil::crypto3::algebra;

int main(){

    using curve_type = curves::bls12<381>;
    using field_type = typename curve_type::scalar_field_type;
        
    // Create blueprint

    blueprint<field_type> bp;
    blueprint::value_type<field_type> out;
    blueprint::value_type<field_type> x;

    // Allocate variables

    out.allocate(bp);
    x.allocate(bp);

    // This sets up the blueprint variables
    // so that the first one (out) represents the public
    // input and the rest is private input

    bp.set_input_sizes(1);

    // Initialize component

    test_component<field_type> g(bp, out, x);
    g.generate_gates();
    
    // Add witness values

    bp.val(out) = 35;
    bp.val(x) = 3;

    g.generate_assignments();
    
    assert(bp.is_satisfied());

    const snark::r1cs_constraint_system<field_type> constraint_system = bp.get_constraint_system();

    const typename snark::r1cs_gg_ppzksnark<curve_type>::keypair_type keypair = snark::generate<crypto3::zk::snark::r1cs_gg_ppzksnark<curve_type>>(constraint_system);

    const typename snark::r1cs_gg_ppzksnark<curve_type>::proof_type proof = snark::prove<crypto3::zk::snark::r1cs_gg_ppzksnark<curve_type>>(keypair.first, bp.primary_input(), bp.auxiliary_input());

    bool verified = snark::verify<crypto3::zk::snark::r1cs_gg_ppzksnark<curve_type>>(keypair.second, bp.primary_input(), proof);

    std::cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << std::endl;
    std::cout << "Verification status: " << verified << std::endl;

    const typename snark::r1cs_gg_ppzksnark<curve_type>::verification_key_type vk = keypair.second;

    return 0;
}
