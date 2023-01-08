use bellman::domain::Scalar;
use bellman::gadgets::num::AllocatedNum;
use zcash_proofs::circuit::ecc::*;
use bellman::{Circuit, ConstraintSystem, LinearCombination, SynthesisError};
use bellman::gadgets::sha256::sha256;
use bellman::gadgets::boolean::{self, Boolean};
use jubjub;
use zcash_proofs::constants::*;

pub struct Mint {
    pub token_id : Option<jubjub::Fr>,
    pub sk : Option<jubjub::Fr>,
    pub hash : Option<jubjub::Fr>
}

impl Circuit<bls12_381::Scalar> for Mint {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let token_id = boolean::field_into_boolean_vec_le(cs.namespace(|| "p"), self.token_id)?;
        let p = fixed_base_multiplication(
            cs.namespace(|| "computation of randomization for the signing key"),
            &SPENDING_KEY_GENERATOR,
            &token_id,
        )?;

        let sk = boolean::field_into_boolean_vec_le(cs.namespace(|| "q"), self.sk)?;
        let q = fixed_base_multiplication(
            cs.namespace(|| "computation of randomization for the signing key"),
            &SPENDING_KEY_GENERATOR,
            &sk,
        )?;

        let sum = p.add(cs.namespace(|| "add"), &q)?;
        
        let x = sum.get_u();

    
        let mut x_bits = x.to_bits_le_strict(cs.namespace(|| "bits")).unwrap();
        
        while x_bits.len()!=256{

            x_bits.push(Boolean::constant(false));
        }

        let hash_expect = sha256(cs.namespace(|| "sha256"), &x_bits).unwrap();
        // let hash_expect2  = sha256(cs.namespace(|| "sha256"), &hash_expect).unwrap();
        
        let mut hash = boolean::field_into_boolean_vec_le(cs.namespace(|| "p"), self.hash)?;

        while hash.len()!=256{

            hash.push(Boolean::constant(false));
        }
        for i in 0..255{
            Boolean::enforce_equal(cs.namespace(|| "equal"), &hash_expect[i], &hash[i]).unwrap();
        }
        

        Ok(())
    }

}


pub struct Transfer {
    pub token_id : Option<jubjub::Fr>,
    pub sk : Option<jubjub::Fr>,
    pub hash1 : Option<jubjub::Fr>,
    pub pk_x : Option<bls12_381::Scalar>,
    pub pk_y : Option<bls12_381::Scalar>,
    pub hash2 : Option<jubjub::Fr>

}

impl Circuit<bls12_381::Scalar> for Transfer {
    fn synthesize<CS: ConstraintSystem<bls12_381::Scalar>>(self, cs: &mut CS) -> Result<(), SynthesisError> {
        let token_id = boolean::field_into_boolean_vec_le(cs.namespace(|| "p"), self.token_id)?;
        let p = fixed_base_multiplication(
            cs.namespace(|| "computation of randomization for the signing key"),
            &SPENDING_KEY_GENERATOR,
            &token_id,
        )?;

        let sk = boolean::field_into_boolean_vec_le(cs.namespace(|| "q"), self.sk)?;
        let q = fixed_base_multiplication(
            cs.namespace(|| "computation of randomization for the signing key"),
            &SPENDING_KEY_GENERATOR,
            &sk,
        )?;

        let sum = p.add(cs.namespace(|| "add"), &q)?;
        
        let x = sum.get_u();

    
        let mut x_bits = x.to_bits_le_strict(cs.namespace(|| "bits")).unwrap();
        
        while x_bits.len()!=256{

            x_bits.push(Boolean::constant(false));
        }

        let hash_expect = sha256(cs.namespace(|| "sha256"), &x_bits).unwrap();
        // let hash_expect2  = sha256(cs.namespace(|| "sha256"), &hash_expect).unwrap();
        
        let mut hash = boolean::field_into_boolean_vec_le(cs.namespace(|| "p"), self.hash1)?;

        while hash.len()!=256{

            hash.push(Boolean::constant(false));
        }
        for i in 0..255{
            Boolean::enforce_equal(cs.namespace(|| "equal"), &hash_expect[i], &hash[i]).unwrap();
        }

        let pk_x = AllocatedNum::alloc(cs.namespace(|| "alloc_x"), || self.pk_x.ok_or(SynthesisError::AssignmentMissing))?;

        let pk_y = AllocatedNum::alloc(cs.namespace(|| "alloc_y"), || self.pk_y.ok_or(SynthesisError::AssignmentMissing))?;

        let pk = EdwardsPoint::interpret(cs.namespace(|| "new point"),&pk_x,&pk_y).unwrap();
        
        let sum_ = p.add(cs.namespace(|| "add_"), &pk).unwrap();

        let x_ = sum_.get_u();

        let mut x_bits_ = x_.to_bits_le_strict(cs.namespace(|| "bits_")).unwrap();
        
        while x_bits_.len()!=256{

            x_bits_.push(Boolean::constant(false));
        }

        let hash_expect_ = sha256(cs.namespace(|| "sha256_"), &x_bits_).unwrap();

        let mut hash2 = boolean::field_into_boolean_vec_le(cs.namespace(|| "p"), self.hash2)?;

        while hash2.len()!=256{

            hash2.push(Boolean::constant(false));
        }

        for i in 0..255{
            Boolean::enforce_equal(cs.namespace(|| "equal"), &hash_expect_[i], &hash2[i]).unwrap();
        }
        
        Ok(())
    }

}