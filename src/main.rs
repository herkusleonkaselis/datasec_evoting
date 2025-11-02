use std::ops::Mul;

use crypto_bigint::{
    CheckedAdd, CheckedMul, Integer, RandomBits, RandomMod, U128,
    modular::{MontyForm, MontyParams},
};
use crypto_primes::{generate_prime, generate_safe_prime};

struct RsaPrivateKey<T> {
    pub p: T,
    pub q: T,
}

impl<T: Integer + RandomBits + RandomMod> RsaPrivateKey<T> {
    pub fn new(bit_length: usize) -> Self {
        let p = generate_prime(bit_length as u32);
        let q = generate_prime(bit_length as u32);

        RsaPrivateKey { p, q }
    }
}

struct RsaPublicKey<T> {
    n: T,
}

impl<T: CheckedMul> RsaPublicKey<T> {
    pub fn new(private_key: &RsaPrivateKey<T>) -> Self {
        let n = private_key
            .p
            .checked_mul(&private_key.q)
            .expect("N=n*q should fit into given group");

        RsaPublicKey { n }
    }
}

type UintType = U128; // Sufficient where the problem only asks for 28 bits.
static N_VOTERS: usize = 16; // log2(N_VOTERS) determines the amount of bits needed to encode the number of voters per candidate
static N_CANDIDATES: usize = 3; // Together with log2(N_VOTERS), determines the size of the vote message
static CHOSEN_CANDIDATE_IDX: u32 = 0; // Determines ehich candidate position in the message to shift a vote (value 1) into
static NUM_BITS_WORKING: usize = 14;

fn main() {
    let private_key: RsaPrivateKey<UintType> = RsaPrivateKey::new(14); // Working with 28 bits...
    let public_key: RsaPublicKey<UintType> = RsaPublicKey::new(&private_key);
    let r: UintType = generate_safe_prime(NUM_BITS_WORKING as u32); // Signing nonce.

    println!("ri = {}", r.to_string_radix_vartime(10));
    println!("N = {}", public_key.n.to_string_radix_vartime(10));

    let vote_message;
    {
        let per_candidate_bits = N_VOTERS.ilog2(); // Number of bits needed to fit votes per candidate in respect to amount of voters
        let vote_shift = CHOSEN_CANDIDATE_IDX * per_candidate_bits;
        assert!(vote_shift <= per_candidate_bits * N_CANDIDATES as u32);
        vote_message = UintType::from_u8(1).shl(vote_shift);
    }

    let vote_ciphertext;
    {
        let n = public_key.n;
        let one = UintType::ONE;
        let n_plus_one: UintType = n
            .checked_add(&one)
            .expect("N+1 must not overflow in given datatype. Increase UintType.");

        let n_squared = n
            .checked_square()
            .expect("N^2 must not overflow in the given datatype. Increase width."); // Not exactly true :)
        let odd_modulus = n_squared
            .to_odd()
            .expect("N^2 must be odd, because p is odd and q is odd. odd*odd->odd, odd^2=odd.");

        // Monty-form enables modular exponentiation at low-cost.
        // A Monty form must be initialized for a given integer with an odd modulus before computation.
        let monty_params_modulus_nsquare = MontyParams::new(odd_modulus);
        let n_plus_one = MontyForm::new(&n_plus_one, monty_params_modulus_nsquare.clone());
        let n_plus_one_pow_m = n_plus_one.pow(&vote_message);

        let r_mod_nsquare = MontyForm::new(&r, monty_params_modulus_nsquare);
        let r_pow_n = r_mod_nsquare.pow(&n);

        let result = n_plus_one_pow_m.mul(r_pow_n);
        let result_int = result.retrieve();

        vote_ciphertext = result_int;
    }

    println!("ci = {}", vote_ciphertext.to_string_radix_vartime(10));
}
