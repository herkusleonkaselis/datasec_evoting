use std::{io::Write, ops::Mul};

use crypto_bigint::{
    CheckedAdd, CheckedMul, CheckedSub, Constants, Integer, RandomBits, RandomMod, U128,
    modular::{MontyForm, MontyParams},
};
use crypto_primes::{generate_prime, generate_safe_prime};

struct AuthorityPrivateKey<T> {
    pub phi_n: T,
}

impl<T: Integer + RandomBits + RandomMod + Constants> AuthorityPrivateKey<T> {
    pub fn get_phi_n(p: &T, q: &T) -> T {
        let one = T::ONE;
        let p_minus_one = p.checked_sub(&one).expect("p-1 must not underflow.");
        let q_minus_one = q.checked_sub(&one).expect("q-1 must not underflow.");
        p_minus_one.checked_mul(&q_minus_one).expect(
            "(p-1)*(q-1) must not overflow. Check if the word size is sufficient to accomodate N ...",
        )
    }
    #[allow(dead_code)]
    pub fn new(bit_length: usize) -> Self {
        let p = generate_prime(bit_length as u32);
        let q = generate_prime(bit_length as u32);

        Self::from_primes(p, q)
    }
    pub fn from_primes(p: T, q: T) -> Self {
        let phi_n = Self::get_phi_n(&p, &q);

        AuthorityPrivateKey { phi_n }
    }
    pub fn from_phi_n(phi_n: T) -> Self {
        AuthorityPrivateKey { phi_n }
    }
}

struct AuthorityPublicKey<T> {
    pub n: T,
}

impl<T: CheckedMul> AuthorityPublicKey<T> {
    pub fn new(n: T) -> Self {
        AuthorityPublicKey { n }
    }
}

struct AuthorityKeypair<T> {
    pub private_key: AuthorityPrivateKey<T>,
    pub public_key: AuthorityPublicKey<T>,
}

type UintType = U128; // Sufficient where the problem only asks for 28 bits.
static N_VOTERS: usize = 16; // log2(N_VOTERS) determines the amount of bits needed to encode the number of voters per candidate
static N_CANDIDATES: usize = 3; // Together with log2(N_VOTERS), determines the size of the vote message
static CHOSEN_CANDIDATE_IDX: u32 = 0; // Determines ehich candidate position in the message to shift a vote (value 1) into
static NUM_BITS_WORKING: usize = 14;

static N: UintType = UintType::from_u32(14351); // The public key of the authority. Must be known before the program runs.

fn main() {
    // These belong to the central authority...
    // let private_key: RsaPrivateKey<UintType> = RsaPrivateKey::new(14); // Working with 28 bits...
    // let public_key: RsaPublicKey<UintType> = RsaPublicKey::new(&private_key);
    let n = N;
    let r: UintType = generate_safe_prime(NUM_BITS_WORKING as u32); // Signing nonce.

    println!("ri = {}", r.to_string_radix_vartime(10));
    println!("N = {}", N.to_string_radix_vartime(10));

    let per_candidate_bits = N_VOTERS.ilog2(); // Number of bits needed to fit votes per candidate in respect to amount of voters

    let vote_message;
    {
        let vote_shift = CHOSEN_CANDIDATE_IDX * per_candidate_bits;
        assert!(vote_shift <= per_candidate_bits * N_CANDIDATES as u32);
        vote_message = UintType::from_u8(1).shl(vote_shift);
    }

    // Will be required in both voting (enc) and verification (dec) routines.
    let n_squared = n
        .checked_square()
        .expect("N^2 must not overflow in the given datatype. Increase width."); // Not exactly true :)
    let n_squared_odd = n_squared
        .to_odd()
        .expect("N^2 must be odd, because p is odd and q is odd. odd*odd->odd, odd^2=odd.");

    let vote_ciphertext;
    {
        let one = UintType::ONE;
        let n_plus_one: UintType = n
            .checked_add(&one)
            .expect("N+1 must not overflow in given datatype. Increase UintType.");

        // Monty-form enables modular exponentiation at low-cost.
        // A Monty form must be initialized for a given integer with an odd modulus before computation.
        let monty_params_modulus_nsquare = MontyParams::new(n_squared_odd);
        let n_plus_one = MontyForm::new(&n_plus_one, monty_params_modulus_nsquare.clone());
        let n_plus_one_pow_m = n_plus_one.pow(&vote_message);

        let r_mod_nsquare = MontyForm::new(&r, monty_params_modulus_nsquare);
        let r_pow_n = r_mod_nsquare.pow(&n);

        let result = n_plus_one_pow_m.mul(r_pow_n);
        let result_int = result.retrieve();

        vote_ciphertext = result_int;
    }

    println!("ci = {}", vote_ciphertext.to_string_radix_vartime(10));

    println!("End of voting stage. Begin verification stage");
    println!("(p,q) or phi(n)? Input either p,q (separated by comma) or phi(N) without a comma.");
    let mut input = String::with_capacity(64);
    std::io::stdin()
        .read_line(&mut input)
        .expect("Failure to read stdin.");
    input = input.trim().replace(" ", "");

    let authority_priv = if input.contains(",") {
        println!("Interpreting as p,q");
        let split: Vec<&str> = input.split(',').collect();
        assert!(split.len() == 2);
        let p = UintType::from_str_radix_vartime(split[0], 10)
            .expect("p must be a valid Uint. Check if in word size bounds.");
        let q = UintType::from_str_radix_vartime(split[1], 10)
            .expect("q must be a valid Uint. Check if in word size bounds.");

        AuthorityPrivateKey::from_primes(p, q)
    } else {
        AuthorityPrivateKey::from_phi_n(
            UintType::from_str_radix_vartime(&input, 10)
                .expect("phi(n) must be a valid Uint. Check if the word size is sufficient."),
        )
    };
    let phi_n = authority_priv.phi_n;

    let authority_pub = AuthorityPublicKey::new(n);
    let authority_keypair = AuthorityKeypair {
        private_key: authority_priv,
        public_key: authority_pub,
    };

    println!("phi(n) = {}", phi_n.to_string_radix_vartime(10));

    eprintln!(
        "Enter the ciphertexts you would like to verify the contents of, input \"x\" to escape, \"pop\" to undo last:"
    );

    let mut vote_stack: Vec<UintType> = Vec::with_capacity(N_VOTERS);
    for i in 1.. {
        print!("{i}. ");
        std::io::stdout().flush().expect("Failure to flush stdout.");
        input.clear();
        std::io::stdin()
            .read_line(&mut input)
            .expect("Failure to use stdin");
        input = input.trim().to_lowercase();

        if input == "x" {
            break;
        } else if input == "pop" {
            if let Some(vote) = vote_stack.pop() {
                println!("Removed c={vote}.");
            } else {
                println!("Nothing to be done.");
            }
            continue;
        }

        let c = UintType::from_str_radix_vartime(&input, 10)
            .expect("Input ciphertext must be a valid Uint. Check if the word size is sufficient.");
        vote_stack.push(c);

        let m = decrypt(&c, &authority_keypair);
        let m1_small = m.as_words().first().expect("m must be non-empty");
        println!("m{i} = {m} ({m:b})", m = m1_small);
    }

    let n_squared_nz = n_squared.to_nz().expect("N-squared/N must not be 0");
    let product = vote_stack
        .iter()
        .fold(UintType::ONE, |acc, vote| acc.mul_mod(vote, &n_squared_nz));
    println!("prod(c) = {}", product.to_string_radix_vartime(10));

    let m_total = decrypt(&product, &authority_keypair);
    let m_total_small = m_total
        .as_words()
        .first()
        .expect("m_total must be non-empty");
    println!("m_final = {m} ({m:b})", m = m_total_small);

    let m_total_small_upcasted = UintType::from_u64(*m_total_small);
    assert!(
        m_total.eq(&m_total_small_upcasted),
        "Overflow when downcasting total votes to u64. Increase width..."
    );

    let mut votes = 0;
    for i in 0..N_CANDIDATES {
        let mask = N_VOTERS as u64 - 1;
        let votes_shifted = m_total_small >> (per_candidate_bits as usize * i);
        let votes_for_candidate = votes_shifted & mask;
        votes += votes_for_candidate;

        println!("Candidate {i}: {votes_for_candidate} votes.");
    }

    let n_voters = vote_stack.len();
    let votes = votes as usize;
    if votes > n_voters {
        let surplus = votes - n_voters;
        println!("Surplus of {surplus} votes... Curious.");
    } else if votes == n_voters {
        println!("All voters and votes accounted for.");
    } else {
        let deficit = n_voters - votes;
        println!("Deficit of {deficit} votes.");
    }
}

fn decrypt(ciphertext: &UintType, authority_keypair: &AuthorityKeypair<UintType>) -> UintType {
    let n = authority_keypair.public_key.n;
    let phi_n = authority_keypair.private_key.phi_n;

    let n_squared = n
        .checked_square()
        .expect("N^2 must not overflow in the given datatype. Increase width."); // Not exactly true :)
    let n_squared_odd = n_squared
        .to_odd()
        .expect("N^2 must be odd, because p is odd and q is odd. odd*odd->odd, odd^2=odd.");

    let d1 = {
        // Modulus N^2 for this block
        let monty_param_modulus_n_square = MontyParams::new(n_squared_odd);
        let c_mod_n_square = MontyForm::new(&ciphertext, monty_param_modulus_n_square);

        let c_pow_phi_n_mod_n_square = c_mod_n_square.pow(&phi_n);
        c_pow_phi_n_mod_n_square.retrieve()
    };

    let n_nonzero = n.to_nz().expect("N must not be 0.");

    let d2 = {
        // Modulus N
        let d1_minus_one = d1
            .checked_sub(&UintType::ONE)
            .expect("d1-1 must not underflow, d1 must not be 0.");

        let (quotient, _) = d1_minus_one.div_rem(&n_nonzero);
        quotient.rem(&n_nonzero)
    };

    let d3 = {
        // Modulus N
        phi_n
            .inv_mod(&n)
            .expect("Phi(N) must have a multiplicative inverse.")
    };

    d2.mul_mod(&d3, &n_nonzero)
}
