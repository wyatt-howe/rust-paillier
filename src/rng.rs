use gmp::mpz::Mpz;
use gmp::rand::RandState;

pub fn generate_urandom(randstate: &mut RandState, len: usize) -> Mpz {

    let mut a : Mpz = randstate.urandom_2exp(len as u64 - 1);
    a.setbit(len - 1);
    assert!(a.bit_length() == len);
    a
}

pub fn generate_prime(randstate: &mut RandState, len: usize) -> Mpz {
    loop {
        let a: Mpz = generate_urandom(randstate, len);
        let p: Mpz = a.nextprime();
        if p.bit_length() == len { return p; }
    }
}
/// Generate a prime p such that p-1 has a large prime factor
pub fn generate_strong_prime(mut randstate: &mut RandState, len: usize) -> Mpz {

    // generate a half-size prime pp
    let pp = generate_prime(randstate, len / 2);
    let a = generate_urandom(randstate, len - len / 2 + 1);

    let mut p: Mpz = &pp * &a + Mpz::one();
    assert!( p.bit_length() >= len);
    loop {
        if p.probab_prime_p(40) { 
            if p.bit_length() == len {
                return p; 
            } else { 
                return generate_strong_prime(&mut randstate, len);
            }
        }
        else { p = &p + &a; }
    }
}
