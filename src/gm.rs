/// Goldwasser-Micali cryptosystem

use gmp::mpz::Mpz;
use gmp::rand::RandState;
use rand::Rng;
use rand;
use rng::generate_strong_prime;

pub struct GmSk {
    pub p: Mpz,
    pub q: Mpz,
}

pub struct GmPk {
    pub n: Mpz,
    pub x: Mpz,
}
pub struct GM {
    pub pk : GmPk,
    pub sk : GmSk,
    pub rs : RandState,
}

impl GM {

    pub fn new(keysize: usize) -> GM {
        let mut rng = rand::thread_rng();
        let mut randstate = RandState::new();
        randstate.seed_ui( rng.gen::<u64>() );
        let (pk, sk) = GM::generate_key(&mut randstate, keysize);

        GM { pk: pk, sk: sk, rs: randstate }
    }

    fn generate_key(mut randstate: &mut RandState, keysize: usize) -> (GmPk, GmSk) {
        assert!(keysize % 2 == 0);
        let p = generate_strong_prime(&mut randstate, keysize/2 + 1);
        let mut q = generate_strong_prime(&mut randstate, keysize/2);
        while p == q {
            q = generate_strong_prime(&mut randstate, keysize/2);
        }
        let n = &p*&q;
        assert!( n.bit_length() >= keysize );
        let mut x : Mpz;
        loop {
            x = randstate.urandom(&n);
            if x.legendre(&p) == -1 && x.legendre(&q) == -1 {
                break;
            }
        }

        (GmPk {n: n, x: x}, GmSk {p: p, q: q} )
    }

    pub fn encrypt(&mut self, m: bool) -> Mpz {

        let mm = if m {Mpz::one()} else {Mpz::zero()};

        let mut y = self.rs.urandom(&self.pk.n);
        while  y.gcd(&self.pk.n) != Mpz::one() {
            y = self.rs.urandom(&self.pk.n)
        }

        (&y * &y) * self.pk.x.powm(&mm, &self.pk.n) % &self.pk.n
    }

    pub fn decrypt(&mut self, c: &Mpz) -> bool {
        c.legendre(&self.sk.p) != 1 && c.legendre(&self.sk.q) != 1
    }

    pub fn xor(&mut self, c1: &Mpz, c2: &Mpz) -> Mpz {
        ( c1 * c2 ) %  &self.pk.n
    }
}
