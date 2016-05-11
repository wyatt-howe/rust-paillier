/// Paillier cryptosystem

use gmp::mpz::Mpz;
use gmp::rand::RandState;
use rand::Rng;
use rand;
use rng::generate_strong_prime;

pub struct PaiSk {
    pub lambda : Mpz,
    pub mu     : Mpz,
}

pub struct PaiPk {
    pub n : Mpz,
    pub n2 : Mpz,
    pub g : Mpz,
}

pub struct Paillier {
    pub pk : PaiPk,
    pub sk : PaiSk,
    pub rs : RandState,
}

impl Paillier {

    pub fn new(keysize: usize) -> Paillier {
        let mut rng = rand::thread_rng();
        let mut randstate = RandState::new();
        randstate.seed_ui( rng.gen::<u64>() );
        let (pk, sk) = Paillier::generate_key(&mut randstate, keysize);

        Paillier { pk: pk, sk: sk, rs: randstate }
    }

    fn generate_key(mut randstate: &mut RandState, keysize: usize) -> (PaiPk, PaiSk) {
        assert!(keysize % 2 == 0);

        let p = generate_strong_prime(&mut randstate, keysize/2);
        let q = generate_strong_prime(&mut randstate, keysize/2);
        
        let n           = &p * &q;
        let g       = &n + Mpz::one();
        let lambda  = (&p - Mpz::one()) * (&q - Mpz::one());
        let mu      = lambda.invert(&n).unwrap();
        let n2 = &n * &n;

        (PaiPk {n: n, n2: n2, g: g}, PaiSk {lambda: lambda, mu: mu} )
    }

    pub fn encrypt(&mut self, m: &Mpz) -> Mpz {
        let mut r = self.rs.urandom(&self.pk.n);
        while r.gcd(&self.pk.n) != Mpz::one() {
            r = self.rs.urandom(&self.pk.n);
        }

        let rn = r.powm(&self.pk.n, &self.pk.n2);
        let gm = m * &self.pk.n + Mpz::one();   // faster version
        // let gm = self.pk.g.powm(m, &self.pk.n2);

        (&gm*&rn ) % &self.pk.n2
    }

    pub fn decrypt(&mut self, c: &Mpz) -> Mpz {
        let cl = c.powm(&self.sk.lambda, &self.pk.n2);
        let lc = (cl - Mpz::one()) / &self.pk.n;
        (&lc * &self.sk.mu) % &self.pk.n
    }

    pub fn add_cipher(&self, c1: &Mpz, c2: &Mpz) -> Mpz {
        (c1 * c2) % &self.pk.n2
    }

    pub fn add_const(&self, c: &Mpz, m: &Mpz) -> Mpz {
        self.add_cipher(c, &self.pk.g.powm(&m, &self.pk.n2))
    }

    pub fn mul_const(&self, c: &Mpz, m: &Mpz) -> Mpz {
       c.powm(&m, &self.pk.n2) 
    }
}
