
use super::rng::generate_strong_prime;
use super::rng::generate_urandom;
use super::gm::GM;
use super::gmp::mpz::Mpz;
use super::paillier::Paillier;
use super::gmp::rand::RandState;
use super::rand::Rng;
use super::rand;
use test::Bencher;

#[test]
fn strong_prime() {
    let mut rng = rand::thread_rng();
    let mut randstate = RandState::new();
    randstate.seed_ui( rng.gen::<u64>() );
    let p = generate_strong_prime(&mut randstate, 1024);
    assert!( p.probab_prime_p(40) == true);
}

#[test]
fn gm_gen_key() {
    let gmcrypto = GM::new(1024);
    assert!( &gmcrypto.sk.p != &gmcrypto.sk.q );
}

#[test]
fn gm_enc_dec() {
    let mut gmcrypto = GM::new(1024);
    let c = gmcrypto.encrypt(true);
    assert!( gmcrypto.decrypt(&c) == true);
    let c1 = gmcrypto.encrypt(true);
    assert!( &c1 != &c );
    assert!( gmcrypto.decrypt(&c1) == true);
    let c2 = gmcrypto.encrypt(false);
    let c3 = gmcrypto.encrypt(false);
    assert!( &c2 != &c3 );
    assert!( gmcrypto.decrypt(&c2) == false);
    assert!( gmcrypto.decrypt(&c3) == false);
}

#[test]
fn gm_xor() {
    let mut gmcrypto = GM::new(1024);
    let c = gmcrypto.encrypt(true);
    let c1 = gmcrypto.encrypt(true);
    let c2 = gmcrypto.encrypt(false);
    let c3 = gmcrypto.encrypt(false);
    let cc1 = gmcrypto.xor(&c, &c1);
    let cc2 = gmcrypto.xor(&c2, &c2);
    let cc3 = gmcrypto.xor(&c, &c3);
    let cc4 = gmcrypto.xor(&c3, &c1);
    assert!( gmcrypto.decrypt( &cc1 ) == false );
    assert!( gmcrypto.decrypt( &cc2 ) == false );
    assert!( gmcrypto.decrypt( &cc3 ) == true  );
    assert!( gmcrypto.decrypt( &cc4 ) == true  );
}

#[bench]
fn bench_gm_enc(b: &mut Bencher) {
    let mut gmcrypto = GM::new(1024);
    b.iter(|| { let c = gmcrypto.encrypt(false); c} );
}

#[bench]
fn bench_gm_dec(b: &mut Bencher) {
    let mut gmcrypto = GM::new(1024);
    let c = gmcrypto.encrypt(false);
    b.iter(|| { let m = gmcrypto.decrypt(&c); m} );
}

#[test]
fn pai_gen_key() {
    let paics = Paillier::new(1024);
    assert!(&paics.pk.n == &(&paics.pk.g - Mpz::one()));
}

#[test]
fn pai_enc_dec() {
    let m : Mpz = From::<i64>::from(1235);
    let mut paics = Paillier::new(1024);
    let c = paics.encrypt(&m);
    let mm = paics.decrypt(&c);
    assert!(&m == &mm);
}

#[test]
fn pai_add_cipher() {
    let mut paics = Paillier::new(1024);
    let m1 : Mpz = From::<i64>::from(1235);
    let m2 : Mpz = From::<i64>::from(5321);
    let c1 = paics.encrypt(&m1);
    let c2 = paics.encrypt(&m2);
    let c3 = paics.add_cipher(&c1, &c2);
    let m3 = paics.decrypt(&c3);
    assert!(&m3 == &From::from(6556i64));
}

#[test]
fn pai_add_const() {
    let mut paics = Paillier::new(1024);
    let m1 : Mpz = From::<i64>::from(1235);
    let m2 : Mpz = From::<i64>::from(5321);
    let c1 = paics.encrypt(&m1);
    let c3 = paics.add_const(&c1, &m2);
    let m3 = paics.decrypt(&c3);
    assert!(&m3 == &From::from(6556i64));
}

#[test]
fn pai_mul_const() {
    let mut paics = Paillier::new(1024);
    let m1 : Mpz = From::<i64>::from(1235);
    let m2 : Mpz = From::<i64>::from(5321);
    let c1 = paics.encrypt(&m1);
    let c3 = paics.mul_const(&c1, &m2);
    let m3 = paics.decrypt(&c3);
    assert!(&m3 == &From::from(1235i64 * 5321));
}

#[bench]
fn bench_pai_enc(b: &mut Bencher) {
    let m : Mpz = From::<i64>::from(1235);
    let mut paics = Paillier::new(1024);
    b.iter(|| { let c = paics.encrypt(&m); c} );
}

#[bench]
fn bench_pai_dec(b: &mut Bencher) {
    let m : Mpz = From::<i64>::from(1235);
    let mut paics = Paillier::new(1024);
    let c = paics.encrypt(&m);
    b.iter(|| { let m = paics.decrypt(&c); m} );
}
#[bench]
fn bench_slow_l(b: &mut Bencher) {
    let mut rng = rand::thread_rng();
    let mut randstate = RandState::new();
    randstate.seed_ui( rng.gen::<u64>() );
    let mut n = generate_urandom(&mut randstate, 1024);
    n.setbit(0);
    let u = generate_urandom(&mut randstate, 1024) * &n + Mpz::one();

    b.iter(|| { let m = (&u - Mpz::one()) / &n; m } )
}

#[bench]
fn bench_fast_l(b: &mut Bencher) {
    let mut rng = rand::thread_rng();
    let mut randstate = RandState::new();
    randstate.seed_ui( rng.gen::<u64>() );
    let mut n = generate_urandom(&mut randstate, 1024);
    n.setbit(0);
    let u = generate_urandom(&mut randstate, 1024) * &n + Mpz::one();
    let len = n.bit_length();
    let mut two_n = Mpz::zero();
    two_n.setbit(len);
    let ninv = n.invert(&two_n).unwrap();
    let m = (&u - Mpz::one()) / &n;
    let m1 = ( (&u - Mpz::one()) * &ninv ) % &two_n;
    assert!(&m == &m1);

    b.iter(|| { let m1 = ( (&u - Mpz::one()) * &ninv ) % &two_n ; m1  } )
}
