use super::mpz::{mpz_struct, Mpz, mpz_ptr, mpz_srcptr};
use super::mpf::{Mpf, mpf_srcptr};
use libc::{c_double, c_int, c_ulong};
use std::convert::{From, Into};
use std::mem::uninitialized;
use std::fmt;
use std::cmp::Ordering::{self, Greater, Less, Equal};
use std::ops::{Div, Mul, Add, Sub, Neg};

#[repr(C)]
pub struct mpq_struct {
    _mp_num: mpz_struct,
    _mp_den: mpz_struct
}

pub type mpq_srcptr = *const mpq_struct;
pub type mpq_ptr = *mut mpq_struct;

#[link(name = "gmp")]
extern "C" {
    fn __gmpq_init(x: mpq_ptr);
    fn __gmpq_clear(x: mpq_ptr);
    fn __gmpq_set(rop: mpq_ptr, op: mpq_srcptr);
    fn __gmpq_set_z(rop: mpq_ptr, op: mpz_srcptr);
    fn __gmpq_set_ui(rop: mpq_ptr, op1: c_ulong, op2: c_ulong);
    fn __gmpq_set_d(rop: mpq_ptr, op: c_double);
    fn __gmpq_set_f(rop: mpq_ptr, op: mpf_srcptr);
    fn __gmpq_cmp(op1: mpq_srcptr, op2: mpq_srcptr) -> c_int;
    fn __gmpq_cmp_ui(op1: mpq_srcptr, num2: c_ulong, den2: c_ulong) -> c_int;
    fn __gmpq_equal(op1: mpq_srcptr, op2: mpq_srcptr) -> c_int;
    fn __gmpq_add(sum: mpq_ptr, addend1: mpq_srcptr, addend2: mpq_srcptr);
    fn __gmpq_sub(difference: mpq_ptr, minuend: mpq_srcptr, subtrahend: mpq_srcptr);
    fn __gmpq_mul(product: mpq_ptr, multiplier: mpq_srcptr, multiplicand: mpq_srcptr);
    fn __gmpq_div(product: mpq_ptr, multiplier: mpq_srcptr, multiplicand: mpq_srcptr);
    fn __gmpq_neg(negated_operand: mpq_ptr, operand: mpq_srcptr);
    fn __gmpq_abs(rop: mpq_ptr, op: mpq_srcptr);
    fn __gmpq_inv(inverted_number: mpq_ptr, number: mpq_srcptr);
    fn __gmpq_get_num(numerator: mpz_ptr, rational: mpq_srcptr);
    fn __gmpq_get_den(denominator: mpz_ptr, rational: mpq_srcptr);
}

pub struct Mpq {
    mpq: mpq_struct,
}

unsafe impl Send for Mpq { }

impl Drop for Mpq {
    fn drop(&mut self) { unsafe { __gmpq_clear(&mut self.mpq) } }
}

impl Mpq {
    pub unsafe fn inner(&self) -> mpq_srcptr {
        &self.mpq
    }

    pub unsafe fn inner_mut(&mut self) -> mpq_ptr {
        &mut self.mpq
    }

    pub fn new() -> Mpq {
        unsafe {
            let mut mpq = uninitialized();
            __gmpq_init(&mut mpq);
            Mpq { mpq: mpq }
        }
    }

    pub fn set(&mut self, other: &Mpq) {
        unsafe { __gmpq_set(&mut self.mpq, &other.mpq) }
    }

    pub fn set_z(&mut self, other: &Mpz) {
        unsafe { __gmpq_set_z(&mut self.mpq, other.inner()) }
    }

    pub fn set_d(&mut self, other: f64) {
        unsafe { __gmpq_set_d(&mut self.mpq, other) }
    }

    pub fn set_f(&mut self, other: &Mpf) {
        unsafe { __gmpq_set_f(&mut self.mpq, other.inner()) }
    }

    pub fn get_num(&self) -> Mpz {
        unsafe {
            let mut res = Mpz::new();
            __gmpq_get_num(res.inner_mut(), &self.mpq);
            res
        }
    }

    pub fn get_den(&self) -> Mpz {
        unsafe {
            let mut res = Mpz::new();
            __gmpq_get_den(res.inner_mut(), &self.mpq);
            res
        }
    }

    pub fn abs(&self) -> Mpq {
        unsafe {
            let mut res = Mpq::new();
            __gmpq_abs(&mut res.mpq, &self.mpq);
            res
        }
    }

    pub fn invert(&self) -> Mpq {
        unsafe {
            if self.is_zero() {
                panic!("divide by zero")
            }

            let mut res = Mpq::new();
            __gmpq_inv(&mut res.mpq, &self.mpq);
            res
        }
    }

    pub fn one() -> Mpq {
        let mut res = Mpq::new();
        unsafe { __gmpq_set_ui(&mut res.mpq, 1, 1) }
        res
    }

    pub fn zero() -> Mpq { Mpq::new() }
    pub fn is_zero(&self) -> bool {
        unsafe { __gmpq_cmp_ui(&self.mpq, 0, 1) == 0 }
    }
}

impl Clone for Mpq {
    fn clone(&self) -> Mpq {
        let mut res = Mpq::new();
        res.set(self);
        res
    }
}

impl Eq for Mpq { }
impl PartialEq for Mpq {
    fn eq(&self, other: &Mpq) -> bool {
        unsafe { __gmpq_equal(&self.mpq, &other.mpq) != 0 }
    }
}

impl Ord for Mpq {
    fn cmp(&self, other: &Mpq) -> Ordering {
        let cmp = unsafe { __gmpq_cmp(&self.mpq, &other.mpq) };
        if cmp == 0 {
            Equal
        } else if cmp < 0 {
            Less
        } else {
            Greater
        }
    }
}
impl PartialOrd for Mpq {
    fn partial_cmp(&self, other: &Mpq) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, 'b> Add<&'a Mpq> for &'b Mpq {
    type Output = Mpq;
    fn add(self, other: &Mpq) -> Mpq {
        unsafe {
            let mut res = Mpq::new();
            __gmpq_add(&mut res.mpq, &self.mpq, &other.mpq);
            res
        }
    }
}

impl<'a> Add<&'a Mpq> for Mpq {
    type Output = Mpq;
    #[inline]
    fn add(mut self, other: &Mpq) -> Mpq {
        unsafe {
            __gmpq_add(&mut self.mpq, &self.mpq, &other.mpq);
            self
        }
    }
}

impl<'a, 'b> Sub<&'a Mpq> for &'b Mpq {
    type Output = Mpq;
    fn sub(self, other: &Mpq) -> Mpq {
        unsafe {
            let mut res = Mpq::new();
            __gmpq_sub(&mut res.mpq, &self.mpq, &other.mpq);
            res
        }
    }
}

impl<'a> Sub<&'a Mpq> for Mpq {
    type Output = Mpq;
    #[inline]
    fn sub(mut self, other: &Mpq) -> Mpq {
        unsafe {
            __gmpq_sub(&mut self.mpq, &self.mpq, &other.mpq);
            self
        }
    }
}

impl<'a, 'b> Mul<&'a Mpq> for &'b Mpq {
    type Output = Mpq;
    fn mul(self, other: &Mpq) -> Mpq {
        unsafe {
            let mut res = Mpq::new();
            __gmpq_mul(&mut res.mpq, &self.mpq, &other.mpq);
            res
        }
    }
}

impl<'a> Mul<&'a Mpq> for Mpq {
    type Output = Mpq;
    #[inline]
    fn mul(mut self, other: &Mpq) -> Mpq {
        unsafe {
            __gmpq_mul(&mut self.mpq, &self.mpq, &other.mpq);
            self
        }
    }
}

impl<'a, 'b> Div<&'a Mpq> for &'b Mpq {
    type Output = Mpq;
    fn div(self, other: &Mpq) -> Mpq {
        unsafe {
            if other.is_zero() {
                panic!("divide by zero")
            }

            let mut res = Mpq::new();
            __gmpq_div(&mut res.mpq, &self.mpq, &other.mpq);
            res
        }
    }
}

impl<'a> Div<&'a Mpq> for Mpq {
    type Output = Mpq;
    #[inline]
    fn div(mut self, other: &Mpq) -> Mpq {
        unsafe {
            if other.is_zero() {
                panic!("divide by zero")
            }
            
            __gmpq_div(&mut self.mpq, &self.mpq, &other.mpq);
            self
        }
    }
}

impl<'b> Neg for &'b Mpq {
    type Output = Mpq;
    fn neg(self) -> Mpq {
        unsafe {
            let mut res = Mpq::new();
            __gmpq_neg(&mut res.mpq, &self.mpq);
            res
        }
    }
}

impl Neg for Mpq {
    type Output = Mpq;
    #[inline]
    fn neg(mut self) -> Mpq {
        unsafe {
            __gmpq_neg(&mut self.mpq, &self.mpq);
            self
        }
    }
}

impl Into<Option<i64>> for Mpq {
    fn into(self) -> Option<i64> {
        panic!("not implemented")
    }
}

impl Into<Option<u64>> for Mpq {
    fn into(self) -> Option<u64> {
        panic!("not implemented")
    }
}

impl From<i64> for Mpq {
    fn from(other: i64) -> Mpq {
        let mut res = Mpq::new();
        res.set_z(&From::<i64>::from(other));
        res
    }
}

impl From<u64> for Mpq {
    fn from(other: u64) -> Mpq {
        let mut res = Mpq::new();
        res.set_z(&From::<u64>::from(other));
        res
    }
}


impl fmt::Debug for Mpq {
    /// Renders as `numer/denom`. If denom=1, renders as numer.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let numer = self.get_num();
        let denom = self.get_den();

        if denom == From::<i64>::from(1) {
            write!(f, "{}", numer)
        } else {
            write!(f, "{}/{}", numer, denom)
        }
    }
}

gen_overloads!(Mpq);