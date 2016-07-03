use libc::{c_double, c_int, c_long, c_ulong, c_void,c_char};
use std::mem::uninitialized;
use std::cmp;
use std::cmp::Ordering::{self, Greater, Less, Equal};
use std::ops::{Div, Mul, Add, Sub, Neg};
use std::ffi::CString;
use std::string::String;
use super::mpz::mp_bitcnt_t;
use super::mpz::{Mpz, mpz_srcptr};
use super::mpq::{Mpq, mpq_srcptr};

type mp_exp_t = c_long;

#[repr(C)]
pub struct mpf_struct {
    _mp_prec: c_int,
    _mp_size: c_int,
    _mp_exp: mp_exp_t,
    _mp_d: *mut c_void
}

pub type mpf_srcptr = *const mpf_struct;
pub type mpf_ptr = *mut mpf_struct;

#[link(name = "gmp")]
extern "C" {
    fn __gmpf_init2(x: mpf_ptr, prec: mp_bitcnt_t);
    fn __gmpf_init_set(rop: mpf_ptr, op: mpf_srcptr);
    fn __gmpf_clear(x: mpf_ptr);
    fn __gmpf_get_prec(op: mpf_srcptr) -> mp_bitcnt_t;
    fn __gmpf_set_prec(rop: mpf_ptr, prec: mp_bitcnt_t);
    fn __gmpf_set(rop: mpf_ptr, op: mpf_srcptr);
    fn __gmpf_set_z(rop: mpf_ptr, op: mpz_srcptr);
    fn __gmpf_set_q(rop: mpf_ptr, op: mpq_srcptr);

    fn __gmpf_set_str(rop: mpf_ptr, str: *const c_char, base: c_int);
    fn __gmpf_set_si(rop: mpf_ptr, op: c_long);
    fn __gmpf_get_str(str: *const c_char, expptr: *const mp_exp_t, base: i32, n_digits: i32, op: mpf_ptr) -> *mut c_char;

    fn __gmpf_cmp(op1: mpf_srcptr, op2: mpf_srcptr) -> c_int;
    fn __gmpf_cmp_d(op1: mpf_srcptr, op2: c_double) -> c_int;
    fn __gmpf_cmp_ui(op1: mpf_srcptr, op2: c_ulong) -> c_int;
    fn __gmpf_cmp_si(op1: mpf_srcptr, op2: c_long) -> c_int;
    fn __gmpf_reldiff(rop: mpf_ptr, op1: mpf_srcptr, op2: mpf_srcptr);
    fn __gmpf_add(rop: mpf_ptr, op1: mpf_srcptr, op2: mpf_srcptr);
    fn __gmpf_sub(rop: mpf_ptr, op1: mpf_srcptr, op2: mpf_srcptr);
    fn __gmpf_mul(rop: mpf_ptr, op1: mpf_srcptr, op2: mpf_srcptr);
    fn __gmpf_div(rop: mpf_ptr, op1: mpf_srcptr, op2: mpf_srcptr);
    fn __gmpf_neg(rop: mpf_ptr, op: mpf_srcptr);
    fn __gmpf_abs(rop: mpf_ptr, op: mpf_srcptr);
    fn __gmpf_ceil(rop: mpf_ptr, op: mpf_srcptr);
    fn __gmpf_floor(rop: mpf_ptr, op: mpf_srcptr);
    fn __gmpf_trunc(rop: mpf_ptr, op: mpf_srcptr);
    fn __gmpf_sqrt(rop: mpf_ptr, op: mpf_srcptr);
}

pub struct Mpf {
    mpf: mpf_struct,
}

unsafe impl Send for Mpf { }

impl Drop for Mpf {
    fn drop(&mut self) { unsafe { __gmpf_clear(&mut self.mpf) } }
}

impl Mpf {
    pub unsafe fn inner(&self) -> mpf_srcptr {
        &self.mpf
    }

    pub unsafe fn inner_mut(&mut self) -> mpf_ptr {
        &mut self.mpf
    }

    pub fn zero() -> Mpf { Mpf::new(32) }

    pub fn new(precision: usize) -> Mpf {
        unsafe {
            let mut mpf = uninitialized();
            __gmpf_init2(&mut mpf, precision as c_ulong);
            Mpf { mpf: mpf }
        }
    }

    pub fn set(&mut self, other: &Mpf) {
        unsafe { __gmpf_set(&mut self.mpf, &other.mpf) }
    }

    pub fn set_z(&mut self, other: &Mpz) {
        unsafe { __gmpf_set_z(&mut self.mpf, other.inner()) }
    }

    pub fn set_q(&mut self, other: &Mpq) {
        unsafe { __gmpf_set_q(&mut self.mpf, other.inner()) }
    }

    pub fn get_prec(&self) -> usize {
        unsafe { __gmpf_get_prec(&self.mpf) as usize }
    }

    pub fn set_prec(&mut self, precision: usize) {
        unsafe { __gmpf_set_prec(&mut self.mpf, precision as c_ulong) }
    }

    pub fn set_from_str(&mut self, string: &str, base: i32){
        let c_str = CString::new(string).unwrap();
        unsafe {
            __gmpf_set_str(&mut self.mpf, c_str.as_ptr(), base as c_int);
        }
    }

    pub fn set_from_si(&mut self, int: i64){
        unsafe{
            __gmpf_set_si(&mut self.mpf,int as c_long);
        }
    }

    pub fn get_str(&mut self, n_digits: i32, base: i32, exp: &mut c_long) -> String{
        let c_str = CString::new("").unwrap();
        let out;
        unsafe{
            out = CString::from_raw(__gmpf_get_str(c_str.into_raw(), exp, base, n_digits, &mut self.mpf));
        }
        out.to_str().unwrap().to_string()
    }

    pub fn abs(&self) -> Mpf {
        unsafe {
            let mut res = Mpf::new(self.get_prec());
            __gmpf_abs(&mut res.mpf, &self.mpf);
            res
        }
    }

    pub fn ceil(&self) -> Mpf {
        unsafe {
            let mut res = Mpf::new(self.get_prec());
            __gmpf_ceil(&mut res.mpf, &self.mpf);
            res
        }
    }

    pub fn floor(&self) -> Mpf {
        unsafe {
            let mut res = Mpf::new(self.get_prec());
            __gmpf_floor(&mut res.mpf, &self.mpf);
            res
        }
    }

    pub fn trunc(&self) -> Mpf {
        unsafe {
            let mut res = Mpf::new(self.get_prec());
            __gmpf_trunc(&mut res.mpf, &self.mpf);
            res
        }
    }

    pub fn reldiff(&self, other: &Mpf) -> Mpf {
        unsafe {
            let mut res = Mpf::new(cmp::max(self.get_prec(), other.get_prec()));
            __gmpf_reldiff(&mut res.mpf, &self.mpf, &other.mpf);
            res
        }
    }

    pub fn sqrt(self) -> Mpf {
        let mut retval:Mpf;
        unsafe {
            retval = Mpf::new(__gmpf_get_prec(&self.mpf) as usize);
            retval.set_from_si(0);
            if __gmpf_cmp_si(&self.mpf, 0) > 0 {
                __gmpf_sqrt(&mut retval.mpf, &self.mpf);
            } else {
                panic!("Square root of negative/zero");
            }
        }
        retval
    }
}

impl Clone for Mpf {
    fn clone(&self) -> Mpf {
        unsafe {
            let mut mpf = uninitialized();
            __gmpf_init_set(&mut mpf, &self.mpf);
            Mpf { mpf: mpf }
        }
    }
}

impl Eq for Mpf { }
impl PartialEq for Mpf {
    fn eq(&self, other: &Mpf) -> bool {
        unsafe { __gmpf_cmp(&self.mpf, &other.mpf) == 0 }
    }
}

impl Ord for Mpf {
    fn cmp(&self, other: &Mpf) -> Ordering {
        let cmp = unsafe { __gmpf_cmp(&self.mpf, &other.mpf) };
        if cmp == 0 {
            Equal
        } else if cmp > 0 {
            Greater
        } else {
            Less
        }
    }
}

impl PartialOrd for Mpf {
    fn partial_cmp(&self, other: &Mpf) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<'a, 'b> Add<&'a Mpf> for &'b Mpf {
    type Output = Mpf;
    fn add(self, other: &Mpf) -> Mpf {
        unsafe {
            let mut res = Mpf::new(cmp::max(self.get_prec(), other.get_prec()));
            __gmpf_add(&mut res.mpf, &self.mpf, &other.mpf);
            res
        }
    }
}

impl<'a> Add<&'a Mpf> for Mpf {
    type Output = Mpf;
    #[inline]
    fn add(mut self, other: &Mpf) -> Mpf {
        unsafe {
            __gmpf_add(&mut self.mpf, &self.mpf, &other.mpf);
            self
        }
    }
}

impl<'a, 'b> Sub<&'a Mpf> for &'b Mpf {
    type Output = Mpf;
    fn sub(self, other: &Mpf) -> Mpf {
        unsafe {
            let mut res = Mpf::new(cmp::max(self.get_prec(), other.get_prec()));
            __gmpf_sub(&mut res.mpf, &self.mpf, &other.mpf);
            res
        }
    }
}

impl<'a> Sub<&'a Mpf> for Mpf {
    type Output = Mpf;
    #[inline]
    fn sub(mut self, other: &Mpf) -> Mpf {
        unsafe {
            __gmpf_sub(&mut self.mpf, &self.mpf, &other.mpf);
            self
        }
    }
}

impl<'a, 'b> Mul<&'a Mpf> for &'b Mpf {
    type Output = Mpf;
    fn mul(self, other: &Mpf) -> Mpf {
        unsafe {
            let mut res = Mpf::new(cmp::max(self.get_prec(), other.get_prec()));
            __gmpf_mul(&mut res.mpf, &self.mpf, &other.mpf);
            res
        }
    }
}

impl<'a> Mul<&'a Mpf> for Mpf {
    type Output = Mpf;
    #[inline]
    fn mul(mut self, other: &Mpf) -> Mpf {
        unsafe {
            __gmpf_mul(&mut self.mpf, &self.mpf, &other.mpf);
            self
        }
    }
}

impl<'a, 'b> Div<&'a Mpf> for &'b Mpf {
    type Output = Mpf;
    fn div(self, other: &Mpf) -> Mpf {
        unsafe {
            if __gmpf_cmp_ui(&self.mpf, 0) == 0 {
                panic!("divide by zero")
            }

            let mut res = Mpf::new(cmp::max(self.get_prec(), other.get_prec()));
            __gmpf_div(&mut res.mpf, &self.mpf, &other.mpf);
            res
        }
    }
}

impl<'a> Div<&'a Mpf> for Mpf {
    type Output = Mpf;
    #[inline]
    fn div(mut self, other: &Mpf) -> Mpf {
        unsafe {
            if __gmpf_cmp_ui(&self.mpf, 0) == 0 {
                panic!("divide by zero")
            }

            __gmpf_div(&mut self.mpf, &self.mpf, &other.mpf);
            self
        }
    }
}

impl<'b> Neg for &'b Mpf {
    type Output = Mpf;
    fn neg(self) -> Mpf {
        unsafe {
            let mut res = Mpf::new(self.get_prec());
            __gmpf_neg(&mut res.mpf, &self.mpf);
            res
        }
    }
}

impl Neg for Mpf {
    type Output = Mpf;
    #[inline]
    fn neg(mut self) -> Mpf {
        unsafe {
            __gmpf_neg(&mut self.mpf, &self.mpf);
            self
        }
    }
}

gen_overloads!(Mpf);
