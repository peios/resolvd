//! Packing an answer into the caller's buffer.
//!
//! Every NSS entry point is handed a `char *buf` and a length, and the
//! structure it fills points *into* that buffer. Nothing here allocates.
//! Running out of room is `NSS_STATUS_TRYAGAIN` with `ERANGE`, and glibc
//! calls again with a larger buffer — so a packer that overflowed silently
//! would corrupt the caller rather than trigger the retry that exists for
//! it. Same design as authd/nss/src/buffer.rs.

use core::ffi::c_char;

pub struct Packer {
    base: *mut c_char,
    len: usize,
    used: usize,
}

impl Packer {
    /// # Safety
    ///
    /// `base` must point to at least `len` writable bytes that outlive every
    /// pointer this hands out.
    pub unsafe fn new(base: *mut c_char, len: usize) -> Self {
        Self { base, len, used: 0 }
    }

    /// Reserve `size` bytes at `align`; the offset, or `None` when full.
    fn offset(&mut self, size: usize, align: usize) -> Option<usize> {
        let start = self.used.div_ceil(align) * align;
        let end = start.checked_add(size)?;
        if end > self.len {
            return None;
        }
        self.used = end;
        Some(start)
    }

    /// Reserve `size` bytes at `align` and return a pointer to them.
    pub fn reserve(&mut self, size: usize, align: usize) -> Option<*mut c_char> {
        let at = self.offset(size, align)?;
        // SAFETY: `at + size <= len`.
        Some(unsafe { self.base.add(at) })
    }

    /// Copy a string in, NUL-terminated.
    pub fn str(&mut self, value: &str) -> Option<*mut c_char> {
        if value.as_bytes().contains(&0) {
            return None;
        }
        let dst = self.reserve(value.len() + 1, 1)? as *mut u8;
        // SAFETY: `reserve` gave `len + 1` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(value.as_ptr(), dst, value.len());
            dst.add(value.len()).write(0);
        }
        Some(dst as *mut c_char)
    }

    /// Copy raw bytes in (an address), aligned.
    pub fn bytes(&mut self, value: &[u8], align: usize) -> Option<*mut c_char> {
        let dst = self.reserve(value.len(), align)? as *mut u8;
        // SAFETY: `reserve` gave `value.len()` bytes.
        unsafe { core::ptr::copy_nonoverlapping(value.as_ptr(), dst, value.len()) };
        Some(dst as *mut c_char)
    }

    /// Room for `count` pointers plus a terminating NULL, zeroed.
    pub fn pointers(&mut self, count: usize) -> Option<*mut *mut c_char> {
        let size = (count + 1) * core::mem::size_of::<*mut c_char>();
        let dst = self.reserve(size, core::mem::align_of::<*mut c_char>())? as *mut *mut c_char;
        // SAFETY: `reserve` gave `count + 1` aligned slots.
        unsafe {
            for i in 0..=count {
                dst.add(i).write(core::ptr::null_mut());
            }
        }
        Some(dst)
    }
}
