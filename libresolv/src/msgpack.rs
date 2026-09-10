//! A MessagePack codec: the subset PSPU messages use — nil, bool, integers,
//! strings, binary, arrays, maps.
//!
//! libresolv is linked into `libnss_peios_net.so.2`, which is loaded into
//! every process on the system, so it takes no dependency on libpeios (whose
//! `peios::msgpack` this mirrors in API) — the same choice `libauthd` made for
//! the identity shim. Total: every input decodes or returns an error.

use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    Truncated,
    /// The next value is not of the type asked for.
    Type,
    /// A float or extension, which no PSPU message here carries.
    Unsupported,
    Utf8,
    /// A container nested deeper than a message may.
    Depth,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Error::Truncated => "truncated message",
            Error::Type => "unexpected value type",
            Error::Unsupported => "unsupported value type",
            Error::Utf8 => "string is not UTF-8",
            Error::Depth => "nested too deeply",
        })
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Type {
    Nil,
    Bool,
    Int,
    Str,
    Bin,
    Array,
    Map,
    Other,
}

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Writer {
        Writer {
            buf: Vec::with_capacity(256),
        }
    }

    pub fn write_nil(&mut self) -> &mut Self {
        self.buf.push(0xc0);
        self
    }

    pub fn write_bool(&mut self, v: bool) -> &mut Self {
        self.buf.push(if v { 0xc3 } else { 0xc2 });
        self
    }

    pub fn write_uint(&mut self, v: u64) -> &mut Self {
        if v < 0x80 {
            self.buf.push(v as u8);
        } else if v <= 0xff {
            self.buf.extend_from_slice(&[0xcc, v as u8]);
        } else if v <= 0xffff {
            self.buf.push(0xcd);
            self.buf.extend_from_slice(&(v as u16).to_be_bytes());
        } else if v <= 0xffff_ffff {
            self.buf.push(0xce);
            self.buf.extend_from_slice(&(v as u32).to_be_bytes());
        } else {
            self.buf.push(0xcf);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
        self
    }

    pub fn write_int(&mut self, v: i64) -> &mut Self {
        if v >= 0 {
            return self.write_uint(v as u64);
        }
        if v >= -32 {
            self.buf.push(v as i8 as u8);
        } else if v >= i8::MIN as i64 {
            self.buf.extend_from_slice(&[0xd0, v as i8 as u8]);
        } else if v >= i16::MIN as i64 {
            self.buf.push(0xd1);
            self.buf.extend_from_slice(&(v as i16).to_be_bytes());
        } else if v >= i32::MIN as i64 {
            self.buf.push(0xd2);
            self.buf.extend_from_slice(&(v as i32).to_be_bytes());
        } else {
            self.buf.push(0xd3);
            self.buf.extend_from_slice(&v.to_be_bytes());
        }
        self
    }

    pub fn write_str(&mut self, s: &str) -> &mut Self {
        let n = s.len();
        if n < 32 {
            self.buf.push(0xa0 | n as u8);
        } else if n <= 0xff {
            self.buf.extend_from_slice(&[0xd9, n as u8]);
        } else if n <= 0xffff {
            self.buf.push(0xda);
            self.buf.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            self.buf.push(0xdb);
            self.buf.extend_from_slice(&(n as u32).to_be_bytes());
        }
        self.buf.extend_from_slice(s.as_bytes());
        self
    }

    pub fn write_bin(&mut self, b: &[u8]) -> &mut Self {
        let n = b.len();
        if n <= 0xff {
            self.buf.extend_from_slice(&[0xc4, n as u8]);
        } else if n <= 0xffff {
            self.buf.push(0xc5);
            self.buf.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            self.buf.push(0xc6);
            self.buf.extend_from_slice(&(n as u32).to_be_bytes());
        }
        self.buf.extend_from_slice(b);
        self
    }

    pub fn write_array(&mut self, count: u32) -> &mut Self {
        if count < 16 {
            self.buf.push(0x90 | count as u8);
        } else if count <= 0xffff {
            self.buf.push(0xdc);
            self.buf.extend_from_slice(&(count as u16).to_be_bytes());
        } else {
            self.buf.push(0xdd);
            self.buf.extend_from_slice(&count.to_be_bytes());
        }
        self
    }

    pub fn write_map(&mut self, count: u32) -> &mut Self {
        if count < 16 {
            self.buf.push(0x80 | count as u8);
        } else if count <= 0xffff {
            self.buf.push(0xde);
            self.buf.extend_from_slice(&(count as u16).to_be_bytes());
        } else {
            self.buf.push(0xdf);
            self.buf.extend_from_slice(&count.to_be_bytes());
        }
        self
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.buf.clone()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }
}

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: u32,
}

const MAX_DEPTH: u32 = 32;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Reader<'a> {
        Reader {
            buf,
            pos: 0,
            depth: 0,
        }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn byte(&mut self) -> Result<u8> {
        let b = *self.buf.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let s = self
            .buf
            .get(self.pos..self.pos + n)
            .ok_or(Error::Truncated)?;
        self.pos += n;
        Ok(s)
    }

    fn be_u(&mut self, n: usize) -> Result<u64> {
        let s = self.take(n)?;
        Ok(s.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
    }

    pub fn peek(&self) -> Option<Type> {
        let b = *self.buf.get(self.pos)?;
        Some(match b {
            0xc0 => Type::Nil,
            0xc2 | 0xc3 => Type::Bool,
            0x00..=0x7f | 0xe0..=0xff | 0xcc..=0xd3 => Type::Int,
            0xa0..=0xbf | 0xd9..=0xdb => Type::Str,
            0xc4..=0xc6 => Type::Bin,
            0x90..=0x9f | 0xdc | 0xdd => Type::Array,
            0x80..=0x8f | 0xde | 0xdf => Type::Map,
            _ => Type::Other,
        })
    }

    pub fn read_nil(&mut self) -> Result<()> {
        match self.byte()? {
            0xc0 => Ok(()),
            _ => Err(Error::Type),
        }
    }

    pub fn read_bool(&mut self) -> Result<bool> {
        match self.byte()? {
            0xc2 => Ok(false),
            0xc3 => Ok(true),
            _ => Err(Error::Type),
        }
    }

    pub fn read_int(&mut self) -> Result<i64> {
        let b = self.byte()?;
        Ok(match b {
            0x00..=0x7f => i64::from(b),
            0xe0..=0xff => i64::from(b as i8),
            0xcc => self.be_u(1)? as i64,
            0xcd => self.be_u(2)? as i64,
            0xce => self.be_u(4)? as i64,
            0xcf => {
                let v = self.be_u(8)?;
                i64::try_from(v).map_err(|_| Error::Type)?
            }
            0xd0 => self.be_u(1)? as u8 as i8 as i64,
            0xd1 => self.be_u(2)? as u16 as i16 as i64,
            0xd2 => self.be_u(4)? as u32 as i32 as i64,
            0xd3 => self.be_u(8)? as i64,
            _ => return Err(Error::Type),
        })
    }

    pub fn read_uint(&mut self) -> Result<u64> {
        let v = self.read_int()?;
        u64::try_from(v).map_err(|_| Error::Type)
    }

    pub fn read_str(&mut self) -> Result<&'a str> {
        let b = self.byte()?;
        let n = match b {
            0xa0..=0xbf => (b & 0x1f) as usize,
            0xd9 => self.be_u(1)? as usize,
            0xda => self.be_u(2)? as usize,
            0xdb => self.be_u(4)? as usize,
            _ => return Err(Error::Type),
        };
        std::str::from_utf8(self.take(n)?).map_err(|_| Error::Utf8)
    }

    pub fn read_bin(&mut self) -> Result<&'a [u8]> {
        let b = self.byte()?;
        let n = match b {
            0xc4 => self.be_u(1)? as usize,
            0xc5 => self.be_u(2)? as usize,
            0xc6 => self.be_u(4)? as usize,
            _ => return Err(Error::Type),
        };
        self.take(n)
    }

    pub fn read_array(&mut self) -> Result<usize> {
        let b = self.byte()?;
        let n = match b {
            0x90..=0x9f => (b & 0x0f) as usize,
            0xdc => self.be_u(2)? as usize,
            0xdd => self.be_u(4)? as usize,
            _ => return Err(Error::Type),
        };
        // A count larger than the bytes left cannot be honest.
        if n > self.remaining() {
            return Err(Error::Truncated);
        }
        Ok(n)
    }

    pub fn read_map(&mut self) -> Result<usize> {
        let b = self.byte()?;
        let n = match b {
            0x80..=0x8f => (b & 0x0f) as usize,
            0xde => self.be_u(2)? as usize,
            0xdf => self.be_u(4)? as usize,
            _ => return Err(Error::Type),
        };
        if n * 2 > self.remaining() {
            return Err(Error::Truncated);
        }
        Ok(n)
    }

    /// Skip one value of any supported type.
    pub fn skip(&mut self) -> Result<()> {
        match self.peek().ok_or(Error::Truncated)? {
            Type::Nil => self.read_nil(),
            Type::Bool => self.read_bool().map(drop),
            Type::Int => self.read_int().map(drop),
            Type::Str => self.read_str().map(drop),
            Type::Bin => self.read_bin().map(drop),
            Type::Array => {
                let n = self.read_array()?;
                self.nested(|r| (0..n).try_for_each(|_| r.skip()))
            }
            Type::Map => {
                let n = self.read_map()?;
                self.nested(|r| (0..n).try_for_each(|_| r.skip().and_then(|_| r.skip())))
            }
            Type::Other => Err(Error::Unsupported),
        }
    }

    fn nested<T>(&mut self, f: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        self.depth += 1;
        if self.depth > MAX_DEPTH {
            return Err(Error::Depth);
        }
        let r = f(self);
        self.depth -= 1;
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalars_round_trip() {
        let mut w = Writer::new();
        w.write_array(9)
            .write_nil()
            .write_bool(true)
            .write_uint(5)
            .write_uint(300)
            .write_uint(70000)
            .write_uint(1 << 40)
            .write_int(-5)
            .write_int(-300)
            .write_str("hello");
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_array().unwrap(), 9);
        r.read_nil().unwrap();
        assert!(r.read_bool().unwrap());
        assert_eq!(r.read_uint().unwrap(), 5);
        assert_eq!(r.read_uint().unwrap(), 300);
        assert_eq!(r.read_uint().unwrap(), 70000);
        assert_eq!(r.read_uint().unwrap(), 1 << 40);
        assert_eq!(r.read_int().unwrap(), -5);
        assert_eq!(r.read_int().unwrap(), -300);
        assert_eq!(r.read_str().unwrap(), "hello");
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn long_strings_bins_and_containers() {
        let long = "x".repeat(300);
        let bin = vec![7u8; 70000];
        let mut w = Writer::new();
        w.write_map(2)
            .write_str("s")
            .write_str(&long)
            .write_str("b")
            .write_bin(&bin);
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_map().unwrap(), 2);
        assert_eq!(r.read_str().unwrap(), "s");
        assert_eq!(r.read_str().unwrap(), long);
        assert_eq!(r.read_str().unwrap(), "b");
        assert_eq!(r.read_bin().unwrap(), &bin[..]);
    }

    #[test]
    fn skip_walks_nested_values_and_refuses_lies() {
        let mut w = Writer::new();
        w.write_array(2)
            .write_map(1)
            .write_str("k")
            .write_array(1)
            .write_uint(1)
            .write_str("after");
        let bytes = w.into_bytes();
        let mut r = Reader::new(&bytes);
        assert_eq!(r.read_array().unwrap(), 2);
        r.skip().unwrap();
        assert_eq!(r.read_str().unwrap(), "after");
        // An array claiming a billion elements in three bytes.
        let lie = [0xdd, 0x3b, 0x9a, 0xca, 0x00];
        assert_eq!(Reader::new(&lie).read_array(), Err(Error::Truncated));
        let mut deep = vec![0x91u8; 40];
        deep.push(0xc0);
        assert_eq!(Reader::new(&deep).skip(), Err(Error::Depth));
        assert_eq!(
            Reader::new(&[0xca, 0, 0, 0, 0]).skip(),
            Err(Error::Unsupported)
        );
    }
}
