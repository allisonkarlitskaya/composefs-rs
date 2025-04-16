use core::{fmt, hash::Hash};

use hex::FromHexError;
use sha2::{digest::FixedOutputReset, digest::Output, Digest, Sha256, Sha512};
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

pub trait FsVerityHashValue
where
    Self: Clone,
    Self: From<Output<Self::Digest>>,
    Self: FromBytes + Immutable + IntoBytes + KnownLayout + Unaligned,
    Self: Hash + Eq,
    Self: fmt::Debug,
{
    type Digest: Digest + FixedOutputReset + fmt::Debug;
    const ALGORITHM: u8;
    const EMPTY: Self;
    const ID: &str;

    fn from_hex(hex: impl AsRef<[u8]>) -> Result<Self, FromHexError> {
        let mut value = Self::EMPTY;
        hex::decode_to_slice(hex.as_ref(), value.as_mut_bytes())?;
        Ok(value)
    }

    fn from_object_dir_and_basename(
        dirnum: u8,
        basename: impl AsRef<[u8]>,
    ) -> Result<Self, FromHexError> {
        let expected_size = 2 * (size_of::<Self>() - 1);
        let bytes = basename.as_ref();
        if bytes.len() != expected_size {
            return Err(FromHexError::InvalidStringLength);
        }
        let mut result = Self::EMPTY;
        result.as_mut_bytes()[0] = dirnum;
        hex::decode_to_slice(bytes, &mut result.as_mut_bytes()[1..])?;
        Ok(result)
    }

    fn from_object_pathname(pathname: impl AsRef<[u8]>) -> Result<Self, FromHexError> {
        // We want to the trailing part of "....../xx/yyyyyy" where xxyyyyyy is our hex length
        let min_size = 2 * size_of::<Self>() + 1;
        let bytes = pathname.as_ref();
        if bytes.len() < min_size {
            return Err(FromHexError::InvalidStringLength);
        }

        let trailing = &bytes[bytes.len() - min_size..];
        let mut result = Self::EMPTY;
        hex::decode_to_slice(&trailing[0..2], &mut result.as_mut_bytes()[0..1])?;
        hex::decode_to_slice(&trailing[2..], &mut result.as_mut_bytes()[1..])?;
        Ok(result)
    }

    fn to_object_pathname(&self) -> String {
        format!("{:02x}/{}", self.as_bytes()[0], self.to_object_basename())
    }

    fn to_object_dir(&self) -> String {
        format!("{:02x}", self.as_bytes()[0])
    }

    fn to_object_basename(&self) -> String {
        hex::encode(&self.as_bytes()[1..])
    }

    fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    fn to_id(&self) -> String {
        format!("{}:{}", Self::ID, self.to_hex())
    }
}

impl fmt::Debug for Sha256HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.to_hex())
    }
}

impl fmt::Debug for Sha512HashValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha512:{}", self.to_hex())
    }
}

#[derive(Clone, Eq, FromBytes, Hash, Immutable, IntoBytes, KnownLayout, PartialEq, Unaligned)]
#[repr(C)]
pub struct Sha256HashValue([u8; 32]);

impl From<Output<Sha256>> for Sha256HashValue {
    fn from(value: Output<Sha256>) -> Self {
        Self(value.into())
    }
}

impl FsVerityHashValue for Sha256HashValue {
    type Digest = Sha256;
    const ALGORITHM: u8 = 1;
    const EMPTY: Self = Self([0; 32]);
    const ID: &str = "sha256";
}

#[derive(Clone, Eq, FromBytes, Hash, Immutable, IntoBytes, KnownLayout, PartialEq, Unaligned)]
#[repr(C)]
pub struct Sha512HashValue([u8; 64]);

impl From<Output<Sha512>> for Sha512HashValue {
    fn from(value: Output<Sha512>) -> Self {
        Self(value.into())
    }
}

impl FsVerityHashValue for Sha512HashValue {
    type Digest = Sha512;
    const ALGORITHM: u8 = 2;
    const EMPTY: Self = Self([0; 64]);
    const ID: &str = "sha512";
}
