pub mod capbac {
    include!(concat!(env!("OUT_DIR"), "/capbac.rs"));
}
pub mod bls;

use crate::capbac::{Certificate, Invocation, certificate, invocation};
use fastcrypto::bls12381::min_sig::{BLS12381PublicKey, BLS12381PrivateKey, BLS12381AggregateSignature};
use fastcrypto::traits::{Signer, ToFromBytes, AggregateAuthenticator};
use fastcrypto::error::FastCryptoError;
use http::uri::Uri;
use thiserror::Error;
use prost::Message;
use std::io::Cursor;

pub trait Resolver {
    fn get(&self, id: &Uri) -> Option<BLS12381PublicKey>;
}

pub trait TrustChecker {
    fn is_trusted(&self, id: &Uri) -> bool;
}

#[derive(Error, Debug)]
pub enum BLSError {
}

#[derive(Error, Debug)]
pub enum ForgeError {
    #[error("Unexpected BLS error. Invalid private key?")]
    CryptoError {
        #[from]
        source: FastCryptoError
    },
}

#[derive(Error, Debug)]
pub enum DelegateError {
    #[error("Unexpected BLS error. Invalid private key?")]
    CryptoError {
        #[from]
        source: FastCryptoError
    },
    #[error("Malformed protobuf message")]
    DecodeError {
        #[from]
        source: prost::DecodeError
    }
}

#[derive(Error, Debug)]
pub enum InvokeError {
    #[error("Unexpected BLS error. Invalid private key?")]
    CryptoError {
        #[from]
        source: FastCryptoError
    },
    #[error("Malformed protobuf message")]
    DecodeError {
        #[from]
        source: prost::DecodeError
    }
}

pub struct CertificateBlueprint {
    pub subject: Uri,
    pub capability: Vec<u8>,
    pub expiration: Option<u64>,
    pub content_type: Option<::std::string::String>,
}

pub struct InvocationBlueprint {
    pub certificate: Certificate,
    pub action: Vec<u8>,
    pub expiration: Option<u64>,
    pub content_type: Option<::std::string::String>,
}

pub struct Holder {
    me: Uri,
    sk: BLS12381PrivateKey,
}

pub fn serialize_certificate_payload(payload: &certificate::Payload) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.reserve(payload.encoded_len());
    // Unwrap is safe, since we have reserved sufficient capacity in the vector.
    payload.encode(&mut buf).unwrap();
    buf
}

pub fn deserialize_certificate_payload(buf: &[u8]) -> Result<certificate::Payload, prost::DecodeError> {
    certificate::Payload::decode(&mut Cursor::new(buf))
}

pub fn serialize_invocation_payload(payload: &invocation::Payload) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.reserve(payload.encoded_len());
    // Unwrap is safe, since we have reserved sufficient capacity in the vector.
    payload.encode(&mut buf).unwrap();
    buf
}

pub fn deserialize_invocation_payload(buf: &[u8]) -> Result<invocation::Payload, prost::DecodeError> {
    invocation::Payload::decode(&mut Cursor::new(buf))
}

impl Holder {
    pub fn new(me: Uri, sk: BLS12381PrivateKey) -> Self {
        Holder { me, sk }
    }

    pub fn forge(&self, options: CertificateBlueprint) -> Result<Certificate, ForgeError> {
        let mut proto_payload = certificate::Payload::default();
        self.write_certificate_payload(&mut proto_payload, options);
        let aggregate_signature = BLS12381AggregateSignature::default();
        let proto = self.write_certificate(aggregate_signature, proto_payload)?;
        Ok(proto)
    }

    pub fn delegate(
        &self,
        cert: Certificate,
        options: CertificateBlueprint,
    ) -> Result<Certificate, DelegateError> {
        let mut proto_payload = certificate::Payload::default();
        proto_payload.parent = Some(Box::new(deserialize_certificate_payload(&cert.payload)?));
        self.write_certificate_payload(&mut proto_payload, options);
        let aggregate_signature = BLS12381AggregateSignature::from_bytes(&cert.signature)?;
        let proto = self.write_certificate(aggregate_signature, proto_payload)?;
        Ok(proto)
    }

    pub fn invoke(
        &self, cert: Certificate,
        options: InvocationBlueprint
    ) -> Result<Invocation, InvokeError> {
        let mut proto_payload = invocation::Payload::default();
        proto_payload.certificate = Some(deserialize_certificate_payload(&cert.payload)?);
        self.write_invocation_payload(&mut proto_payload, options);
        let aggregate_signature = BLS12381AggregateSignature::from_bytes(&cert.signature)?;
        let proto = self.write_invocation(aggregate_signature, proto_payload)?;
        Ok(proto)
    }

    fn write_certificate_payload(
        &self,
        proto_payload: &mut certificate::Payload,
        options: CertificateBlueprint,
    ) -> () {
        proto_payload.issuer = self.me.to_string();
        proto_payload.subject = options.subject.to_string();
        proto_payload.capability = options.capability;
        if let Some(x) = options.expiration {
            proto_payload.expiration = x;
        }
        if let Some(x) = options.content_type {
            proto_payload.content_type = x;
        }
    }

    fn write_certificate(
        &self,
        mut aggregate_signature: BLS12381AggregateSignature,
        proto_payload: certificate::Payload,
    ) -> Result<Certificate, FastCryptoError> {
        let payload = serialize_certificate_payload(&proto_payload);
        aggregate_signature.add_signature(self.sk.sign(&payload))?;
        let signature = aggregate_signature.as_bytes().to_vec();
        let mut proto = Certificate::default();
        proto.payload = payload;
        proto.signature = signature;

        Ok(proto)
    }

    fn write_invocation_payload(
        &self,
        proto_payload: &mut invocation::Payload,
        options: InvocationBlueprint,
    ) -> () {
        proto_payload.invoker = self.me.to_string();
        proto_payload.action = options.action;
        if let Some(x) = options.expiration {
            proto_payload.expiration = x;
        }
        if let Some(x) = options.content_type {
            proto_payload.content_type = x;
        }
    }

    fn write_invocation(
        &self,
        mut aggregate_signature: BLS12381AggregateSignature,
        proto_payload: invocation::Payload,
    ) -> Result<Invocation, FastCryptoError> {
        let payload = serialize_invocation_payload(&proto_payload);
        aggregate_signature.add_signature(self.sk.sign(&payload))?;
        let signature = aggregate_signature.as_bytes().to_vec();
        let mut proto = Invocation::default();
        proto.payload = payload;
        proto.signature = signature;

        Ok(proto)
    }
}

#[derive(Error, Debug)]
pub enum ValidateError {
    #[error("Malformed protobuf message")]
    Malformed {
        #[from]
        source: prost::DecodeError,
    },
    #[error("Untrusted issuer {issuer}")]
    Untrusted { issuer: Uri },
    #[error("Can't parse URI {uri}")]
    BadURI { uri: String },
    #[error("Unknown pub key for {uri}")]
    UnknownPub { uri: Uri },
    #[error("Issuer {issuer} doesn't match subject {subject}")]
    BadIssuer { subject: Uri, issuer: Uri },
    #[error("Invoker {invoker} doesn't match subject {subject}")]
    BadInvoker { subject: Uri, invoker: Uri },
    #[error("Expired item")]
    Expired,
    #[error("Bad signature")]
    BadSign,
}

impl Iterator for certificate::Payload {
    type Item = certificate::Payload;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(x) = self.parent.clone() {
            return Some(*x);
        }

        None
    }
}

pub struct Validator<'a> {
    trust_checker: &'a dyn TrustChecker,
    resolver: &'a dyn Resolver,
}

impl<'a> Validator<'a> {
    pub fn new(trust_checker: &'a dyn TrustChecker, resolver: &'a dyn Resolver) -> Self {
        Validator {
            trust_checker,
            resolver,
        }
    }

    pub fn validate_certificate(
        &self,
        certificate: &Certificate,
        now: u64
    ) -> Result<(), ValidateError> {
        let mut pks = Vec::new();
        let mut messages = Vec::new();
        let mut signature = BLS12381AggregateSignature::default();

        self.verify_chain(&pks, &messages, certificate, now)?;

        // pks.reverse();
        // messages.reverse();

        let mut messages_q = Vec::new();
        for message in messages.iter() {
            messages_q.push(message.as_slice());
        }

        match signature.verify_different_msg(&pks, messages_q.as_slice()) {
            Ok(_) => Ok(()),
            Err(_) => Err(ValidateError::BadSign)
        }
    }

    pub fn validate_invocation(
        &self,
        invocation: &Invocation,
        now: u64,
    ) -> Result<(), ValidateError> {
        todo!()
    }

    fn verify_chain(
        &self,
        mut pks: &Vec<BLS12381PublicKey>,
        mut messages: &Vec<Vec<u8>>,
        certificate: &Certificate,
        now: u64
    ) -> Result<(), ValidateError> {
        let certificate_payload = deserialize_certificate_payload(&certificate.payload);
        for certificate_in_chain_payload in certificate_payload.into_iter() {
            let message = serialize_certificate_payload(&certificate_in_chain_payload);

            let issuer = certificate_in_chain_payload.issuer.parse::<Uri>().map_err(|_| ValidateError::BadURI {
                uri: certificate_in_chain_payload.issuer,
            })?;

            let expiration = certificate_in_chain_payload.expiration;

            if expiration != 0 && expiration < now {
                return Err(ValidateError::Expired);
            }

            if let Some(parent_cert_payload) = certificate_in_chain_payload.parent {

                let subject = parent_cert_payload.subject.parse::<Uri>().map_err(|_| ValidateError::BadURI {
                    uri: parent_cert_payload.subject,
                })?;

                if issuer != subject {
                    return Err(ValidateError::BadIssuer {
                        subject,
                        issuer,
                    })
                }
            }

            let issuer_pk = match self.resolver.get(&issuer) {
                Some(x) => x,
                None => return Err(ValidateError::UnknownPub { uri: issuer })
            };

            pks.push(issuer_pk);
            messages.push(message);
        }
        Ok(())
    }
}
