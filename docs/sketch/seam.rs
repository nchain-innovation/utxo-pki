//! Plug-in seam sketch. std only; a type-check target plus a few behaviour tests, not an implementation.
#![allow(dead_code)]
use std::future::Future;

// ---------------------------------------------------------------- primitives
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time(pub i64); // unix seconds, UTC

#[derive(Clone, Copy, Debug)]
pub struct TimeEstimate {
    pub at: Time,
    pub uncertainty_secs: u32, // UTXO: miner-set block time; list/signed: 0
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusRef {
    pub scheme: String, // routes to a source: "utxo", "list", "http"
    pub id: Vec<u8>,    // opaque to the core; each backend parses its own, returning Err, never panicking
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reason(pub u8); // RFC 5280 CRLReason code

/// SHA-256( len(serial) as u8 || serial (minimal big-endian) || SPKI DER ). Fixed before the credential exists.
pub struct Commitment(pub [u8; 32]);

pub trait Clock {
    fn now(&self) -> Time;
}

// -------------------------------------------------------------------- status
pub enum Status {
    Good,
    Revoked { since: TimeEstimate, reason: Reason },
    Unknown, // the backend has no record
}
pub struct Evidence {
    pub kind: String,
    pub bytes: Vec<u8>,
}
pub struct StatusAnswer {
    pub status: Status,
    pub evidence: Option<Evidence>,
}
#[derive(Debug)]
pub enum SourceError {
    Unavailable,
    Malformed,
    Other(String),
}
#[derive(Debug)]
pub enum SinkError {
    Unavailable,
    Rejected(String),
}
pub struct RevokeReceipt {
    pub evidence: Option<Evidence>,
}

/// Verifier side: read-only.
pub trait StatusSource: Send + Sync {
    fn scheme(&self) -> &'static str;
    fn status(&self, r: &StatusRef, at: Time) -> impl Future<Output = Result<StatusAnswer, SourceError>> + Send;
    /// Re-check evidence offline, so a verifier need not trust the backend's word.
    fn check_evidence(&self, r: &StatusRef, e: &Evidence) -> Result<Status, SourceError>;
}

/// Issuer side. Both calls MUST be idempotent: a retry after a crash returns the first result.
pub trait StatusSink: Send + Sync {
    fn register(&self, c: &Commitment) -> impl Future<Output = Result<StatusRef, SinkError>> + Send;
    fn revoke(&self, r: &StatusRef, why: Reason) -> impl Future<Output = Result<RevokeReceipt, SinkError>> + Send;
}

// ---------------------------------------------------------------------- keys
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Alg {
    Es256,
    Ed25519,
}
pub struct PublicKey {
    pub alg: Alg,
    pub spki_der: Vec<u8>,
}
#[derive(Debug)]
pub enum SignError {
    Unavailable,
    Refused,
}
/// A sign oracle. Private key bytes never cross this boundary.
pub trait Signer: Send + Sync {
    fn alg(&self) -> Alg;
    fn public_key(&self) -> &PublicKey;
    /// Fixed-size raw signature (ES256: 64 bytes, r || s big-endian); formats re-encode if they need DER.
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, SignError>;
}

// -------------------------------------------------------------------- format
pub struct TrustAnchors {
    pub der: Vec<Vec<u8>>,
}
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_chain_depth: u8,
}
pub struct VerifyCtx<'a> {
    pub now: Time,
    pub anchors: &'a TrustAnchors,
    pub limits: &'a Limits,
}
pub struct IssueRequest {
    pub subject: Vec<u8>,
    pub key: PublicKey,
    pub serial: Vec<u8>,
    pub not_before: Time,
    pub not_after: Time,
}
pub struct Verified {
    pub subject: Vec<u8>,
    pub key: PublicKey,
    pub validated_at: Time,         // time the chain was validated for (HCS: the signed `time`; X.509: now)
    pub asserted_at: Option<Time>,  // the signer's own claim of when it signed: self-asserted
    pub payload: Option<Vec<u8>>,   // signed content, if the format carries any
    pub status_checks: Vec<StatusRef>, // every ref that must be Good, in chain order
}
#[derive(Debug)]
pub enum FormatError {
    Malformed,
    Untrusted,
    Expired,
    Limit,
}
/// Sync and CPU-only: no network, no status lookups. That is the core's job.
pub trait Format: Send + Sync {
    fn name(&self) -> &'static str;
    fn verify(&self, input: &[u8], ctx: &VerifyCtx<'_>) -> Result<Verified, FormatError>;
    fn commitment(&self, req: &IssueRequest) -> Result<Commitment, FormatError>;
    fn issue(&self, req: &IssueRequest, status: &StatusRef, signer: &dyn Signer) -> Result<Vec<u8>, FormatError>;
}

// ---------------------------------------------------------------------- core
pub enum Scope {
    AtTime,
    Retroactive,
}
pub enum OnUnavailable {
    Fail,
    SoftFail,
}
pub struct Policy {
    pub scope: Scope,
    pub retroactive_reasons: Vec<Reason>,
    pub on_unavailable: OnUnavailable,
}
#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    Format,
    Revoked(StatusRef),
    Unknown(StatusRef),
    Unavailable(StatusRef),
    NoSource(String),
}
pub struct Outcome {
    pub accepted: bool,
    pub verified: Option<Verified>,
    pub rejects: Vec<Reject>,
}

/// Fail-closed. The revoked window is widened by the backend's uncertainty, and the subtraction
/// SATURATES toward i64::MIN, i.e. toward "revoked". Saturating (not wrapping, not erroring) is deliberate.
pub fn revoked_as_of(since: TimeEstimate, reason: Reason, t: Time, p: &Policy) -> bool {
    let retroactive = matches!(p.scope, Scope::Retroactive) || p.retroactive_reasons.contains(&reason);
    retroactive || since.at.0.saturating_sub(i64::from(since.uncertainty_secs)) <= t.0
}

// Closed set of sources chosen from TOML: enum dispatch, so no `dyn` and no `async-trait`.
pub enum AnySource {
    List(ListSource),
    Http(HttpSource),
}
impl AnySource {
    pub fn scheme(&self) -> &'static str {
        match self {
            AnySource::List(s) => s.scheme(),
            AnySource::Http(s) => s.scheme(),
        }
    }
    pub async fn status(&self, r: &StatusRef, at: Time) -> Result<StatusAnswer, SourceError> {
        match self {
            AnySource::List(s) => s.status(r, at).await,
            AnySource::Http(s) => s.status(r, at).await,
        }
    }
}

pub async fn verify<F: Format>(
    f: &F,
    sources: &[AnySource],
    input: &[u8],
    pol: &Policy,
    ctx: &VerifyCtx<'_>,
) -> Outcome {
    let v = match f.verify(input, ctx) {
        Ok(v) => v,
        Err(_) => return Outcome { accepted: false, verified: None, rejects: vec![Reject::Format] },
    };
    let mut rejects = Vec::new();
    for r in &v.status_checks {
        let Some(src) = sources.iter().find(|s| s.scheme() == r.scheme) else {
            rejects.push(Reject::NoSource(r.scheme.clone()));
            continue;
        };
        match src.status(r, v.validated_at).await {
            Ok(a) => match a.status {
                Status::Good => {}
                Status::Unknown => rejects.push(Reject::Unknown(r.clone())),
                Status::Revoked { since, reason } => {
                    if revoked_as_of(since, reason, v.validated_at, pol) {
                        rejects.push(Reject::Revoked(r.clone()));
                    }
                }
            },
            Err(SourceError::Unavailable) => {
                if matches!(pol.on_unavailable, OnUnavailable::Fail) {
                    rejects.push(Reject::Unavailable(r.clone()));
                }
            }
            Err(_) => rejects.push(Reject::Unavailable(r.clone())), // malformed answers never soft-fail
        }
    }
    Outcome { accepted: rejects.is_empty(), verified: Some(v), rejects }
}

// ------------------------------------------------- two toy sources, for the tests
pub struct ListSource {
    pub revoked: Vec<(Vec<u8>, TimeEstimate, Reason)>,
    pub down: bool,
}
impl StatusSource for ListSource {
    fn scheme(&self) -> &'static str {
        "list"
    }
    fn status(&self, r: &StatusRef, _at: Time) -> impl Future<Output = Result<StatusAnswer, SourceError>> + Send {
        let out = if self.down {
            Err(SourceError::Unavailable)
        } else {
            let status = match self.revoked.iter().find(|(id, _, _)| *id == r.id) {
                Some((_, since, reason)) => Status::Revoked { since: *since, reason: *reason },
                None => Status::Good,
            };
            Ok(StatusAnswer { status, evidence: None })
        };
        async move { out }
    }
    fn check_evidence(&self, _r: &StatusRef, _e: &Evidence) -> Result<Status, SourceError> {
        Err(SourceError::Malformed)
    }
}
pub struct HttpSource;
impl StatusSource for HttpSource {
    fn scheme(&self) -> &'static str {
        "http"
    }
    fn status(&self, _r: &StatusRef, _at: Time) -> impl Future<Output = Result<StatusAnswer, SourceError>> + Send {
        async { Err(SourceError::Unavailable) }
    }
    fn check_evidence(&self, _r: &StatusRef, _e: &Evidence) -> Result<Status, SourceError> {
        Err(SourceError::Malformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pol(scope: Scope, on_unavailable: OnUnavailable) -> Policy {
        Policy { scope, retroactive_reasons: vec![Reason(1)], on_unavailable }
    }
    fn est(at: i64, unc: u32) -> TimeEstimate {
        TimeEstimate { at: Time(at), uncertainty_secs: unc }
    }
    fn block_on<T>(f: impl Future<Output = T>) -> T {
        let mut f = std::pin::pin!(f);
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        loop {
            if let std::task::Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn revocation_after_t_is_not_revoked_at_t() {
        let p = pol(Scope::AtTime, OnUnavailable::Fail);
        assert!(!revoked_as_of(est(1000, 0), Reason(0), Time(999), &p));
        assert!(revoked_as_of(est(1000, 0), Reason(0), Time(1000), &p)); // equality fails closed
    }
    #[test]
    fn uncertainty_widens_toward_revoked() {
        let p = pol(Scope::AtTime, OnUnavailable::Fail);
        assert!(revoked_as_of(est(1000, 100), Reason(0), Time(950), &p));
        assert!(!revoked_as_of(est(1000, 100), Reason(0), Time(899), &p));
    }
    #[test]
    fn subtraction_saturates_toward_revoked_without_panic() {
        let p = pol(Scope::AtTime, OnUnavailable::Fail);
        assert!(revoked_as_of(est(i64::MIN + 5, u32::MAX), Reason(0), Time(i64::MIN), &p));
    }
    #[test]
    fn key_compromise_is_retroactive_even_in_at_time_scope() {
        let p = pol(Scope::AtTime, OnUnavailable::Fail);
        assert!(revoked_as_of(est(9_000_000_000, 0), Reason(1), Time(0), &p));
        assert!(!revoked_as_of(est(9_000_000_000, 0), Reason(4), Time(0), &p));
    }

    struct F {
        refs: Vec<StatusRef>,
    }
    impl Format for F {
        fn name(&self) -> &'static str {
            "test"
        }
        fn verify(&self, _i: &[u8], _c: &VerifyCtx<'_>) -> Result<Verified, FormatError> {
            Ok(Verified {
                subject: vec![],
                key: PublicKey { alg: Alg::Es256, spki_der: vec![] },
                validated_at: Time(500),
                asserted_at: Some(Time(500)),
                payload: None,
                status_checks: self.refs.clone(),
            })
        }
        fn commitment(&self, _r: &IssueRequest) -> Result<Commitment, FormatError> {
            Ok(Commitment([0; 32]))
        }
        fn issue(&self, _r: &IssueRequest, _s: &StatusRef, _k: &dyn Signer) -> Result<Vec<u8>, FormatError> {
            Ok(vec![])
        }
    }
    fn run(refs: Vec<StatusRef>, sources: Vec<AnySource>, p: Policy) -> Outcome {
        let anchors = TrustAnchors { der: vec![] };
        let limits = Limits { max_input_bytes: 1024, max_chain_depth: 4 };
        let ctx = VerifyCtx { now: Time(1000), anchors: &anchors, limits: &limits };
        block_on(verify(&F { refs }, &sources, b"x", &p, &ctx))
    }
    fn lref(id: u8) -> StatusRef {
        StatusRef { scheme: "list".into(), id: vec![id] }
    }

    #[test]
    fn flow_accepts_good_and_rejects_revoked_before_validated_at() {
        let src = || AnySource::List(ListSource { revoked: vec![(vec![2], est(400, 0), Reason(0))], down: false });
        assert!(run(vec![lref(1)], vec![src()], pol(Scope::AtTime, OnUnavailable::Fail)).accepted);
        let o = run(vec![lref(2)], vec![src()], pol(Scope::AtTime, OnUnavailable::Fail));
        assert_eq!(o.rejects, vec![Reject::Revoked(lref(2))]);
    }
    #[test]
    fn flow_accepts_revocation_after_validated_at_in_at_time_scope() {
        let src = AnySource::List(ListSource { revoked: vec![(vec![2], est(600, 0), Reason(0))], down: false });
        assert!(run(vec![lref(2)], vec![src], pol(Scope::AtTime, OnUnavailable::Fail)).accepted);
    }
    #[test]
    fn unavailable_fails_closed_unless_soft_fail() {
        let down = || AnySource::List(ListSource { revoked: vec![], down: true });
        assert!(!run(vec![lref(1)], vec![down()], pol(Scope::AtTime, OnUnavailable::Fail)).accepted);
        assert!(run(vec![lref(1)], vec![down()], pol(Scope::AtTime, OnUnavailable::SoftFail)).accepted);
    }
    #[test]
    fn unknown_scheme_is_rejected() {
        let o = run(vec![StatusRef { scheme: "utxo".into(), id: vec![] }], vec![], pol(Scope::AtTime, OnUnavailable::Fail));
        assert_eq!(o.rejects, vec![Reject::NoSource("utxo".into())]);
    }
}
