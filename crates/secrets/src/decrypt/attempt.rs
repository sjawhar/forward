use crate::proto::ErrCode;

/// One decrypt attempt's stable result for the approval worker.
#[derive(Clone, Copy)]
#[allow(
    clippy::redundant_pub_crate,
    reason = "the worker needs this crate-private error through decrypt's private module"
)]
pub(crate) struct AttemptError {
    pub(crate) code: ErrCode,
    pub(crate) retryable: bool,
    pub(crate) label: &'static str,
}

impl AttemptError {
    pub(crate) const fn non_retryable(code: ErrCode, label: &'static str) -> Self {
        Self {
            code,
            retryable: false,
            label,
        }
    }

    pub(crate) const fn unreachable_probe() -> Self {
        Self {
            code: ErrCode::YubikeyUnreachable,
            retryable: true,
            label: "yubikey-unreachable-probe",
        }
    }

    const fn from_code(code: ErrCode) -> Self {
        let label = match code {
            ErrCode::Timeout => "decrypt-timeout",
            ErrCode::YubikeyUnreachable => "yubikey-unreachable",
            _ => "decrypt-error",
        };
        Self::non_retryable(code, label)
    }
}

impl From<ErrCode> for AttemptError {
    fn from(code: ErrCode) -> Self {
        Self::from_code(code)
    }
}
