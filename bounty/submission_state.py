from enum import Enum


class SubmissionState(str, Enum):
    DISCOVERED = "DISCOVERED"
    VERIFIED = "VERIFIED"
    REPORT_READY = "REPORT_READY"
    FORM_VERIFIED = "FORM_VERIFIED"
    TERMS_ACCEPTED = "TERMS_ACCEPTED"
    SUBMITTING = "SUBMITTING"
    RECEIPT_VERIFIED = "RECEIPT_VERIFIED"
    HOLD = "HOLD"
    SUBMISSION_FAILED = "SUBMISSION_FAILED"


_ALLOWED = {
    SubmissionState.DISCOVERED: {SubmissionState.VERIFIED, SubmissionState.HOLD},
    SubmissionState.VERIFIED: {SubmissionState.REPORT_READY, SubmissionState.HOLD},
    SubmissionState.REPORT_READY: {SubmissionState.FORM_VERIFIED, SubmissionState.HOLD},
    SubmissionState.FORM_VERIFIED: {SubmissionState.TERMS_ACCEPTED, SubmissionState.HOLD},
    SubmissionState.TERMS_ACCEPTED: {SubmissionState.SUBMITTING, SubmissionState.HOLD},
    SubmissionState.SUBMITTING: {SubmissionState.RECEIPT_VERIFIED, SubmissionState.SUBMISSION_FAILED},
    SubmissionState.RECEIPT_VERIFIED: set(),
    SubmissionState.HOLD: {SubmissionState.VERIFIED},
    SubmissionState.SUBMISSION_FAILED: {SubmissionState.FORM_VERIFIED, SubmissionState.HOLD},
}


def transition(current: SubmissionState, target: SubmissionState) -> SubmissionState:
    current = SubmissionState(current)
    target = SubmissionState(target)
    if target in _ALLOWED[current]:
        return target
    return SubmissionState.SUBMISSION_FAILED
