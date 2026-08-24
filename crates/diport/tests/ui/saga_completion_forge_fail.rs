//! INVARIANT: SAGA-RECEIPT-COMPLETION-TYPE-01 { level = "Medium", exec = "test", source = "trybuild" }
//! Private fields prevent external crates from forging either layer of the completion carrier.

use consistency::{SagaAttempt, SagaReceiptFormatVersion, SagaReceiptScope};
use diport::{SagaForwardCompletion, SagaForwardProgress, SagaStepCompletion};
use secure::Plaintext;

fn forge_step(
    scope: SagaReceiptScope,
    attempt: SagaAttempt,
    format: SagaReceiptFormatVersion,
    plaintext: Plaintext,
) {
    let _forged = SagaStepCompletion {
        scope,
        attempt,
        format,
        plaintext,
        completed_seq: 1,
    };
}

fn forge_forward(completion: SagaStepCompletion, progress: SagaForwardProgress) {
    let _forged = SagaForwardCompletion {
        completion,
        progress,
    };
}

fn main() {}
