use generated::saga::billing_v1::{
    ACTION_REGISTRY_GENERATION, BillingCaptureReceipt, BillingReserveFundsReceipt, CaptureStep,
    Definition, ReserveFundsStep, SPEC, STEP_0, STEP_1, STEPS,
};

#[test]
fn saga_steps_are_generated_in_contract_order() {
    assert_eq!(STEPS, &[STEP_0, STEP_1]);
    assert_eq!(SPEC.steps(), STEPS);
    assert_eq!(STEPS[0].name(), "reserve_funds");
    assert_eq!(STEPS[0].receipt_schema(), "reserve.schema.json");
    assert_eq!(STEPS[0].effect_scope(), "billing.reserve-funds");
    assert_eq!(
        STEPS[0].compensation_effect_scope(),
        "billing.release-funds"
    );
    assert_eq!(STEPS[1].name(), "capture");
    assert_eq!(STEPS[1].receipt_schema(), "capture.schema.json");
    assert_eq!(
        SPEC.action_registry_generation(),
        ACTION_REGISTRY_GENERATION
    );
    assert_eq!(<Definition as generated::saga::Definition>::SPEC, SPEC);
}

#[test]
fn saga_receipt_dtos_are_sealed_to_their_step_and_roundtrip_json() -> serde_json::Result<()> {
    fn assert_receipt<S, R>()
    where
        S: generated::saga::StepMarker<Receipt = R>,
        R: generated::saga::Receipt<S>,
    {
    }
    assert_receipt::<ReserveFundsStep, BillingReserveFundsReceipt>();
    assert_receipt::<CaptureStep, BillingCaptureReceipt>();

    let reserve = BillingReserveFundsReceipt {
        reservation_id: "res-123".to_string(),
    };
    let reserve_json = serde_json::to_value(&reserve)?;
    assert_eq!(
        reserve_json,
        serde_json::json!({ "reservationId": "res-123" })
    );
    let reserve_back: BillingReserveFundsReceipt = serde_json::from_value(reserve_json)?;
    assert_eq!(reserve_back.reservation_id, "res-123");

    let capture = BillingCaptureReceipt {
        capture_id: "cap-123".to_string(),
    };
    let capture_json = serde_json::to_value(&capture)?;
    assert_eq!(capture_json, serde_json::json!({ "captureId": "cap-123" }));
    let capture_back: BillingCaptureReceipt = serde_json::from_value(capture_json)?;
    assert_eq!(capture_back.capture_id, "cap-123");
    Ok(())
}
