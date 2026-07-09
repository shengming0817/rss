use generated::saga::billing_v1::{
    BillingCaptureResult, BillingReserveFundsResult, SPEC, STEP_0, STEP_1, STEPS,
};

#[test]
fn saga_steps_are_generated_in_contract_order() {
    assert_eq!(STEPS, &[STEP_0, STEP_1]);
    assert_eq!(SPEC.steps(), STEPS);
    assert_eq!(STEPS[0].name(), "reserve_funds");
    assert_eq!(STEPS[0].output_schema(), "reserve.schema.json");
    assert_eq!(STEPS[1].name(), "capture");
    assert_eq!(STEPS[1].output_schema(), "capture.schema.json");
}

#[test]
fn saga_output_dtos_roundtrip_json() -> serde_json::Result<()> {
    assert_eq!(
        <BillingReserveFundsResult as vocab::SagaStepOutputBinding>::BINDING,
        STEP_0
    );
    assert_eq!(
        <BillingCaptureResult as vocab::SagaStepOutputBinding>::BINDING,
        STEP_1
    );

    let reserve = BillingReserveFundsResult {
        reservation_id: "res-123".to_string(),
    };
    let reserve_json = serde_json::to_value(&reserve)?;
    assert_eq!(
        reserve_json,
        serde_json::json!({ "reservationId": "res-123" })
    );
    let reserve_back: BillingReserveFundsResult = serde_json::from_value(reserve_json)?;
    assert_eq!(reserve_back.reservation_id, "res-123");

    let capture = BillingCaptureResult {
        capture_id: "cap-123".to_string(),
    };
    let capture_json = serde_json::to_value(&capture)?;
    assert_eq!(capture_json, serde_json::json!({ "captureId": "cap-123" }));
    let capture_back: BillingCaptureResult = serde_json::from_value(capture_json)?;
    assert_eq!(capture_back.capture_id, "cap-123");
    Ok(())
}
