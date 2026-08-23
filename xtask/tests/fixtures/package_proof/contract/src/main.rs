use release_package::*;
use std::error::Error;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let id = ContractId::parse("runtime.inventory")?;
    let version = ContractVersion::parse("v12")?;
    let digest = SchemaDigest::parse(&format!("sha256:{}", "a".repeat(64)))?;
    let descriptor = ContractDescriptor::from_static_version(
        "runtime.inventory",
        "v12",
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    );
    let invalid = ContractId::parse("Runtime..inventory").is_err();

    let earlier = Timepoint::try_from(7_i64)?;
    let later = Timepoint::try_from(11_i64)?;
    let timepoint_roundtrip = Timepoint::try_from(earlier.to_system_time()?)? == earlier;
    let negative_timepoint_rejected = Timepoint::try_from(-1_i64).is_err();

    let raw_cursor = "c2Vuc2l0aXZlLWN1cnNvcg";
    let cursor = PageCursor::parse(raw_cursor)?;
    let cursor_debug = format!("{cursor:?}");
    let oversized_cursor = "A".repeat(4097);

    let data_class_labels = [
        DataClass::Public.as_str(),
        DataClass::Internal.as_str(),
        DataClass::Pii.as_str(),
        DataClass::Secret.as_str(),
    ];
    let safe_error = SafeError::new(SafeErrorCode::Internal);
    let safe_debug = format!("{safe_error:?}");
    let safe_display = safe_error.to_string();
    let safe_diagnostics_redacted = safe_debug == "SafeError { code: Internal, category: Internal }"
        && safe_display == "internal error";

    println!(
        r#"{{"package":"rss-contract","dottedId":{},"version":"{}","digest":{},"descriptor":{},"invalidRejected":{},"timepointRoundtrip":{},"timepointOrdered":{},"negativeTimepointRejected":{},"cursorRoundtrip":{},"malformedCursorRejected":{},"oversizedCursorRejected":{},"cursorDebugRedacted":{},"dataClassLabels":["{}","{}","{}","{}"],"safeErrorCode":"{}","safeErrorCategory":"{}","safeErrorMessage":"{}","safeErrorSourceAbsent":{},"safeErrorDiagnosticsRedacted":{}}}"#,
        descriptor.id() == id.as_str(),
        descriptor.version(),
        descriptor.schema_digest() == digest.as_str(),
        version.major() == 12,
        invalid,
        timepoint_roundtrip,
        earlier < later,
        negative_timepoint_rejected,
        cursor.as_str() == raw_cursor,
        PageCursor::parse("not+base64").is_err(),
        PageCursor::parse(&oversized_cursor).is_err(),
        cursor_debug == "PageCursor([REDACTED])" && !cursor_debug.contains(raw_cursor),
        data_class_labels[0],
        data_class_labels[1],
        data_class_labels[2],
        data_class_labels[3],
        safe_error.code(),
        safe_error.category(),
        safe_error.message(),
        safe_error.source().is_none(),
        safe_diagnostics_redacted,
    );
    Ok(())
}
