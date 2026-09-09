mod allocator;
use rss_data_protection::{BlindIndex, BlindIndexKey, FilterBits, IndexScope, Transform};
use rss_redact::RedactionHashKey;

fn keys() {
    for size in [0, 1, 31, 32, 4096] {
        for redaction in [false, true] {
            // Spare capacity contains previously initialized material too.
            let mut bytes = vec![0xA5; size + 23];
            bytes.truncate(size);
            allocator::start(usize::MAX);
            allocator::watch(&bytes);
            if redaction {
                let key = RedactionHashKey::from_bytes(bytes);
                assert_eq!(key.is_ok(), size >= 32);
                drop(std::hint::black_box(key));
            } else {
                let key = BlindIndexKey::from_bytes(bytes);
                assert_eq!(key.is_ok(), size >= 32);
                drop(std::hint::black_box(key));
            }
            allocator::finish(1, 0);
        }
    }
}

fn transforms() -> Result<(), Box<dyn std::error::Error>> {
    let root = BlindIndexKey::from_bytes(vec![0x42; 32])?;
    let scope = IndexScope::new(
        rss_request_context::TenantId::parse("11111111-2222-4333-8444-555555555555")?,
        "d",
        "f",
        "n",
    )?;
    // All plaintext generations are >= 1024 bytes; scope/HMAC/index allocations are smaller.
    let text = format!("   {}   ", "ABC123İΑΣ".repeat(512));
    for (steps, copies) in [
        (vec![], 1),
        (vec![Transform::Lowercase], 2),
        (vec![Transform::Trim], 2),
        (vec![Transform::DigitsOnly], 2),
        (vec![Transform::LastN(2048)], 2),
        (
            vec![
                Transform::Trim,
                Transform::Lowercase,
                Transform::DigitsOnly,
                Transform::LastN(1200),
            ],
            5,
        ),
    ] {
        let index = BlindIndex::new(scope.clone(), &steps, FilterBits::DEFAULT);
        allocator::start(1024);
        let result = index.index(&root, std::hint::black_box(&text));
        allocator::finish(copies, 0);
        assert!(result.is_ok());
    }
    for (text, steps, copies) in [
        (String::new(), vec![], 0),
        ("X".repeat(4096), vec![Transform::DigitsOnly], 1),
        (" ".repeat(4096), vec![Transform::Trim], 1),
        ("X".repeat(4096), vec![Transform::LastN(0)], 1),
    ] {
        let index = BlindIndex::new(scope.clone(), &steps, FilterBits::DEFAULT);
        allocator::start(1024);
        let result = index.index(&root, std::hint::black_box(&text));
        allocator::finish(copies, 0);
        assert!(matches!(
            result,
            Err(rss_data_protection::BlindIndexError::EmptyPlaintext)
        ));
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Anti-vacuity: ordinary Vec release must be observed as dirty.
    let bytes = vec![0x5A; 31];
    allocator::start(usize::MAX);
    allocator::watch(&bytes);
    drop(std::hint::black_box(bytes));
    allocator::finish(1, 1);
    match std::env::args().nth(1).as_deref() {
        Some("keys") => keys(),
        Some("transforms") => transforms()?,
        _ => {
            keys();
            transforms()?;
        }
    }
    println!("zeroize probe passed");
    Ok(())
}
