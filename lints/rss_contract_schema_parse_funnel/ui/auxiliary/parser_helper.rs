pub fn cross_file(bytes: &[u8]) {
    use crate::serde_json::Deserializer as JsonDeserializer;
    use crate::serde_json::from_reader as parse_json;

    let parser = parse_json::<_, crate::serde_json::Value>;
    let _ = parser(bytes);
    let _ = JsonDeserializer::from_slice(bytes);

    let closure = || crate::serde_json::from_slice::<crate::serde_json::Value>(bytes);
    let _ = closure();
}
