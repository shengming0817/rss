use crate::{
    Action, ActorId, ActorKind, ActorRef, AuditEventV1, AuditPayload, Coordinates, DecodedAuditV1,
    Error, EventContext, EventFacts, EventId, Field, OperationId, Outcome, RecordIdentity,
    RecordVersion, ResourceId, ResourceKind, ResourceRef, SourceContract, SourceId, SourceIdentity,
};
use rss_contract::{ContractId, ContractVersion, SchemaDigest, Timepoint};
use rss_diag_context::CorrelationId;
use rss_request_context::{RequestId, TenantId};

const DOMAIN: &[u8] = b"rss.audit.record\0";
const CONTRACT_ID_MAX_BYTES: usize = 255;
const SCHEMA_DIGEST_BYTES: usize = 71;
const REQUEST_ID_MAX_BYTES: usize = 128;
/// Maximum complete canonical Audit V1 bytes.
pub const MAX_RECORD_BYTES: usize = 131_072;

/// Maximum V1 bytes through the opaque payload's length prefix. Includes thirteen
/// length prefixes, the three optional tags and all fixed-width fields.
pub const MAX_HEADER_BYTES: usize = DOMAIN.len()
    + 2
    + 16
    + 4
    + 1
    + 16
    + 3
    + 13 * 4
    + SourceId::MAX_BYTES
    + EventId::MAX_BYTES
    + CONTRACT_ID_MAX_BYTES
    + SCHEMA_DIGEST_BYTES
    + ActorKind::MAX_BYTES
    + ActorId::MAX_BYTES
    + Action::MAX_BYTES
    + ResourceKind::MAX_BYTES
    + ResourceId::MAX_BYTES
    + CorrelationId::MAX_LEN
    + REQUEST_ID_MAX_BYTES
    + OperationId::MAX_BYTES;

/// Exact complete V1 size, including the fixed-width recorder timestamp.
pub fn canonical_len(event: &AuditEventV1) -> Result<usize, Error> {
    let mut size = 0usize;
    visit_encoding(event, 0, |field| {
        size = size
            .checked_add(field.len())
            .filter(|n| *n <= MAX_RECORD_BYTES)
            .ok_or(Error::RecordTooLarge)?;
        Ok(())
    })?;
    Ok(size)
}

pub(crate) fn encode(event: &AuditEventV1, recorded_at: Timepoint) -> Result<Vec<u8>, Error> {
    let mut bytes = Vec::with_capacity(canonical_len(event)?);
    visit_encoding(event, recorded_at.unix_seconds(), |field| {
        bytes.extend_from_slice(field);
        Ok(())
    })?;
    Ok(bytes)
}

fn visit_encoding(
    event: &AuditEventV1,
    recorded_at: i64,
    mut emit: impl FnMut(&[u8]) -> Result<(), Error>,
) -> Result<(), Error> {
    let id = event.identity();
    let source = id.source();
    let contract = source.contract();
    let facts = event.facts();
    let coordinates = event.context().coordinates();
    emit(DOMAIN)?;
    emit(&RecordVersion::V1.tag().to_be_bytes())?;
    emit(&id.tenant().octets())?;
    for text in [
        source.source_id().as_str(),
        id.event_id().as_str(),
        contract.id().as_str(),
    ] {
        field(&mut emit, text.as_bytes())?;
    }
    emit(&contract.version().major().to_be_bytes())?;
    for text in [
        contract.schema_digest().as_str(),
        facts.actor().kind().as_str(),
        facts.actor().id().as_str(),
        facts.action().as_str(),
        facts.resource().kind().as_str(),
        facts.resource().id().as_str(),
    ] {
        field(&mut emit, text.as_bytes())?;
    }
    emit(&[facts.outcome().tag()])?;
    emit(&facts.occurred_at().unix_seconds().to_be_bytes())?;
    emit(&recorded_at.to_be_bytes())?;
    for coordinate in [
        coordinates.correlation_id().map(CorrelationId::as_str),
        coordinates.request_id().map(RequestId::as_str),
        coordinates.operation_id().map(OperationId::as_str),
    ] {
        emit(&[u8::from(coordinate.is_some())])?;
        if let Some(text) = coordinate {
            field(&mut emit, text.as_bytes())?;
        }
    }
    field(&mut emit, event.context().payload().as_bytes())
}
fn field(emit: &mut impl FnMut(&[u8]) -> Result<(), Error>, bytes: &[u8]) -> Result<(), Error> {
    let len = u32::try_from(bytes.len()).map_err(|_| Error::RecordTooLarge)?;
    emit(&len.to_be_bytes())?;
    emit(bytes)
}

/// Decode canonical V1 bytes after applying all structural and size checks.
///
/// The returned value is not source authentication, ledger authentication, or durable-commit
/// evidence. With the ledger feature, use an authenticated window for verified reads.
pub fn decode_untrusted(bytes: &[u8]) -> Result<DecodedAuditV1, Error> {
    #[cfg(feature = "integration")]
    tracing::trace!(target: "read_cost::decode", "decode");
    let parsed = parse(bytes)?;
    let context = EventContext::new(
        parsed.coordinates,
        AuditPayload::new(parsed.payload.to_vec())?,
    );
    Ok(DecodedAuditV1::new(
        AuditEventV1::new(parsed.identity, parsed.facts, context),
        parsed.recorded_at,
    ))
}

pub(crate) struct Parsed<'a> {
    pub identity: RecordIdentity,
    pub facts: EventFacts,
    pub recorded_at: Timepoint,
    coordinates: Coordinates,
    payload: &'a [u8],
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Parsed<'_>, Error> {
    parse_prefix(bytes, bytes.len())
}

/// Inspect structural identity and time from a bounded prefix and the actual stored length.
/// The suffix is an opaque payload. This cannot mint a prepared record or authenticate it.
pub fn inspect_canonical_header(
    prefix: &[u8],
    record_len: usize,
) -> Result<(RecordIdentity, Timepoint), Error> {
    let parsed = parse_prefix(prefix, record_len)?;
    Ok((parsed.identity, parsed.recorded_at))
}

fn parse_prefix(bytes: &[u8], record_len: usize) -> Result<Parsed<'_>, Error> {
    if record_len > MAX_RECORD_BYTES {
        return Err(Error::RecordTooLarge);
    }
    if bytes.len() > record_len {
        return Err(Error::MalformedEncoding);
    }
    let mut reader = Reader::new(bytes);
    if reader.take(DOMAIN.len())? != DOMAIN {
        return Err(Error::MalformedEncoding);
    }
    if reader.u16()? != RecordVersion::V1.tag() {
        return Err(Error::UnsupportedVersion);
    }
    let tenant = decode_tenant(reader.take(16)?)?;
    let source_id = SourceId::parse(reader.text(Field::SourceId, SourceId::MAX_BYTES)?)?;
    let event_id = EventId::parse(reader.text(Field::EventId, EventId::MAX_BYTES)?)?;
    let contract_id_text = reader.text(Field::SourceContract, CONTRACT_ID_MAX_BYTES)?;
    if contract_id_text.is_empty() {
        return Err(Error::Empty(Field::SourceContract));
    }
    let contract_id = ContractId::parse(contract_id_text)
        .map_err(|_| Error::InvalidCharacter(Field::SourceContract))?;
    let contract_version =
        ContractVersion::from_major(reader.u32()?).map_err(|_| Error::MalformedEncoding)?;
    let schema_digest_text = reader.text(Field::SourceContract, SCHEMA_DIGEST_BYTES)?;
    if schema_digest_text.is_empty() {
        return Err(Error::Empty(Field::SourceContract));
    }
    let schema_digest = SchemaDigest::parse(schema_digest_text)
        .map_err(|_| Error::InvalidCharacter(Field::SourceContract))?;
    let actor_kind = ActorKind::parse(reader.text(Field::ActorKind, ActorKind::MAX_BYTES)?)?;
    let actor_id = ActorId::parse(reader.text(Field::ActorId, ActorId::MAX_BYTES)?)?;
    let action = Action::parse(reader.text(Field::Action, Action::MAX_BYTES)?)?;
    let resource_kind =
        ResourceKind::parse(reader.text(Field::ResourceKind, ResourceKind::MAX_BYTES)?)?;
    let resource_id = ResourceId::parse(reader.text(Field::ResourceId, ResourceId::MAX_BYTES)?)?;
    let outcome = Outcome::from_tag(reader.u8()?).ok_or(Error::UnsupportedTag)?;
    let occurred_at = Timepoint::try_from(reader.i64()?).map_err(|_| Error::MalformedEncoding)?;
    let recorded_at = Timepoint::try_from(reader.i64()?).map_err(|_| Error::MalformedEncoding)?;
    let correlation_id = reader
        .optional_text(Field::CorrelationId, CorrelationId::MAX_LEN)?
        .map(CorrelationId::parse)
        .transpose()
        .map_err(|_| Error::InvalidCharacter(Field::CorrelationId))?;
    let request_id = reader
        .optional_text(Field::RequestId, REQUEST_ID_MAX_BYTES)?
        .map(RequestId::parse)
        .transpose()
        .map_err(|_| Error::InvalidCharacter(Field::RequestId))?;
    let operation_id = reader
        .optional_text(Field::OperationId, OperationId::MAX_BYTES)?
        .map(OperationId::parse)
        .transpose()?;
    let payload_len = reader.u32()? as usize;
    if payload_len > MAX_RECORD_BYTES {
        return Err(Error::RecordTooLarge);
    }
    match (reader.offset + payload_len).cmp(&record_len) {
        std::cmp::Ordering::Greater => return Err(Error::MalformedEncoding),
        std::cmp::Ordering::Less => return Err(Error::UnknownField),
        std::cmp::Ordering::Equal => {}
    }
    let payload = &bytes[reader.offset..];
    let source = SourceIdentity::new(
        source_id,
        SourceContract::new(contract_id, contract_version, schema_digest),
    );
    let identity = RecordIdentity::new(tenant, source, event_id);
    let facts = EventFacts::new(
        ActorRef::new(actor_kind, actor_id),
        action,
        ResourceRef::new(resource_kind, resource_id),
        outcome,
        occurred_at,
    );
    Ok(Parsed {
        identity,
        facts,
        recorded_at,
        coordinates: Coordinates::new(correlation_id, request_id, operation_id),
        payload,
    })
}

fn decode_tenant(bytes: &[u8]) -> Result<TenantId, Error> {
    let mut value = String::with_capacity(36);
    for (index, byte) in bytes.iter().copied().enumerate() {
        if matches!(index, 4 | 6 | 8 | 10) {
            value.push('-');
        }
        value.push(char::from(b"0123456789abcdef"[usize::from(byte >> 4)]));
        value.push(char::from(b"0123456789abcdef"[usize::from(byte & 0x0f)]));
    }
    TenantId::parse(&value).map_err(|_| Error::MalformedEncoding)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(Error::MalformedEncoding)?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::MalformedEncoding)?;
        self.offset = end;
        Ok(value)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        self.take(N)?
            .try_into()
            .map_err(|_| Error::MalformedEncoding)
    }

    fn u8(&mut self) -> Result<u8, Error> {
        Ok(self.fixed::<1>()?[0])
    }

    fn u16(&mut self) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.fixed()?))
    }

    fn u32(&mut self) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.fixed()?))
    }

    fn i64(&mut self) -> Result<i64, Error> {
        Ok(i64::from_be_bytes(self.fixed()?))
    }

    fn bytes(&mut self, field: Field, max: usize) -> Result<&'a [u8], Error> {
        let len = usize::try_from(self.u32()?).map_err(|_| Error::MalformedEncoding)?;
        if len > max {
            return Err(Error::TooLong(field));
        }
        self.take(len)
    }

    fn text(&mut self, field: Field, max: usize) -> Result<&'a str, Error> {
        std::str::from_utf8(self.bytes(field, max)?).map_err(|_| Error::InvalidCharacter(field))
    }

    fn optional_text(&mut self, field: Field, max: usize) -> Result<Option<&'a str>, Error> {
        match self.u8()? {
            0 => Ok(None),
            1 => self.text(field, max).map(Some),
            _ => Err(Error::UnsupportedTag),
        }
    }
}
