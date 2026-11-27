//! Account directory values. Field binding and SQL remain with the Identity adapters.
//! ref: tokio-rs/axum axum-v0.8.9 src/extract/query.rs.
use serde::{Deserialize, Serialize};

/// Largest explicitly selected account/session page.
pub const MAX_PAGE_SIZE: u16 = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Field {
    PrincipalId,
    Login,
    Enabled,
    MemberActive,
    HasLocalPassword,
    DisplayName,
    Email,
    ProfileStatus,
    DepartmentStatus,
    DepartmentSnapshot,
    Department,
    DepartmentSubtree,
}
impl Field {
    pub fn parse(name: &str) -> Result<Self, InvalidQuery> {
        serde_json::from_value(serde_json::Value::String(name.into())).map_err(|_| InvalidQuery)
    }
    pub fn name(self) -> &'static str {
        match self {
            Self::PrincipalId => "principalId",
            Self::Login => "login",
            Self::Enabled => "enabled",
            Self::MemberActive => "memberActive",
            Self::HasLocalPassword => "hasLocalPassword",
            Self::DisplayName => "displayName",
            Self::Email => "email",
            Self::ProfileStatus => "profileStatus",
            Self::DepartmentStatus => "departmentStatus",
            Self::DepartmentSnapshot => "departmentSnapshot",
            Self::Department => "department",
            Self::DepartmentSubtree => "departmentSubtree",
        }
    }
    pub fn profile(self) -> bool {
        matches!(self, Self::DisplayName | Self::Email | Self::ProfileStatus)
    }
    pub fn department(self) -> bool {
        matches!(
            self,
            Self::DepartmentStatus
                | Self::DepartmentSnapshot
                | Self::Department
                | Self::DepartmentSubtree
        )
    }
    pub fn boolean(self) -> bool {
        matches!(
            self,
            Self::Enabled | Self::MemberActive | Self::HasLocalPassword
        )
    }
    pub fn sortable(self) -> bool {
        !matches!(
            self,
            Self::DepartmentSnapshot | Self::Department | Self::DepartmentSubtree
        )
    }
    pub fn output(self) -> bool {
        !matches!(self, Self::Department | Self::DepartmentSubtree)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Sort {
    pub field: Field,
    pub descending: bool,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Expression {
    Compare {
        field: Field,
        operator: String,
        values: Vec<String>,
    },
    And(Vec<Expression>),
    Or(Vec<Expression>),
}
impl Expression {
    pub fn fields(&self, out: &mut Vec<Field>) {
        match self {
            Self::Compare { field, .. } => out.push(*field),
            Self::And(items) | Self::Or(items) => items.iter().for_each(|item| item.fields(out)),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AccountQuery {
    filter: Option<Expression>,
    sort: Vec<Sort>,
    fields: Vec<Field>,
    source: Option<String>,
    limit: u16,
}
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("invalid account query")]
pub struct InvalidQuery;
impl Default for AccountQuery {
    fn default() -> Self {
        Self::parse(None, None, None, None, 50).expect("default account query")
    }
}
impl AccountQuery {
    /// Parse bounded account-directory inputs; omitted ordering uses `principalId`.
    ///
    /// Filters use `;` for AND and `,` for OR (AND binds more tightly); parentheses
    /// group conditions. Quote operands containing delimiters and escape quotes or
    /// backslashes with a backslash. Sets use `=in=(...)` / `=out=(...)`; null tests use
    /// `=isnull=true` / `=isnotnull=true`. Sorting is comma-separated, with `-` for
    /// descending order; the unique principal key is appended automatically.
    /// Profile and department fields require an explicit source (`local` or IdP UUID).
    ///
    /// ```
    /// use rss_identity_core::directory::AccountQuery;
    /// let query = AccountQuery::parse(Some("enabled==true;login=icontains='alice'"),
    ///     Some("-login"), Some("principalId,login"), None, 20)?;
    /// # Ok::<(), rss_identity_core::directory::InvalidQuery>(())
    /// ```
    pub fn parse(
        filter: Option<&str>,
        sort: Option<&str>,
        fields: Option<&str>,
        source: Option<&str>,
        limit: u16,
    ) -> Result<Self, InvalidQuery> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(InvalidQuery);
        }
        let source = source
            .map(|s| {
                if s == "local" {
                    Ok(s.to_owned())
                } else {
                    crate::federation::ProviderId::parse(s)
                        .map(|id| id.to_string())
                        .map_err(|_| InvalidQuery)
                }
            })
            .transpose()?;
        let fields = match fields {
            Some(raw) => names(raw)?
                .into_iter()
                .map(Field::parse)
                .collect::<Result<Vec<_>, _>>()?,
            None => vec![
                Field::PrincipalId,
                Field::Login,
                Field::Enabled,
                Field::MemberActive,
                Field::HasLocalPassword,
            ],
        };
        if fields.iter().any(|field| !field.output()) {
            return Err(InvalidQuery);
        }
        let mut ordering = Vec::new();
        if let Some(raw) = sort {
            for name in names(raw)? {
                let field = Field::parse(name.strip_prefix('-').unwrap_or(name))?;
                if !field.sortable() || ordering.iter().any(|s: &Sort| s.field == field) {
                    return Err(InvalidQuery);
                }
                ordering.push(Sort {
                    field,
                    descending: name.starts_with('-'),
                });
            }
        }
        if !ordering.iter().any(|s| s.field == Field::PrincipalId) {
            ordering.push(Sort {
                field: Field::PrincipalId,
                descending: false,
            });
        }
        let filter = filter.map(parse_filter).transpose()?;
        let result = Self {
            filter,
            sort: ordering,
            fields,
            source,
            limit,
        };
        if (result.needs_profiles() || result.needs_departments()) && result.source.is_none() {
            return Err(InvalidQuery);
        }
        if result.needs_departments() && result.source.as_deref() == Some("local") {
            return Err(InvalidQuery);
        }
        Ok(result)
    }
    pub fn filter(&self) -> Option<&Expression> {
        self.filter.as_ref()
    }
    pub fn sort(&self) -> &[Sort] {
        &self.sort
    }
    pub fn fields(&self) -> &[Field] {
        &self.fields
    }
    pub fn source(&self) -> Option<&str> {
        self.source.as_deref()
    }
    pub fn limit(&self) -> u16 {
        self.limit
    }
    /// Fields affecting membership, ordering or the requested projection.
    pub fn used_fields(&self) -> Vec<Field> {
        let mut used = self.fields.clone();
        used.extend(self.sort.iter().map(|s| s.field));
        if let Some(filter) = &self.filter {
            filter.fields(&mut used);
        }
        used
    }
    pub fn needs_profiles(&self) -> bool {
        self.used_fields().iter().any(|f| f.profile())
    }
    pub fn needs_departments(&self) -> bool {
        self.used_fields().iter().any(|f| f.department())
    }
}
fn names(raw: &str) -> Result<Vec<&str>, InvalidQuery> {
    if raw.len() > 4096 {
        return Err(InvalidQuery);
    }
    let names: Vec<_> = raw.split(',').collect();
    if names.is_empty()
        || names.len() > 16
        || names.iter().any(|s| s.is_empty() || s.len() > 128)
        || names
            .iter()
            .enumerate()
            .any(|(i, s)| names[..i].contains(s))
    {
        return Err(InvalidQuery);
    }
    Ok(names)
}
fn parse_filter(raw: &str) -> Result<Expression, InvalidQuery> {
    if raw.is_empty() || raw.len() > 8192 {
        return Err(InvalidQuery);
    }
    let mut parser = Parser {
        raw,
        offset: 0,
        nodes: 0,
        set_items: 0,
    };
    let expression = parser.expression(0, 0)?;
    if parser.offset != raw.len() {
        return Err(InvalidQuery);
    }
    Ok(expression)
}
struct Parser<'a> {
    raw: &'a str,
    offset: usize,
    nodes: usize,
    set_items: usize,
}
impl Parser<'_> {
    fn eat(&mut self, text: &str) -> bool {
        if self.raw[self.offset..].starts_with(text) {
            self.offset += text.len();
            true
        } else {
            false
        }
    }
    fn expression(&mut self, precedence: u8, depth: usize) -> Result<Expression, InvalidQuery> {
        if depth > 16 {
            return Err(InvalidQuery);
        }
        if precedence < 2 {
            let first = self.expression(precedence + 1, depth)?;
            let separator = if precedence == 0 { "," } else { ";" };
            if !self.eat(separator) {
                return Ok(first);
            }
            self.node()?;
            let mut items = vec![first];
            loop {
                items.push(self.expression(precedence + 1, depth)?);
                if !self.eat(separator) {
                    break;
                }
            }
            return Ok(if precedence == 0 {
                Expression::Or(items)
            } else {
                Expression::And(items)
            });
        }
        if self.eat("(") {
            let inner = self.expression(0, depth + 1)?;
            if !self.eat(")") {
                return Err(InvalidQuery);
            }
            return Ok(inner);
        }
        self.node()?;
        let start = self.offset;
        while self
            .raw
            .as_bytes()
            .get(self.offset)
            .is_some_and(u8::is_ascii_alphanumeric)
        {
            self.offset += 1;
        }
        let field = Field::parse(&self.raw[start..self.offset])?;
        let operator = [
            "==",
            "!=",
            "=lt=",
            "=le=",
            "=gt=",
            "=ge=",
            "=icontains=",
            "=in=",
            "=out=",
            "=isnull=",
            "=isnotnull=",
        ]
        .into_iter()
        .find(|op| self.eat(op))
        .ok_or(InvalidQuery)?;
        let set = matches!(operator, "=in=" | "=out=");
        let mut values = if set {
            if !self.eat("(") {
                return Err(InvalidQuery);
            }
            let mut values = Vec::new();
            loop {
                self.set_items += 1;
                if self.set_items > 256 || values.len() >= 64 {
                    return Err(InvalidQuery);
                }
                values.push(self.value()?);
                if self.eat(")") {
                    break;
                }
                if !self.eat(",") {
                    return Err(InvalidQuery);
                }
            }
            values
        } else {
            vec![self.value()?]
        };
        if !field.sortable()
            && (!matches!(field, Field::Department | Field::DepartmentSubtree) || operator != "==")
        {
            return Err(InvalidQuery);
        }
        if field.boolean()
            && (!matches!(operator, "==" | "!=")
                || values
                    .iter()
                    .any(|v| !matches!(v.as_str(), "true" | "false")))
        {
            return Err(InvalidQuery);
        }
        if matches!(operator, "=isnull=" | "=isnotnull=") && values != ["true"] {
            return Err(InvalidQuery);
        }
        if field == Field::PrincipalId {
            for value in &mut values {
                *value = crate::PrincipalId::parse(value)
                    .map_err(|_| InvalidQuery)?
                    .as_uuid()
                    .to_string();
            }
        }
        Ok(Expression::Compare {
            field,
            operator: operator.into(),
            values,
        })
    }
    fn node(&mut self) -> Result<(), InvalidQuery> {
        self.nodes += 1;
        if self.nodes > 128 {
            Err(InvalidQuery)
        } else {
            Ok(())
        }
    }
    fn value(&mut self) -> Result<String, InvalidQuery> {
        let quote = if self.eat("'") {
            Some('\'')
        } else if self.eat("\"") {
            Some('"')
        } else {
            None
        };
        let mut value = String::new();
        let mut closed = quote.is_none();
        while let Some(c) = self.raw[self.offset..].chars().next() {
            if quote == Some(c) {
                self.offset += c.len_utf8();
                closed = true;
                break;
            }
            if quote.is_none() && [',', ';', ')'].contains(&c) {
                break;
            }
            self.offset += c.len_utf8();
            let c = if c == '\\' {
                let next = self.raw[self.offset..].chars().next().ok_or(InvalidQuery)?;
                if !"\\'\",;()".contains(next) {
                    return Err(InvalidQuery);
                }
                self.offset += next.len_utf8();
                next
            } else {
                if quote.is_none() && (c.is_whitespace() || "('\"=!<>*".contains(c)) {
                    return Err(InvalidQuery);
                }
                c
            };
            if c.is_control() {
                return Err(InvalidQuery);
            }
            value.push(c);
            if value.len() > 1024 {
                return Err(InvalidQuery);
            }
        }
        if !closed || (quote.is_none() && value.is_empty()) {
            return Err(InvalidQuery);
        }
        Ok(value)
    }
}
