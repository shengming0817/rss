//! Test-only semantic contracts for SQL migration routines.

#![allow(dead_code)]

#[derive(Clone, Copy)]
pub(crate) enum RoutineSchema<'a> {
    Named(&'a str),
    Unqualified,
}

#[derive(Clone, Copy)]
pub(crate) struct RoutineIdentity<'a> {
    pub(crate) schema: RoutineSchema<'a>,
    pub(crate) name: &'a str,
    pub(crate) argument_types: &'a [&'a str],
}

impl<'a> RoutineIdentity<'a> {
    pub(crate) const fn public(name: &'a str, argument_types: &'a [&'a str]) -> Self {
        Self::named("public", name, argument_types)
    }

    pub(crate) const fn named(
        schema: &'a str,
        name: &'a str,
        argument_types: &'a [&'a str],
    ) -> Self {
        Self {
            schema: RoutineSchema::Named(schema),
            name,
            argument_types,
        }
    }

    pub(crate) const fn unqualified(name: &'a str, argument_types: &'a [&'a str]) -> Self {
        Self {
            schema: RoutineSchema::Unqualified,
            name,
            argument_types,
        }
    }

    fn declaration_name(self) -> String {
        match self.schema {
            RoutineSchema::Named(schema) => format!("{schema}.{}", self.name),
            RoutineSchema::Unqualified => self.name.to_owned(),
        }
    }

    fn resolved_name(self) -> String {
        match self.schema {
            RoutineSchema::Named(schema) => format!("{schema}.{}", self.name),
            RoutineSchema::Unqualified => format!("<unqualified>.{}", self.name),
        }
    }

    fn label(self) -> String {
        format!(
            "{}({})",
            self.resolved_name(),
            self.argument_types.join(",")
        )
    }
}

pub(crate) struct RoutineContract<'a> {
    pub(crate) identity: RoutineIdentity<'a>,
    pub(crate) required: &'a [&'a str],
    pub(crate) forbidden: &'a [&'a str],
    pub(crate) ordered: &'a [&'a str],
}

impl RoutineContract<'_> {
    pub(crate) fn check(&self, sql: &str) -> Result<(), String> {
        let definition = canonical_sql(&routine_definition(sql, self.identity)?);
        let label = self.identity.label();
        for required in self.required {
            let required = canonical_sql(required);
            if !definition.contains(&required) {
                return Err(format!(
                    "routine `{label}` is missing semantic fragment `{required}`"
                ));
            }
        }
        for forbidden in self.forbidden {
            let forbidden = canonical_sql(forbidden);
            if definition.contains(&forbidden) {
                return Err(format!(
                    "routine `{label}` contains forbidden semantic fragment `{forbidden}`"
                ));
            }
        }
        let ordered = self
            .ordered
            .iter()
            .map(|fragment| canonical_sql(fragment))
            .collect::<Vec<_>>();
        assert_fragments_in_order(&definition, &label, &ordered)
    }
}

pub(crate) struct RoutineHeaderContract<'a> {
    pub(crate) identity: RoutineIdentity<'a>,
    pub(crate) required: &'a [&'a str],
    pub(crate) forbidden: &'a [&'a str],
}

impl RoutineHeaderContract<'_> {
    pub(crate) fn check(&self, sql: &str) -> Result<(), String> {
        let span = routine_span(sql, self.identity)?;
        let header = canonical_sql(&sql[span.start..span.body_delimiter_start]);
        let label = self.identity.label();
        for required in self.required {
            if !header.contains(&canonical_sql(required)) {
                return Err(format!(
                    "routine `{label}` header is missing semantic fragment `{required}`"
                ));
            }
        }
        for forbidden in self.forbidden {
            if header.contains(&canonical_sql(forbidden)) {
                return Err(format!(
                    "routine `{label}` header contains forbidden semantic fragment `{forbidden}`"
                ));
            }
        }
        Ok(())
    }
}

pub(crate) fn normalize_sql(sql: &str) -> String {
    strip_sql_comments(sql)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn canonical_sql(sql: &str) -> String {
    let stripped = strip_sql_comments(sql);
    let bytes = stripped.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let start = index;
        if bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'.') {
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric()
                    || matches!(bytes[index], b'_' | b'.')
                    || (bytes[index] == b':'
                        && bytes.get(index + 1).is_some_and(u8::is_ascii_alphanumeric)))
            {
                index += 1;
            }
        } else if bytes[index] == b'\'' || bytes[index] == b'"' {
            index = quoted_end(bytes, index, bytes[index]);
        } else {
            index += 1;
        }
        tokens.push(&stripped[start..index]);
    }
    tokens.join(" ")
}

pub(crate) fn routine_definition(
    sql: &str,
    identity: RoutineIdentity<'_>,
) -> Result<String, String> {
    routine_span(sql, identity).map(|span| sql[span.start..span.end].to_owned())
}

pub(crate) fn routine_definition_slice<'a>(
    sql: &'a str,
    identity: RoutineIdentity<'_>,
) -> Result<&'a str, String> {
    routine_span(sql, identity).map(|span| &sql[span.start..span.end])
}

#[derive(Clone, Copy)]
struct RoutineSpan {
    start: usize,
    body_delimiter_start: usize,
    end: usize,
}

fn routine_span(sql: &str, identity: RoutineIdentity<'_>) -> Result<RoutineSpan, String> {
    let code = top_level_code_mask(sql);
    let tokens = sql_tokens(&code);
    let declaration_name = identity.declaration_name();
    let mut matches = Vec::new();
    let mut index = 0;
    while index < tokens.len() {
        let Some((name_index, open_index)) = create_function_header(&tokens, index) else {
            index += 1;
            continue;
        };
        if !tokens[name_index]
            .text
            .eq_ignore_ascii_case(&declaration_name)
        {
            index += 1;
            continue;
        }
        let Some(close_index) = matching_parenthesis(&tokens, open_index) else {
            return Err(format!(
                "routine `{}` has an unterminated argument list",
                identity.label()
            ));
        };
        let arguments = &sql[tokens[open_index].end..tokens[close_index].start];
        if argument_types_match(arguments, identity.argument_types) {
            let start = tokens[index].start;
            let statement_end_index = tokens
                .iter()
                .enumerate()
                .skip(close_index + 1)
                .find_map(|(token_index, token)| (token.text == ";").then_some(token_index))
                .ok_or_else(|| {
                    format!("routine `{}` has no statement terminator", identity.label())
                })?;
            let as_token = tokens[close_index + 1..statement_end_index]
                .iter()
                .find(|token| token.text.eq_ignore_ascii_case("AS"))
                .ok_or_else(|| {
                    format!("routine `{}` has no AS body introducer", identity.label())
                })?;
            let body_delimiter_start =
                skip_whitespace_and_comments(sql, as_token.end, tokens[statement_end_index].start);
            let delimiter = dollar_delimiter_at(sql, body_delimiter_start).ok_or_else(|| {
                format!(
                    "routine `{}` has no dollar-quoted body at its AS introducer",
                    identity.label()
                )
            })?;
            let body_start = body_delimiter_start + delimiter.len();
            let body_end = sql[body_start..].find(&delimiter).ok_or_else(|| {
                format!(
                    "routine `{}` has an unterminated `{delimiter}` body",
                    identity.label()
                )
            })?;
            matches.push(RoutineSpan {
                start,
                body_delimiter_start,
                end: body_start + body_end + delimiter.len(),
            });
        }
        index = close_index + 1;
    }
    matches
        .into_iter()
        .last()
        .ok_or_else(|| format!("missing exact routine `{}`", identity.label()))
}

fn skip_whitespace_and_comments(sql: &str, mut index: usize, limit: usize) -> usize {
    let bytes = sql.as_bytes();
    while index < limit {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
        } else if bytes[index..].starts_with(b"--") {
            index = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(limit, |offset| (index + offset).min(limit));
        } else if bytes[index..].starts_with(b"/*") {
            index = block_comment_end(bytes, index).min(limit);
        } else {
            break;
        }
    }
    index
}

fn dollar_delimiter_at(sql: &str, start: usize) -> Option<String> {
    let tail = sql.get(start..)?;
    let (_, delimiter) = find_dollar_delimiter(tail)?;
    tail.starts_with(&delimiter).then_some(delimiter)
}

struct SqlToken<'a> {
    text: &'a str,
    start: usize,
    end: usize,
}

fn sql_tokens(code: &str) -> Vec<SqlToken<'_>> {
    let bytes = code.as_bytes();
    let mut tokens = Vec::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index].is_ascii_whitespace() {
            index += 1;
            continue;
        }
        let start = index;
        if bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'.') {
            while index < bytes.len()
                && (bytes[index].is_ascii_alphanumeric() || matches!(bytes[index], b'_' | b'.'))
            {
                index += 1;
            }
        } else {
            index += 1;
        }
        tokens.push(SqlToken {
            text: &code[start..index],
            start,
            end: index,
        });
    }
    tokens
}

fn create_function_header(tokens: &[SqlToken<'_>], index: usize) -> Option<(usize, usize)> {
    if !tokens.get(index)?.text.eq_ignore_ascii_case("CREATE") {
        return None;
    }
    let mut cursor = index + 1;
    if tokens.get(cursor)?.text.eq_ignore_ascii_case("OR") {
        if !tokens.get(cursor + 1)?.text.eq_ignore_ascii_case("REPLACE") {
            return None;
        }
        cursor += 2;
    }
    if !tokens.get(cursor)?.text.eq_ignore_ascii_case("FUNCTION") {
        return None;
    }
    let name_index = cursor + 1;
    let open_index = cursor + 2;
    (tokens.get(open_index)?.text == "(").then_some((name_index, open_index))
}

fn matching_parenthesis(tokens: &[SqlToken<'_>], open_index: usize) -> Option<usize> {
    let mut depth = 0_u32;
    for (index, token) in tokens.iter().enumerate().skip(open_index) {
        match token.text {
            "(" => depth += 1,
            ")" => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return Some(index);
                }
            }
            _ => {}
        }
    }
    None
}

fn argument_types_match(arguments: &str, expected: &[&str]) -> bool {
    let actual = split_arguments(arguments);
    actual.len() == expected.len()
        && actual.iter().zip(expected).all(|(parameter, expected)| {
            let parameter = normalize_sql(parameter);
            let expected = normalize_sql(expected);
            parameter == expected || parameter.ends_with(&format!(" {expected}"))
        })
}

fn split_arguments(arguments: &str) -> Vec<&str> {
    let mut result = Vec::new();
    let mut start = 0;
    let mut depth = 0_u32;
    for (index, character) in arguments.char_indices() {
        match character {
            '(' | '[' => depth += 1,
            ')' | ']' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                result.push(arguments[start..index].trim());
                start = index + 1;
            }
            _ => {}
        }
    }
    if !arguments[start..].trim().is_empty() {
        result.push(arguments[start..].trim());
    }
    result
}

fn find_dollar_delimiter(sql: &str) -> Option<(usize, String)> {
    for (start, _) in sql.match_indices('$') {
        let suffix = &sql[start + 1..];
        let Some(end) = suffix.find('$') else {
            continue;
        };
        let tag = &suffix[..end];
        if tag
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return Some((start, format!("${tag}$")));
        }
    }
    None
}

fn top_level_code_mask(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut masked = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"--") {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| index + offset);
            masked[index..end].fill(b' ');
            index = end;
        } else if bytes[index..].starts_with(b"/*") {
            let end = block_comment_end(bytes, index);
            masked[index..end].fill(b' ');
            index = end;
        } else if bytes[index] == b'\'' || bytes[index] == b'"' {
            let end = quoted_end(bytes, index, bytes[index]);
            masked[index..end].fill(b' ');
            index = end;
        } else if bytes[index] == b'$' {
            let Some((delimiter_start, delimiter)) = find_dollar_delimiter(&sql[index..]) else {
                index += 1;
                continue;
            };
            if delimiter_start != 0 {
                index += 1;
                continue;
            }
            let body_start = index + delimiter.len();
            let end = sql[body_start..]
                .find(&delimiter)
                .map_or(bytes.len(), |offset| body_start + offset + delimiter.len());
            masked[index..end].fill(b' ');
            index = end;
        } else {
            index += 1;
        }
    }
    String::from_utf8(masked).unwrap_or_default()
}

fn strip_sql_comments(sql: &str) -> String {
    let bytes = sql.as_bytes();
    let mut stripped = bytes.to_vec();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index..].starts_with(b"--") {
            let end = bytes[index..]
                .iter()
                .position(|byte| *byte == b'\n')
                .map_or(bytes.len(), |offset| index + offset);
            stripped[index..end].fill(b' ');
            index = end;
        } else if bytes[index..].starts_with(b"/*") {
            let end = block_comment_end(bytes, index);
            stripped[index..end].fill(b' ');
            index = end;
        } else if bytes[index] == b'\'' || bytes[index] == b'"' {
            index = quoted_end(bytes, index, bytes[index]);
        } else {
            index += 1;
        }
    }
    String::from_utf8(stripped).unwrap_or_default()
}

fn quoted_end(bytes: &[u8], start: usize, quote: u8) -> usize {
    let mut index = start + 1;
    while index < bytes.len() {
        if bytes[index] == quote {
            if bytes.get(index + 1) == Some(&quote) {
                index += 2;
            } else {
                return index + 1;
            }
        } else if bytes[index] == b'\\' {
            index = (index + 2).min(bytes.len());
        } else {
            index += 1;
        }
    }
    bytes.len()
}

fn block_comment_end(bytes: &[u8], start: usize) -> usize {
    let mut depth = 1_u32;
    let mut index = start + 2;
    while index < bytes.len() && depth > 0 {
        if bytes[index..].starts_with(b"/*") {
            depth += 1;
            index += 2;
        } else if bytes[index..].starts_with(b"*/") {
            depth -= 1;
            index += 2;
        } else {
            index += 1;
        }
    }
    index
}

fn assert_fragments_in_order(
    definition: &str,
    identity: &str,
    ordered: &[String],
) -> Result<(), String> {
    let mut cursor = 0;
    for fragment in ordered {
        let relative = definition[cursor..].find(fragment).ok_or_else(|| {
            format!("routine `{identity}` is missing ordered semantic fragment `{fragment}`")
        })?;
        cursor += relative + fragment.len();
    }
    Ok(())
}
