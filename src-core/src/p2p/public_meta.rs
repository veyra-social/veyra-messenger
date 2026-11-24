use unicode_normalization::UnicodeNormalization;

use crate::models::PublicNodeMeta;

pub fn sanitized_public_meta(meta: &PublicNodeMeta) -> Option<PublicNodeMeta> {
    let name = clean_text_field(&meta.name, 1, 48)?;
    let title = clean_text_field(&meta.title, 1, 80)?;
    let info = clean_text_field(&meta.info, 0, 240)?;
    let url = match meta.url.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(clean_url(raw)?),
        _ => None,
    };
    let order = match meta.order {
        Some(value) if value <= 10_000 => Some(value),
        Some(_) => return None,
        None => None,
    };
    let cluster = match meta.cluster.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(clean_cluster(raw)?),
        _ => None,
    };
    let cleaned = PublicNodeMeta {
        name,
        title,
        info,
        url,
        order,
        cluster,
    };
    if has_forbidden_content(&cleaned) {
        return None;
    }
    Some(cleaned)
}

fn clean_text_field(raw: &str, min: usize, max: usize) -> Option<String> {
    let cleaned = normalize_visible(raw);
    let len = cleaned.chars().count();
    if len < min || len > max {
        return None;
    }
    Some(cleaned)
}

fn normalize_visible(raw: &str) -> String {
    raw.nfkc()
        .filter(|c| !c.is_control() && !is_zero_width(*c))
        .collect::<String>()
        .trim()
        .to_string()
}

fn is_zero_width(c: char) -> bool {
    matches!(
        c,
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}'
    )
}

fn clean_url(raw: &str) -> Option<String> {
    let url = normalize_visible(raw);
    let lower = url.to_ascii_lowercase();
    if url.len() > 256
        || url.chars().any(char::is_whitespace)
        || !(lower.starts_with("https://") || lower.starts_with("http://"))
    {
        return None;
    }
    let authority = url
        .split_once("://")
        .map(|(_, rest)| rest.split(['/', '?', '#']).next().unwrap_or_default())
        .unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    Some(url)
}

fn clean_cluster(raw: &str) -> Option<String> {
    let cluster = normalize_visible(raw).to_ascii_lowercase();
    if cluster.len() != 64 || !cluster.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    Some(cluster)
}

fn has_forbidden_content(meta: &PublicNodeMeta) -> bool {
    let mut text = String::new();
    text.push_str(&meta.name);
    text.push(' ');
    text.push_str(&meta.title);
    text.push(' ');
    text.push_str(&meta.info);
    if let Some(url) = &meta.url {
        text.push(' ');
        text.push_str(url);
    }
    let folded = fold_for_filter(&text);
    [
        "javascript:",
        "vbscript:",
        "data:",
        "<script",
        "</script",
        "onerror=",
        "onclick=",
        "onload=",
    ]
    .iter()
    .any(|needle| folded.contains(needle))
}

fn fold_for_filter(raw: &str) -> String {
    let mut out = String::new();
    let mut last = '\0';
    for c in raw.nfkc().flat_map(char::to_lowercase) {
        if c.is_control() || is_zero_width(c) {
            continue;
        }
        let c = if c.is_whitespace() { ' ' } else { c };
        if c == last && !c.is_ascii_alphanumeric() {
            continue;
        }
        out.push(c);
        last = c;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_meta() -> PublicNodeMeta {
        PublicNodeMeta {
            name: "Node A".to_string(),
            title: "Community bootstrap".to_string(),
            info: "Optional public node info".to_string(),
            url: Some("https://example.org/node".to_string()),
            order: Some(10),
            cluster: Some(
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string(),
            ),
        }
    }

    #[test]
    fn accepts_valid_public_meta() {
        assert!(sanitized_public_meta(&valid_meta()).is_some());
    }

    #[test]
    fn rejects_invalid_url_and_cluster() {
        let mut meta = valid_meta();
        meta.url = Some("javascript:alert(1)".to_string());
        assert!(sanitized_public_meta(&meta).is_none());
        meta.url = Some("https://example.org".to_string());
        meta.cluster = Some("abc".to_string());
        assert!(sanitized_public_meta(&meta).is_none());
    }

    #[test]
    fn rejects_filtered_text() {
        let mut meta = valid_meta();
        meta.info = "<script>alert(1)</script>".to_string();
        assert!(sanitized_public_meta(&meta).is_none());
    }
}
