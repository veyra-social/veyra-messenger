//! Filesystem-safe names for attachment data that came off the wire.
//!
//! An inbound attachment carries a `file_name` and a `transfer_id` chosen by
//! the remote sender. Both used to reach the filesystem verbatim: the name was
//! joined into the `shared` directory before opening, and the transfer id
//! became a directory component under `attachments/`. Neither is trustworthy —
//! `..`, path separators, drive prefixes and Windows reserved names all had to
//! be assumed hostile (code review 2026-07-27, P1). Every path built from
//! remote input goes through this module.

/// Fallback when the sender's name survives sanitisation as nothing usable.
const FALLBACK_FILE_NAME: &str = "attachment";

/// Upper bound on a sanitised name. Filesystems cap a single component near
/// 255 bytes; staying well below leaves room for the callers' own prefixes
/// (`dl-<uuid>-`) and for a collision suffix.
const MAX_FILE_NAME_CHARS: usize = 120;

/// Characters no Windows path component may contain. `/` and `\` are here as
/// separators — the basename step already dropped everything before them, so
/// what is left is a name that merely looked like a path.
const FORBIDDEN_CHARS: [char; 9] = ['<', '>', ':', '"', '/', '\\', '|', '?', '*'];

/// Device names that Windows resolves regardless of the directory they are
/// written in, with or without an extension.
const RESERVED_STEMS: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8",
    "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
];

/// Reduces a sender-supplied file name to a single safe path component.
///
/// The result never contains a path separator, never resolves to `.` or `..`,
/// never collides with a Windows device name, and is never empty — so
/// `dir.join(sanitize_attachment_file_name(name))` always lands directly
/// inside `dir`.
pub fn sanitize_attachment_file_name(raw: &str) -> String {
    // Basename first: everything up to the last separator (or a drive colon)
    // is the sender's idea of a location, and we have our own.
    let basename = raw.rsplit(['/', '\\', ':']).next().unwrap_or("");

    let mut cleaned: String = basename
        .chars()
        .map(|c| {
            if c.is_control() || FORBIDDEN_CHARS.contains(&c) {
                '_'
            } else {
                c
            }
        })
        .collect();

    // Windows silently strips trailing dots and spaces, which would turn
    // "evil. " into "evil" after the fact — do it ourselves so the name we
    // check is the name that lands.
    cleaned = cleaned.trim().trim_end_matches(['.', ' ']).to_string();
    cleaned = cleaned.trim_start().to_string();

    if cleaned.is_empty() || cleaned.chars().all(|c| c == '.') {
        cleaned = FALLBACK_FILE_NAME.to_string();
    }

    let stem = cleaned.split('.').next().unwrap_or("").to_ascii_lowercase();
    if RESERVED_STEMS.contains(&stem.as_str()) {
        cleaned.insert(0, '_');
    }

    truncate_preserving_extension(&cleaned)
}

/// True when a sender-supplied transfer id is safe as a directory component.
///
/// Our own ids are UUIDv4, but the check stays on the shape of the string
/// rather than on the UUID grammar: any peer implementation that keeps to
/// plain id characters interoperates, while separators, dots and empty ids —
/// the ones that can escape `attachments/` — do not.
pub fn is_safe_transfer_id(transfer_id: &str) -> bool {
    !transfer_id.is_empty()
        && transfer_id.len() <= 64
        && transfer_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// Trims to `MAX_FILE_NAME_CHARS`, keeping a short trailing extension so the
/// OS still opens the file with the right application.
fn truncate_preserving_extension(name: &str) -> String {
    if name.chars().count() <= MAX_FILE_NAME_CHARS {
        return name.to_string();
    }
    let extension = name
        .rsplit_once('.')
        .map(|(_, ext)| ext)
        .filter(|ext| !ext.is_empty() && ext.chars().count() <= 16 && !ext.contains(' '))
        .unwrap_or("");
    if extension.is_empty() {
        return name.chars().take(MAX_FILE_NAME_CHARS).collect();
    }
    let keep = MAX_FILE_NAME_CHARS - extension.chars().count() - 1;
    let stem: String = name.chars().take(keep).collect();
    format!("{stem}.{extension}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// The property the P1 fix exists for: whatever the sender sends, the
    /// joined path is a direct child of the directory we chose.
    #[test]
    fn sanitised_names_stay_inside_the_target_directory() {
        let dir = Path::new("/data/shared");
        for raw in [
            "../../../../etc/passwd",
            "..\\..\\Windows\\System32\\evil.exe",
            "/etc/passwd",
            "C:\\Windows\\System32\\evil.dll",
            "\\\\server\\share\\evil.txt",
            "..",
            ".",
            "",
            "   ",
            "photo.png",
        ] {
            let safe = sanitize_attachment_file_name(raw);
            let joined = dir.join(&safe);
            assert_eq!(
                joined.parent(),
                Some(dir),
                "{raw:?} escaped as {safe:?} -> {joined:?}"
            );
            assert!(!safe.is_empty(), "{raw:?} sanitised to an empty name");
        }
    }

    #[test]
    fn shell_metacharacters_survive_as_plain_text() {
        // Not a shell any more (the opener call replaced `cmd /C start`), and
        // these are all legal on Windows — so they stay in the name rather
        // than being mangled.
        let safe = sanitize_attachment_file_name("report&calc.exe^%PATH%.pdf");
        assert_eq!(safe, "report&calc.exe^%PATH%.pdf");
    }

    #[test]
    fn forbidden_windows_characters_are_replaced() {
        assert_eq!(
            sanitize_attachment_file_name("a<b>c\"d|e?f*g.txt"),
            "a_b_c_d_e_f_g.txt"
        );
    }

    #[test]
    fn control_characters_are_replaced() {
        assert_eq!(
            sanitize_attachment_file_name("name\u{0}\u{1}\r\n\ttail.txt"),
            "name_____tail.txt"
        );
    }

    #[test]
    fn windows_reserved_names_are_defused() {
        assert_eq!(sanitize_attachment_file_name("CON"), "_CON");
        assert_eq!(sanitize_attachment_file_name("nul.txt"), "_nul.txt");
        assert_eq!(sanitize_attachment_file_name("Com1.jpg"), "_Com1.jpg");
        assert_eq!(sanitize_attachment_file_name("console.txt"), "console.txt");
    }

    #[test]
    fn trailing_dots_and_spaces_are_dropped() {
        assert_eq!(sanitize_attachment_file_name("evil.exe. . ."), "evil.exe");
        assert_eq!(
            sanitize_attachment_file_name("  spaced.txt  "),
            "spaced.txt"
        );
    }

    #[test]
    fn unicode_names_are_preserved() {
        assert_eq!(
            sanitize_attachment_file_name("Отчёт 2026 — финал.pdf"),
            "Отчёт 2026 — финал.pdf"
        );
        assert_eq!(sanitize_attachment_file_name("写真.jpg"), "写真.jpg");
    }

    #[test]
    fn overlong_names_are_truncated_with_the_extension_kept() {
        let raw = format!("{}.pdf", "a".repeat(400));
        let safe = sanitize_attachment_file_name(&raw);
        assert_eq!(safe.chars().count(), MAX_FILE_NAME_CHARS);
        assert!(safe.ends_with(".pdf"));

        let no_extension = "b".repeat(400);
        let safe = sanitize_attachment_file_name(&no_extension);
        assert_eq!(safe.chars().count(), MAX_FILE_NAME_CHARS);
    }

    #[test]
    fn transfer_ids_that_can_escape_are_rejected() {
        assert!(is_safe_transfer_id("6f1b0a2c-9d3e-4c1f-8a7b-0e5d2c1a9f34"));
        assert!(is_safe_transfer_id("transfer_1"));
        assert!(!is_safe_transfer_id(""));
        assert!(!is_safe_transfer_id(".."));
        assert!(!is_safe_transfer_id("../../etc"));
        assert!(!is_safe_transfer_id("..\\..\\windows"));
        assert!(!is_safe_transfer_id("a/b"));
        assert!(!is_safe_transfer_id("C:evil"));
        assert!(!is_safe_transfer_id("id.with.dots"));
        assert!(!is_safe_transfer_id(&"a".repeat(65)));
    }
}
