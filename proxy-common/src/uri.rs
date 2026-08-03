use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use std::path::Path;

const PATH_ENCODE_SET: AsciiSet = NON_ALPHANUMERIC
    .remove(b'/')
    .remove(b':')
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~')
    .remove(b'@');

/// Convert a filesystem path to an RFC 3986 percent-encoded `file://` URI.
pub fn path_to_file_uri(path: &Path) -> String {
    file_uri_from_path_string(&path.to_string_lossy(), cfg!(windows))
}

fn file_uri_from_path_string(path: &str, windows: bool) -> String {
    let mut normalized = if windows {
        path.replace('\\', "/")
    } else {
        path.to_string()
    };
    if windows {
        if let Some(unc) = normalized.strip_prefix("//?/UNC/") {
            normalized = format!("//{unc}");
        } else if let Some(verbatim) = normalized.strip_prefix("//?/") {
            normalized = verbatim.to_string();
        }
        if let Some(unc) = normalized.strip_prefix("//") {
            return format!("file://{}", utf8_percent_encode(unc, &PATH_ENCODE_SET));
        }
    }
    let prefix = if normalized.starts_with('/') {
        "file://"
    } else {
        "file:///"
    };
    format!(
        "{prefix}{}",
        utf8_percent_encode(&normalized, &PATH_ENCODE_SET)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_reserved_characters_in_unix_paths() {
        assert_eq!(
            file_uri_from_path_string("/tmp/Java Sources/#1%?.java", false),
            "file:///tmp/Java%20Sources/%231%25%3F.java"
        );
    }

    #[test]
    fn normalizes_and_encodes_windows_paths() {
        assert_eq!(
            file_uri_from_path_string(r"C:\Users\Jane Doe\A#1.java", true),
            "file:///C:/Users/Jane%20Doe/A%231.java"
        );
    }

    #[test]
    fn preserves_windows_unc_authority() {
        assert_eq!(
            file_uri_from_path_string(r"\\server\share\A File.java", true),
            "file://server/share/A%20File.java"
        );
    }

    #[test]
    fn normalizes_windows_verbatim_paths() {
        assert_eq!(
            file_uri_from_path_string(r"\\?\C:\Users\Jane Doe\A.java", true),
            "file:///C:/Users/Jane%20Doe/A.java"
        );
        assert_eq!(
            file_uri_from_path_string(r"\\?\UNC\server\share\A.java", true),
            "file://server/share/A.java"
        );
    }
}
