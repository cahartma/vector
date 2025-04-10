/*
 * Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0.
 */

use crate::http_request::url_escape::percent_encode_query;
use http::Uri;

/// Utility for updating the query string in a [`Uri`].
pub(super) struct QueryWriter {
    base_uri: Uri,
    new_path_and_query: String,
    prefix: Option<char>,
}

impl QueryWriter {
    /// Creates a new `QueryWriter` based off the given `uri`.
    pub(super) fn new(uri: &Uri) -> Self {
        let new_path_and_query = uri
            .path_and_query()
            .map(|pq| pq.to_string())
            .unwrap_or_default();
        let prefix = if uri.query().is_none() {
            Some('?')
        } else if !uri.query().unwrap_or_default().is_empty() {
            Some('&')
        } else {
            None
        };
        QueryWriter {
            base_uri: uri.clone(),
            new_path_and_query,
            prefix,
        }
    }

    /// Clears all query parameters.
    pub(super) fn clear_params(&mut self) {
        if let Some(index) = self.new_path_and_query.find('?') {
            self.new_path_and_query.truncate(index);
            self.prefix = Some('?');
        }
    }

    /// Inserts a new query parameter. The key and value are percent encoded
    /// by `QueryWriter`. Passing in percent encoded values will result in double encoding.
    pub(super) fn insert(&mut self, k: &str, v: &str) {
        if let Some(prefix) = self.prefix {
            self.new_path_and_query.push(prefix);
        }
        self.prefix = Some('&');
        self.new_path_and_query.push_str(&percent_encode_query(k));
        self.new_path_and_query.push('=');

        self.new_path_and_query.push_str(&percent_encode_query(v));
    }

    /// Returns just the built query string.
    pub(super) fn build_query(self) -> String {
        self.build_uri().query().unwrap_or_default().to_string()
    }

    /// Returns a full [`Uri`] with the query string updated.
    pub(super) fn build_uri(self) -> Uri {
        let mut parts = self.base_uri.into_parts();
        parts.path_and_query = Some(
            self.new_path_and_query
                .parse()
                .expect("adding query should not invalidate URI"),
        );
        Uri::from_parts(parts).expect("a valid URL in should always produce a valid URL out")
    }
}

#[cfg(test)]
mod test {
    use super::QueryWriter;
    use http::Uri;

    #[test]
    fn empty_uri() {
        let uri = Uri::from_static("http://www.example.com");
        let mut query_writer = QueryWriter::new(&uri);
        query_writer.insert("key", "val%ue");
        query_writer.insert("another", "value");
        assert_eq!(
            query_writer.build_uri(),
            Uri::from_static("http://www.example.com?key=val%25ue&another=value")
        );
    }

    #[test]
    fn uri_with_path() {
        let uri = Uri::from_static("http://www.example.com/path");
        let mut query_writer = QueryWriter::new(&uri);
        query_writer.insert("key", "val%ue");
        query_writer.insert("another", "value");
        assert_eq!(
            query_writer.build_uri(),
            Uri::from_static("http://www.example.com/path?key=val%25ue&another=value")
        );
    }

    #[test]
    fn uri_with_path_and_query() {
        let uri = Uri::from_static("http://www.example.com/path?original=here");
        let mut query_writer = QueryWriter::new(&uri);
        query_writer.insert("key", "val%ue");
        query_writer.insert("another", "value");
        assert_eq!(
            query_writer.build_uri(),
            Uri::from_static(
                "http://www.example.com/path?original=here&key=val%25ue&another=value"
            )
        );
    }

    #[test]
    fn build_query() {
        let uri = Uri::from_static("http://www.example.com");
        let mut query_writer = QueryWriter::new(&uri);
        query_writer.insert("key", "val%ue");
        query_writer.insert("ano%ther", "value");
        assert_eq!("key=val%25ue&ano%25ther=value", query_writer.build_query());
    }

    #[test]
    // This test ensures that the percent encoding applied to queries always produces a valid URI if
    // the starting URI is valid
    fn doesnt_panic_when_adding_query_to_valid_uri() {
        let uri = Uri::from_static("http://www.example.com");

        let mut problematic_chars = Vec::new();

        for byte in u8::MIN..=u8::MAX {
            match std::str::from_utf8(&[byte]) {
                // If we can't make a str from the byte then we certainly can't make a URL from it
                Err(_) => {
                    continue;
                }
                Ok(value) => {
                    let mut query_writer = QueryWriter::new(&uri);
                    query_writer.insert("key", value);

                    if let Err(_) = std::panic::catch_unwind(|| query_writer.build_uri()) {
                        problematic_chars.push(char::from(byte));
                    };
                }
            }
        }

        if !problematic_chars.is_empty() {
            panic!("we got some bad bytes here: {:#?}", problematic_chars)
        }
    }

    #[test]
    fn clear_params() {
        let uri = Uri::from_static("http://www.example.com/path?original=here&foo=1");
        let mut query_writer = QueryWriter::new(&uri);
        query_writer.clear_params();
        query_writer.insert("new", "value");
        assert_eq!("new=value", query_writer.build_query());
    }
}
