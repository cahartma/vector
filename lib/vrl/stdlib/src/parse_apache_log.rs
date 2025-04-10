use std::collections::BTreeMap;

use vrl::prelude::*;

use crate::log_util;

fn parse_apache_log(
    bytes: Value,
    timestamp_format: Option<Value>,
    format: &Bytes,
    ctx: &Context,
) -> Resolved {
    let message = bytes.try_bytes_utf8_lossy()?;
    let timestamp_format = match timestamp_format {
        None => "%d/%b/%Y:%T %z".to_owned(),
        Some(timestamp_format) => timestamp_format.try_bytes_utf8_lossy()?.to_string(),
    };
    let regex = match format.as_ref() {
        b"common" => &*log_util::REGEX_APACHE_COMMON_LOG,
        b"combined" => &*log_util::REGEX_APACHE_COMBINED_LOG,
        b"error" => &*log_util::REGEX_APACHE_ERROR_LOG,
        _ => unreachable!(),
    };
    let captures = regex
        .captures(&message)
        .ok_or("failed parsing common log line")?;
    log_util::log_fields(regex, &captures, &timestamp_format, ctx.timezone()).map_err(Into::into)
}

fn variants() -> Vec<Value> {
    vec![value!("common"), value!("combined"), value!("error")]
}

#[derive(Clone, Copy, Debug)]
pub struct ParseApacheLog;

impl Function for ParseApacheLog {
    fn identifier(&self) -> &'static str {
        "parse_apache_log"
    }

    fn parameters(&self) -> &'static [Parameter] {
        &[
            Parameter {
                keyword: "value",
                kind: kind::BYTES,
                required: true,
            },
            Parameter {
                keyword: "format",
                kind: kind::BYTES,
                required: true,
            },
            Parameter {
                keyword: "timestamp_format",
                kind: kind::BYTES,
                required: false,
            },
        ]
    }

    fn compile(
        &self,
        _state: (&mut state::LocalEnv, &mut state::ExternalEnv),
        _ctx: &mut FunctionCompileContext,
        mut arguments: ArgumentList,
    ) -> Compiled {
        let value = arguments.required("value");
        let format = arguments
            .required_enum("format", &variants())?
            .try_bytes()
            .expect("format not bytes");

        let timestamp_format = arguments.optional("timestamp_format");

        Ok(Box::new(ParseApacheLogFn {
            value,
            format,
            timestamp_format,
        }))
    }

    fn compile_argument(
        &self,
        _args: &[(&'static str, Option<FunctionArgument>)],
        _ctx: &mut FunctionCompileContext,
        name: &str,
        expr: Option<&expression::Expr>,
    ) -> CompiledArgument {
        match (name, expr) {
            ("format", Some(expr)) => {
                let format = expr
                    .as_enum("format", variants())?
                    .try_bytes()
                    .expect("format not bytes");
                Ok(Some(Box::new(format) as _))
            }
            _ => Ok(None),
        }
    }

    fn examples(&self) -> &'static [Example] {
        &[
            Example {
                title: "parse apache common log",
                source: r#"encode_json(parse_apache_log!(s'127.0.0.1 bob frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326', "common"))"#,
                result: Ok(
                    r#"s'{"host":"127.0.0.1","identity":"bob","message":"GET /apache_pb.gif HTTP/1.0","method":"GET","path":"/apache_pb.gif","protocol":"HTTP/1.0","size":2326,"status":200,"timestamp":"2000-10-10T20:55:36Z","user":"frank"}'"#,
                ),
            },
            Example {
                title: "parse apache combined log",
                source: r#"encode_json(parse_apache_log!(s'127.0.0.1 bob frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.seniorinfomediaries.com/vertical/channels/front-end/bandwidth" "Mozilla/5.0 (X11; Linux i686; rv:5.0) Gecko/1945-10-12 Firefox/37.0"', "combined"))"#,
                result: Ok(
                    r#"s'{"agent":"Mozilla/5.0 (X11; Linux i686; rv:5.0) Gecko/1945-10-12 Firefox/37.0","host":"127.0.0.1","identity":"bob","message":"GET /apache_pb.gif HTTP/1.0","method":"GET","path":"/apache_pb.gif","protocol":"HTTP/1.0","referrer":"http://www.seniorinfomediaries.com/vertical/channels/front-end/bandwidth","size":2326,"status":200,"timestamp":"2000-10-10T20:55:36Z","user":"frank"}'"#,
                ),
            },
            Example {
                title: "parse apache error log",
                source: r#"encode_json(parse_apache_log!(s'[01/Mar/2021:12:00:19 +0000] [ab:alert] [pid 4803:tid 3814] [client 147.159.108.175:24259] I will bypass the haptic COM bandwidth, that should matrix the CSS driver!', "error"))"#,
                result: Ok(
                    r#"s'{"client":"147.159.108.175","message":"I will bypass the haptic COM bandwidth, that should matrix the CSS driver!","module":"ab","pid":4803,"port":24259,"severity":"alert","thread":"3814","timestamp":"2021-03-01T12:00:19Z"}'"#,
                ),
            },
        ]
    }

    fn call_by_vm(&self, ctx: &mut Context, args: &mut VmArgumentList) -> Resolved {
        let value = args.required("value");
        let format = args.required_any("format").downcast_ref::<Bytes>().unwrap();
        let timestamp_format = args.optional("timestamp_format");

        parse_apache_log(value, timestamp_format, format, ctx)
    }
}

#[derive(Debug, Clone)]
struct ParseApacheLogFn {
    value: Box<dyn Expression>,
    format: Bytes,
    timestamp_format: Option<Box<dyn Expression>>,
}

impl Expression for ParseApacheLogFn {
    fn resolve(&self, ctx: &mut Context) -> Resolved {
        let bytes = self.value.resolve(ctx)?;
        let timestamp_format = self
            .timestamp_format
            .as_ref()
            .map(|expr| expr.resolve(ctx))
            .transpose()?;

        parse_apache_log(bytes, timestamp_format, &self.format, ctx)
    }

    fn type_def(&self, _: (&state::LocalEnv, &state::ExternalEnv)) -> TypeDef {
        TypeDef::object(match self.format.as_ref() {
            b"common" => kind_common(),
            b"combined" => kind_combined(),
            b"error" => kind_error(),
            _ => unreachable!(),
        })
        .fallible()
    }
}

fn kind_common() -> BTreeMap<Field, Kind> {
    map! {
         "host": Kind::bytes() | Kind::null(),
         "identity": Kind::bytes() | Kind::null(),
         "user": Kind::bytes() | Kind::null(),
         "timestamp": Kind::timestamp() | Kind::null(),
         "message": Kind::bytes() | Kind::null(),
         "method": Kind::bytes() | Kind::null(),
         "path": Kind::bytes() | Kind::null(),
         "protocol": Kind::bytes() | Kind::null(),
         "status": Kind::integer() | Kind::null(),
         "size": Kind::integer() | Kind::null(),
    }
    .into_iter()
    .map(|(key, kind): (&str, _)| (key.into(), kind))
    .collect()
}

fn kind_combined() -> BTreeMap<Field, Kind> {
    map! {
        "host": Kind::bytes() | Kind::null(),
        "identity": Kind::bytes() | Kind::null(),
        "user": Kind::bytes() | Kind::null(),
        "timestamp": Kind::timestamp() | Kind::null(),
        "message": Kind::bytes() | Kind::null(),
        "method": Kind::bytes() | Kind::null(),
        "path": Kind::bytes() | Kind::null(),
        "protocol": Kind::bytes() | Kind::null(),
        "status": Kind::integer() | Kind::null(),
        "size": Kind::integer() | Kind::null(),
        "referrer": Kind::bytes() | Kind::null(),
        "agent": Kind::bytes() | Kind::null(),
    }
    .into_iter()
    .map(|(key, kind): (&str, _)| (key.into(), kind))
    .collect()
}

fn kind_error() -> BTreeMap<Field, Kind> {
    map! {
         "timestamp": Kind::timestamp() | Kind::null(),
         "module": Kind::bytes() | Kind::null(),
         "severity": Kind::bytes() | Kind::null(),
         "thread": Kind::bytes() | Kind::null(),
         "port": Kind::bytes() | Kind::null(),
         "message": Kind::bytes() | Kind::null(),
    }
    .into_iter()
    .map(|(key, kind): (&str, _)| (key.into(), kind))
    .collect()
}

#[cfg(test)]
mod tests {
    use chrono::prelude::*;
    use vector_common::btreemap;

    use super::*;

    test_function![
        parse_common_log => ParseApacheLog;

        common_line_valid {
            args: func_args![value: r#"127.0.0.1 bob frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326"#,
                             format: "common"
            ],
            want: Ok(btreemap! {
                "host" => "127.0.0.1",
                "identity" => "bob",
                "user" => "frank",
                "timestamp" => Value::Timestamp(DateTime::parse_from_rfc3339("2000-10-10T20:55:36Z").unwrap().into()),
                "message" => "GET /apache_pb.gif HTTP/1.0",
                "method" => "GET",
                "path" => "/apache_pb.gif",
                "protocol" => "HTTP/1.0",
                "status" => 200,
                "size" => 2326,
            }),
            tdef: TypeDef::object(kind_common()).fallible(),
            tz: vector_common::TimeZone::default(),
        }

        combined_line_valid {
            args: func_args![value: r#"224.92.49.50 bob frank [25/Feb/2021:12:44:08 +0000] "PATCH /one-to-one HTTP/1.1" 401 84170 "http://www.seniorinfomediaries.com/vertical/channels/front-end/bandwidth" "Mozilla/5.0 (X11; Linux i686; rv:5.0) Gecko/1945-10-12 Firefox/37.0""#,
                             format: "combined"
                             ],
            want: Ok(btreemap! {
                "host" => "224.92.49.50",
                "identity" => "bob",
                "user" => "frank",
                "timestamp" => Value::Timestamp(DateTime::parse_from_rfc3339("2021-02-25T12:44:08Z").unwrap().into()),
                "message" => "PATCH /one-to-one HTTP/1.1",
                "method" => "PATCH",
                "path" => "/one-to-one",
                "protocol" => "HTTP/1.1",
                "status" => 401,
                "size" => 84170,
                "referrer" => "http://www.seniorinfomediaries.com/vertical/channels/front-end/bandwidth",
                "agent" => "Mozilla/5.0 (X11; Linux i686; rv:5.0) Gecko/1945-10-12 Firefox/37.0",
            }),
            tdef: TypeDef::object(kind_combined()).fallible(),
            tz: vector_common::TimeZone::default(),
        }

        combined_line_missing_fields_valid {
            args: func_args![value: r#"224.92.49.50 bob frank [25/Feb/2021:12:44:08 +0000] "PATCH /one-to-one HTTP/1.1" 401 84170 - -"#,
                             format: "combined"
                             ],
            want: Ok(btreemap! {
                "host" => "224.92.49.50",
                "identity" => "bob",
                "user" => "frank",
                "timestamp" => Value::Timestamp(DateTime::parse_from_rfc3339("2021-02-25T12:44:08Z").unwrap().into()),
                "message" => "PATCH /one-to-one HTTP/1.1",
                "method" => "PATCH",
                "path" => "/one-to-one",
                "protocol" => "HTTP/1.1",
                "status" => 401,
                "size" => 84170,
            }),
            tdef: TypeDef::object(kind_combined()).fallible(),
            tz: vector_common::TimeZone::default(),
        }

        error_line_valid {
            args: func_args![value: r#"[01/Mar/2021:12:00:19 +0000] [ab:alert] [pid 4803:tid 3814] [client 147.159.108.175:24259] I'll bypass the haptic COM bandwidth, that should matrix the CSS driver!"#,
                             format: "error"
                             ],
            want: Ok(btreemap! {
                "timestamp" => Value::Timestamp(DateTime::parse_from_rfc3339("2021-03-01T12:00:19Z").unwrap().into()),
                "message" => "I'll bypass the haptic COM bandwidth, that should matrix the CSS driver!",
                "module" => "ab",
                "severity" => "alert",
                "pid" => 4803,
                "thread" => "3814",
                "client" => "147.159.108.175",
                "port" => 24259
            }),
            tdef: TypeDef::object(kind_error()).fallible(),
            tz: vector_common::TimeZone::default(),
        }

        error_line_ip_v6 {
            args: func_args![value: r#"[01/Mar/2021:12:00:19 +0000] [ab:alert] [pid 4803:tid 3814] [client eda7:35d:3ceb:ef1e:2133:e7bf:116e:24cc:24259] I'll bypass the haptic COM bandwidth, that should matrix the CSS driver!"#,
                             format: "error"
                             ],
            want: Ok(btreemap! {
                "timestamp" => Value::Timestamp(DateTime::parse_from_rfc3339("2021-03-01T12:00:19Z").unwrap().into()),
                "message" => "I'll bypass the haptic COM bandwidth, that should matrix the CSS driver!",
                "module" => "ab",
                "severity" => "alert",
                "pid" => 4803,
                "thread" => "3814",
                "client" => "eda7:35d:3ceb:ef1e:2133:e7bf:116e:24cc",
                "port" => 24259
            }),
            tdef: TypeDef::object(kind_error()).fallible(),
            tz: vector_common::TimeZone::default(),
        }

        error_line_thread_id {
            args: func_args![
                value: r#"[2021-06-04 15:40:27.138633] [php7:emerg] [pid 4803] [client 95.223.77.60:35106] PHP Parse error:  syntax error, unexpected \'->\' (T_OBJECT_OPERATOR) in /var/www/prod/releases/master-c7225365fd9faa26262cffeeb57b31bd7448c94a/source/index.php on line 14"#,
                timestamp_format: "%Y-%m-%d %H:%M:%S.%f",
                format: "error",
            ],
            want: Ok(btreemap! {
                "timestamp" => Value::Timestamp(DateTime::parse_from_rfc3339("2021-06-04T15:40:27.000138633Z").unwrap().into()),
                "message" => "PHP Parse error:  syntax error, unexpected \\\'->\\\' (T_OBJECT_OPERATOR) in /var/www/prod/releases/master-c7225365fd9faa26262cffeeb57b31bd7448c94a/source/index.php on line 14",
                "module" => "php7",
                "severity" => "emerg",
                "pid" => 4803,
                "client" => "95.223.77.60",
                "port" => 35106

            }),
            tdef: TypeDef::object(kind_error()).fallible(),
            tz: vector_common::TimeZone::Named(chrono_tz::Tz::UTC),
        }

        log_line_valid_empty {
            args: func_args![value: "- - - - - - -",
                             format: "common",
            ],
            want: Ok(btreemap! {}),
            tdef: TypeDef::object(kind_common()).fallible(),
            tz: vector_common::TimeZone::default(),
        }

        log_line_valid_empty_variant {
            args: func_args![value: r#"- - - [-] "-" - -"#,
                             format: "common",
            ],
            want: Ok(btreemap! {}),
            tdef: TypeDef::object(kind_common()).fallible(),
            tz: vector_common::TimeZone::default(),
        }

        log_line_valid_with_local_timestamp_format {
            args: func_args![value: format!("[{}] - - - -",
                                            Utc.ymd(2000, 10, 10).and_hms(20,55,36)
                                              .with_timezone(&Local)
                                              .format("%a %b %d %H:%M:%S %Y")
                                            ),
                             timestamp_format: "%a %b %d %H:%M:%S %Y",
                             format: "error",
            ],
            want: Ok(btreemap! {
                "timestamp" => Value::Timestamp(DateTime::parse_from_rfc3339("2000-10-10T20:55:36Z").unwrap().into()),
            }),
            tdef: TypeDef::object(kind_error()).fallible(),
            tz: vector_common::TimeZone::default(),
        }

        log_line_valid_with_timezone {
            args: func_args![
                value: "[2021/06/03 09:30:50] - - - -",
                timestamp_format: "%Y/%m/%d %H:%M:%S",
                format: "error",
            ],
            want: Ok(btreemap! {
                "timestamp" => Value::Timestamp(DateTime::parse_from_rfc3339("2021-06-03T07:30:50Z").unwrap().into()),
            }),
            tdef: TypeDef::object(kind_error()).fallible(),
            tz: vector_common::TimeZone::Named(chrono_tz::Europe::Paris),
        }

        log_line_invalid {
            args: func_args![value: r#"not a common log line"#,
                             format: "common",
            ],
            want: Err("failed parsing common log line"),
            tdef: TypeDef::object(kind_common()).fallible(),
            tz: vector_common::TimeZone::default(),
        }

        log_line_invalid_timestamp {
            args: func_args![value: r#"- - - [1234] - - - - - "#,
                             format: "combined",
            ],
            want: Err("failed parsing timestamp 1234 using format %d/%b/%Y:%T %z: input contains invalid characters"),
            tdef: TypeDef::object(kind_combined()).fallible(),
            tz: vector_common::TimeZone::default(),
        }
    ];
}
