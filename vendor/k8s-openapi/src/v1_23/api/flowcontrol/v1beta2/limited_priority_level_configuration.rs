// Generated from definition io.k8s.api.flowcontrol.v1beta2.LimitedPriorityLevelConfiguration

/// LimitedPriorityLevelConfiguration specifies how to handle requests that are subject to limits. It addresses two issues:
///  * How are requests for this priority level limited?
///  * What should be done with requests that exceed the limit?
#[derive(Clone, Debug, Default, PartialEq)]
pub struct LimitedPriorityLevelConfiguration {
    /// `assuredConcurrencyShares` (ACS) configures the execution limit, which is a limit on the number of requests of this priority level that may be exeucting at a given time.  ACS must be a positive number. The server's concurrency limit (SCL) is divided among the concurrency-controlled priority levels in proportion to their assured concurrency shares. This produces the assured concurrency value (ACV) --- the number of requests that may be executing at a time --- for each such priority level:
    ///
    ///   ACV(l) = ceil( SCL * ACS(l) / ( sum\[priority levels k\] ACS(k) ) )
    ///
    /// bigger numbers of ACS mean more reserved concurrent requests (at the expense of every other PL). This field has a default value of 30.
    pub assured_concurrency_shares: Option<i32>,

    /// `limitResponse` indicates what to do with requests that can not be executed right now
    pub limit_response: Option<crate::api::flowcontrol::v1beta2::LimitResponse>,
}

impl<'de> crate::serde::Deserialize<'de> for LimitedPriorityLevelConfiguration {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: crate::serde::Deserializer<'de> {
        #[allow(non_camel_case_types)]
        enum Field {
            Key_assured_concurrency_shares,
            Key_limit_response,
            Other,
        }

        impl<'de> crate::serde::Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: crate::serde::Deserializer<'de> {
                struct Visitor;

                impl<'de> crate::serde::de::Visitor<'de> for Visitor {
                    type Value = Field;

                    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                        f.write_str("field identifier")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E> where E: crate::serde::de::Error {
                        Ok(match v {
                            "assuredConcurrencyShares" => Field::Key_assured_concurrency_shares,
                            "limitResponse" => Field::Key_limit_response,
                            _ => Field::Other,
                        })
                    }
                }

                deserializer.deserialize_identifier(Visitor)
            }
        }

        struct Visitor;

        impl<'de> crate::serde::de::Visitor<'de> for Visitor {
            type Value = LimitedPriorityLevelConfiguration;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("LimitedPriorityLevelConfiguration")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error> where A: crate::serde::de::MapAccess<'de> {
                let mut value_assured_concurrency_shares: Option<i32> = None;
                let mut value_limit_response: Option<crate::api::flowcontrol::v1beta2::LimitResponse> = None;

                while let Some(key) = crate::serde::de::MapAccess::next_key::<Field>(&mut map)? {
                    match key {
                        Field::Key_assured_concurrency_shares => value_assured_concurrency_shares = crate::serde::de::MapAccess::next_value(&mut map)?,
                        Field::Key_limit_response => value_limit_response = crate::serde::de::MapAccess::next_value(&mut map)?,
                        Field::Other => { let _: crate::serde::de::IgnoredAny = crate::serde::de::MapAccess::next_value(&mut map)?; },
                    }
                }

                Ok(LimitedPriorityLevelConfiguration {
                    assured_concurrency_shares: value_assured_concurrency_shares,
                    limit_response: value_limit_response,
                })
            }
        }

        deserializer.deserialize_struct(
            "LimitedPriorityLevelConfiguration",
            &[
                "assuredConcurrencyShares",
                "limitResponse",
            ],
            Visitor,
        )
    }
}

impl crate::serde::Serialize for LimitedPriorityLevelConfiguration {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: crate::serde::Serializer {
        let mut state = serializer.serialize_struct(
            "LimitedPriorityLevelConfiguration",
            self.assured_concurrency_shares.as_ref().map_or(0, |_| 1) +
            self.limit_response.as_ref().map_or(0, |_| 1),
        )?;
        if let Some(value) = &self.assured_concurrency_shares {
            crate::serde::ser::SerializeStruct::serialize_field(&mut state, "assuredConcurrencyShares", value)?;
        }
        if let Some(value) = &self.limit_response {
            crate::serde::ser::SerializeStruct::serialize_field(&mut state, "limitResponse", value)?;
        }
        crate::serde::ser::SerializeStruct::end(state)
    }
}

#[cfg(feature = "schemars")]
impl crate::schemars::JsonSchema for LimitedPriorityLevelConfiguration {
    fn schema_name() -> String {
        "io.k8s.api.flowcontrol.v1beta2.LimitedPriorityLevelConfiguration".to_owned()
    }

    fn json_schema(__gen: &mut crate::schemars::gen::SchemaGenerator) -> crate::schemars::schema::Schema {
        crate::schemars::schema::Schema::Object(crate::schemars::schema::SchemaObject {
            metadata: Some(Box::new(crate::schemars::schema::Metadata {
                description: Some("LimitedPriorityLevelConfiguration specifies how to handle requests that are subject to limits. It addresses two issues:\n * How are requests for this priority level limited?\n * What should be done with requests that exceed the limit?".to_owned()),
                ..Default::default()
            })),
            instance_type: Some(crate::schemars::schema::SingleOrVec::Single(Box::new(crate::schemars::schema::InstanceType::Object))),
            object: Some(Box::new(crate::schemars::schema::ObjectValidation {
                properties: IntoIterator::into_iter([
                    (
                        "assuredConcurrencyShares".to_owned(),
                        crate::schemars::schema::Schema::Object(crate::schemars::schema::SchemaObject {
                            metadata: Some(Box::new(crate::schemars::schema::Metadata {
                                description: Some("`assuredConcurrencyShares` (ACS) configures the execution limit, which is a limit on the number of requests of this priority level that may be exeucting at a given time.  ACS must be a positive number. The server's concurrency limit (SCL) is divided among the concurrency-controlled priority levels in proportion to their assured concurrency shares. This produces the assured concurrency value (ACV) --- the number of requests that may be executing at a time --- for each such priority level:\n\n            ACV(l) = ceil( SCL * ACS(l) / ( sum[priority levels k] ACS(k) ) )\n\nbigger numbers of ACS mean more reserved concurrent requests (at the expense of every other PL). This field has a default value of 30.".to_owned()),
                                ..Default::default()
                            })),
                            instance_type: Some(crate::schemars::schema::SingleOrVec::Single(Box::new(crate::schemars::schema::InstanceType::Integer))),
                            format: Some("int32".to_owned()),
                            ..Default::default()
                        }),
                    ),
                    (
                        "limitResponse".to_owned(),
                        {
                            let mut schema_obj = __gen.subschema_for::<crate::api::flowcontrol::v1beta2::LimitResponse>().into_object();
                            schema_obj.metadata = Some(Box::new(crate::schemars::schema::Metadata {
                                description: Some("`limitResponse` indicates what to do with requests that can not be executed right now".to_owned()),
                                ..Default::default()
                            }));
                            crate::schemars::schema::Schema::Object(schema_obj)
                        },
                    ),
                ]).collect(),
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}
