// Generated from definition io.k8s.api.policy.v1beta1.PodDisruptionBudgetStatus

/// PodDisruptionBudgetStatus represents information about the status of a PodDisruptionBudget. Status may trail the actual state of a system.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PodDisruptionBudgetStatus {
    /// current number of healthy pods
    pub current_healthy: i32,

    /// minimum desired number of healthy pods
    pub desired_healthy: i32,

    /// DisruptedPods contains information about pods whose eviction was processed by the API server eviction subresource handler but has not yet been observed by the PodDisruptionBudget controller. A pod will be in this map from the time when the API server processed the eviction request to the time when the pod is seen by PDB controller as having been marked for deletion (or after a timeout). The key in the map is the name of the pod and the value is the time when the API server processed the eviction request. If the deletion didn't occur and a pod is still there it will be removed from the list automatically by PodDisruptionBudget controller after some time. If everything goes smooth this map should be empty for the most of the time. Large number of entries in the map may indicate problems with pod deletions.
    pub disrupted_pods: Option<std::collections::BTreeMap<String, crate::apimachinery::pkg::apis::meta::v1::Time>>,

    /// Number of pod disruptions that are currently allowed.
    pub disruptions_allowed: i32,

    /// total number of pods counted by this disruption budget
    pub expected_pods: i32,

    /// Most recent generation observed when updating this PDB status. DisruptionsAllowed and other status information is valid only if observedGeneration equals to PDB's object generation.
    pub observed_generation: Option<i64>,
}

impl<'de> crate::serde::Deserialize<'de> for PodDisruptionBudgetStatus {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error> where D: crate::serde::Deserializer<'de> {
        #[allow(non_camel_case_types)]
        enum Field {
            Key_current_healthy,
            Key_desired_healthy,
            Key_disrupted_pods,
            Key_disruptions_allowed,
            Key_expected_pods,
            Key_observed_generation,
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
                            "currentHealthy" => Field::Key_current_healthy,
                            "desiredHealthy" => Field::Key_desired_healthy,
                            "disruptedPods" => Field::Key_disrupted_pods,
                            "disruptionsAllowed" => Field::Key_disruptions_allowed,
                            "expectedPods" => Field::Key_expected_pods,
                            "observedGeneration" => Field::Key_observed_generation,
                            _ => Field::Other,
                        })
                    }
                }

                deserializer.deserialize_identifier(Visitor)
            }
        }

        struct Visitor;

        impl<'de> crate::serde::de::Visitor<'de> for Visitor {
            type Value = PodDisruptionBudgetStatus;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("PodDisruptionBudgetStatus")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error> where A: crate::serde::de::MapAccess<'de> {
                let mut value_current_healthy: Option<i32> = None;
                let mut value_desired_healthy: Option<i32> = None;
                let mut value_disrupted_pods: Option<std::collections::BTreeMap<String, crate::apimachinery::pkg::apis::meta::v1::Time>> = None;
                let mut value_disruptions_allowed: Option<i32> = None;
                let mut value_expected_pods: Option<i32> = None;
                let mut value_observed_generation: Option<i64> = None;

                while let Some(key) = crate::serde::de::MapAccess::next_key::<Field>(&mut map)? {
                    match key {
                        Field::Key_current_healthy => value_current_healthy = crate::serde::de::MapAccess::next_value(&mut map)?,
                        Field::Key_desired_healthy => value_desired_healthy = crate::serde::de::MapAccess::next_value(&mut map)?,
                        Field::Key_disrupted_pods => value_disrupted_pods = crate::serde::de::MapAccess::next_value(&mut map)?,
                        Field::Key_disruptions_allowed => value_disruptions_allowed = crate::serde::de::MapAccess::next_value(&mut map)?,
                        Field::Key_expected_pods => value_expected_pods = crate::serde::de::MapAccess::next_value(&mut map)?,
                        Field::Key_observed_generation => value_observed_generation = crate::serde::de::MapAccess::next_value(&mut map)?,
                        Field::Other => { let _: crate::serde::de::IgnoredAny = crate::serde::de::MapAccess::next_value(&mut map)?; },
                    }
                }

                Ok(PodDisruptionBudgetStatus {
                    current_healthy: value_current_healthy.unwrap_or_default(),
                    desired_healthy: value_desired_healthy.unwrap_or_default(),
                    disrupted_pods: value_disrupted_pods,
                    disruptions_allowed: value_disruptions_allowed.unwrap_or_default(),
                    expected_pods: value_expected_pods.unwrap_or_default(),
                    observed_generation: value_observed_generation,
                })
            }
        }

        deserializer.deserialize_struct(
            "PodDisruptionBudgetStatus",
            &[
                "currentHealthy",
                "desiredHealthy",
                "disruptedPods",
                "disruptionsAllowed",
                "expectedPods",
                "observedGeneration",
            ],
            Visitor,
        )
    }
}

impl crate::serde::Serialize for PodDisruptionBudgetStatus {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: crate::serde::Serializer {
        let mut state = serializer.serialize_struct(
            "PodDisruptionBudgetStatus",
            4 +
            self.disrupted_pods.as_ref().map_or(0, |_| 1) +
            self.observed_generation.as_ref().map_or(0, |_| 1),
        )?;
        crate::serde::ser::SerializeStruct::serialize_field(&mut state, "currentHealthy", &self.current_healthy)?;
        crate::serde::ser::SerializeStruct::serialize_field(&mut state, "desiredHealthy", &self.desired_healthy)?;
        if let Some(value) = &self.disrupted_pods {
            crate::serde::ser::SerializeStruct::serialize_field(&mut state, "disruptedPods", value)?;
        }
        crate::serde::ser::SerializeStruct::serialize_field(&mut state, "disruptionsAllowed", &self.disruptions_allowed)?;
        crate::serde::ser::SerializeStruct::serialize_field(&mut state, "expectedPods", &self.expected_pods)?;
        if let Some(value) = &self.observed_generation {
            crate::serde::ser::SerializeStruct::serialize_field(&mut state, "observedGeneration", value)?;
        }
        crate::serde::ser::SerializeStruct::end(state)
    }
}

#[cfg(feature = "schemars")]
impl crate::schemars::JsonSchema for PodDisruptionBudgetStatus {
    fn schema_name() -> String {
        "io.k8s.api.policy.v1beta1.PodDisruptionBudgetStatus".to_owned()
    }

    fn json_schema(__gen: &mut crate::schemars::gen::SchemaGenerator) -> crate::schemars::schema::Schema {
        crate::schemars::schema::Schema::Object(crate::schemars::schema::SchemaObject {
            metadata: Some(Box::new(crate::schemars::schema::Metadata {
                description: Some("PodDisruptionBudgetStatus represents information about the status of a PodDisruptionBudget. Status may trail the actual state of a system.".to_owned()),
                ..Default::default()
            })),
            instance_type: Some(crate::schemars::schema::SingleOrVec::Single(Box::new(crate::schemars::schema::InstanceType::Object))),
            object: Some(Box::new(crate::schemars::schema::ObjectValidation {
                properties: IntoIterator::into_iter([
                    (
                        "currentHealthy".to_owned(),
                        crate::schemars::schema::Schema::Object(crate::schemars::schema::SchemaObject {
                            metadata: Some(Box::new(crate::schemars::schema::Metadata {
                                description: Some("current number of healthy pods".to_owned()),
                                ..Default::default()
                            })),
                            instance_type: Some(crate::schemars::schema::SingleOrVec::Single(Box::new(crate::schemars::schema::InstanceType::Integer))),
                            format: Some("int32".to_owned()),
                            ..Default::default()
                        }),
                    ),
                    (
                        "desiredHealthy".to_owned(),
                        crate::schemars::schema::Schema::Object(crate::schemars::schema::SchemaObject {
                            metadata: Some(Box::new(crate::schemars::schema::Metadata {
                                description: Some("minimum desired number of healthy pods".to_owned()),
                                ..Default::default()
                            })),
                            instance_type: Some(crate::schemars::schema::SingleOrVec::Single(Box::new(crate::schemars::schema::InstanceType::Integer))),
                            format: Some("int32".to_owned()),
                            ..Default::default()
                        }),
                    ),
                    (
                        "disruptedPods".to_owned(),
                        crate::schemars::schema::Schema::Object(crate::schemars::schema::SchemaObject {
                            metadata: Some(Box::new(crate::schemars::schema::Metadata {
                                description: Some("DisruptedPods contains information about pods whose eviction was processed by the API server eviction subresource handler but has not yet been observed by the PodDisruptionBudget controller. A pod will be in this map from the time when the API server processed the eviction request to the time when the pod is seen by PDB controller as having been marked for deletion (or after a timeout). The key in the map is the name of the pod and the value is the time when the API server processed the eviction request. If the deletion didn't occur and a pod is still there it will be removed from the list automatically by PodDisruptionBudget controller after some time. If everything goes smooth this map should be empty for the most of the time. Large number of entries in the map may indicate problems with pod deletions.".to_owned()),
                                ..Default::default()
                            })),
                            instance_type: Some(crate::schemars::schema::SingleOrVec::Single(Box::new(crate::schemars::schema::InstanceType::Object))),
                            object: Some(Box::new(crate::schemars::schema::ObjectValidation {
                                additional_properties: Some(Box::new(__gen.subschema_for::<crate::apimachinery::pkg::apis::meta::v1::Time>())),
                                ..Default::default()
                            })),
                            ..Default::default()
                        }),
                    ),
                    (
                        "disruptionsAllowed".to_owned(),
                        crate::schemars::schema::Schema::Object(crate::schemars::schema::SchemaObject {
                            metadata: Some(Box::new(crate::schemars::schema::Metadata {
                                description: Some("Number of pod disruptions that are currently allowed.".to_owned()),
                                ..Default::default()
                            })),
                            instance_type: Some(crate::schemars::schema::SingleOrVec::Single(Box::new(crate::schemars::schema::InstanceType::Integer))),
                            format: Some("int32".to_owned()),
                            ..Default::default()
                        }),
                    ),
                    (
                        "expectedPods".to_owned(),
                        crate::schemars::schema::Schema::Object(crate::schemars::schema::SchemaObject {
                            metadata: Some(Box::new(crate::schemars::schema::Metadata {
                                description: Some("total number of pods counted by this disruption budget".to_owned()),
                                ..Default::default()
                            })),
                            instance_type: Some(crate::schemars::schema::SingleOrVec::Single(Box::new(crate::schemars::schema::InstanceType::Integer))),
                            format: Some("int32".to_owned()),
                            ..Default::default()
                        }),
                    ),
                    (
                        "observedGeneration".to_owned(),
                        crate::schemars::schema::Schema::Object(crate::schemars::schema::SchemaObject {
                            metadata: Some(Box::new(crate::schemars::schema::Metadata {
                                description: Some("Most recent generation observed when updating this PDB status. DisruptionsAllowed and other status information is valid only if observedGeneration equals to PDB's object generation.".to_owned()),
                                ..Default::default()
                            })),
                            instance_type: Some(crate::schemars::schema::SingleOrVec::Single(Box::new(crate::schemars::schema::InstanceType::Integer))),
                            format: Some("int64".to_owned()),
                            ..Default::default()
                        }),
                    ),
                ]).collect(),
                required: IntoIterator::into_iter([
                    "currentHealthy",
                    "desiredHealthy",
                    "disruptionsAllowed",
                    "expectedPods",
                ]).map(std::borrow::ToOwned::to_owned).collect(),
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}
