use serde::Serialize;

/// SARIF (Static Analysis Results Interchange Format) v2.1.0
/// Standard output format consumed by GitHub Code Scanning, VS Code, and other IDEs

#[derive(Serialize)]
pub struct SarifReport {
    #[serde(rename = "$schema")]
    pub schema: String,
    pub version: String,
    pub runs: Vec<SarifRun>,
}

#[derive(Serialize)]
pub struct SarifRun {
    pub tool: SarifTool,
    pub results: Vec<SarifResult>,
    pub invocations: Vec<SarifInvocation>,
}

#[derive(Serialize)]
pub struct SarifTool {
    pub driver: SarifDriver,
}

#[derive(Serialize)]
pub struct SarifDriver {
    pub name: String,
    pub version: String,
    #[serde(rename = "informationUri")]
    pub information_uri: String,
    pub rules: Vec<SarifRuleDescriptor>,
}

#[derive(Serialize)]
pub struct SarifRuleDescriptor {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: SarifMessage,
    #[serde(rename = "fullDescription")]
    pub full_description: SarifMessage,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: SarifConfiguration,
    pub help: SarifMessage,
    pub properties: SarifRuleProperties,
}

#[derive(Serialize)]
pub struct SarifRuleProperties {
    pub tags: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precision: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_severity: Option<String>,
}

#[derive(Serialize)]
pub struct SarifConfiguration {
    pub level: String,
}

#[derive(Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex")]
    pub rule_index: usize,
    pub level: String,
    pub message: SarifMessage,
    pub locations: Vec<SarifLocation>,
    #[serde(rename = "fingerprints")]
    pub fingerprints: std::collections::HashMap<String, String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "codeFlows")]
    pub code_flows: Vec<SarifCodeFlow>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(rename = "relatedLocations")]
    pub related_locations: Vec<SarifRelatedLocation>,
    pub properties: SarifResultProperties,
}

#[derive(Serialize)]
pub struct SarifResultProperties {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}

#[derive(Serialize)]
pub struct SarifMessage {
    pub text: String,
}

#[derive(Serialize)]
pub struct SarifLocation {
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
}

#[derive(Serialize)]
pub struct SarifRelatedLocation {
    pub id: usize,
    #[serde(rename = "physicalLocation")]
    pub physical_location: SarifPhysicalLocation,
    pub message: SarifMessage,
}

#[derive(Serialize)]
pub struct SarifPhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: SarifArtifactLocation,
    pub region: SarifRegion,
}

#[derive(Serialize)]
pub struct SarifArtifactLocation {
    pub uri: String,
    #[serde(rename = "uriBaseId")]
    pub uri_base_id: String,
}

#[derive(Serialize)]
pub struct SarifRegion {
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "startColumn")]
    pub start_column: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "endLine")]
    pub end_line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snippet: Option<SarifSnippet>,
}

#[derive(Serialize)]
pub struct SarifSnippet {
    pub text: String,
}

#[derive(Serialize)]
pub struct SarifCodeFlow {
    #[serde(rename = "threadFlows")]
    pub thread_flows: Vec<SarifThreadFlow>,
}

#[derive(Serialize)]
pub struct SarifThreadFlow {
    pub locations: Vec<SarifThreadFlowLocation>,
}

#[derive(Serialize)]
pub struct SarifThreadFlowLocation {
    pub location: SarifLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kinds: Option<Vec<String>>,
    #[serde(rename = "nestingLevel")]
    pub nesting_level: usize,
}

#[derive(Serialize)]
pub struct SarifInvocation {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
}

use crate::scanner::engine::ScanResult;

pub fn generate_sarif(result: &ScanResult, target_path: &str) -> String {
    let mut rule_descriptors: Vec<SarifRuleDescriptor> = Vec::new();
    let mut results: Vec<SarifResult> = Vec::new();
    let mut rule_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();

    // Process vulnerability findings
    for finding in &result.findings {
        let rule_index = *rule_map.entry(finding.rule_id.clone()).or_insert_with(|| {
            let idx = rule_descriptors.len();
            rule_descriptors.push(SarifRuleDescriptor {
                id: finding.rule_id.clone(),
                name: finding.rule_name.clone(),
                short_description: SarifMessage { text: finding.rule_name.clone() },
                full_description: SarifMessage { text: finding.description.clone() },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(&finding.severity.to_string()),
                },
                help: SarifMessage { text: finding.remediation.clone() },
                properties: SarifRuleProperties {
                    tags: vec!["security".into(), finding.cwe.clone()],
                    precision: Some("high".into()),
                    security_severity: Some(severity_to_score(&finding.severity.to_string())),
                },
            });
            idx
        });

        let relative_path = make_relative(&finding.file_path, target_path);

        let mut fingerprints = std::collections::HashMap::new();
        fingerprints.insert("primaryLocationLineHash".to_string(), finding.fingerprint.clone());

        results.push(SarifResult {
            rule_id: finding.rule_id.clone(),
            rule_index,
            level: severity_to_sarif_level(&finding.severity.to_string()),
            message: SarifMessage { text: format!("{}: {}", finding.rule_name, finding.description) },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: relative_path,
                        uri_base_id: "%SRCROOT%".into(),
                    },
                    region: SarifRegion {
                        start_line: finding.line_number,
                        start_column: 1,
                        end_line: None,
                        snippet: Some(SarifSnippet { text: finding.line_content.clone() }),
                    },
                },
            }],
            fingerprints,
            code_flows: Vec::new(),
            related_locations: Vec::new(),
            properties: SarifResultProperties {
                confidence: None,
                category: Some(format!("{}", finding.category)),
            },
        });
    }

    // Process taint flow findings as path-based results
    for taint in &result.taint_findings {
        let rule_id = format!("TAINT-{}", taint.sink.sink_type.to_uppercase());
        let rule_index = *rule_map.entry(rule_id.clone()).or_insert_with(|| {
            let idx = rule_descriptors.len();
            rule_descriptors.push(SarifRuleDescriptor {
                id: rule_id.clone(),
                name: format!("Taint Flow to {}", taint.sink.sink_type),
                short_description: SarifMessage { text: taint.flow_description.clone() },
                full_description: SarifMessage { text: taint.flow_description.clone() },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(&taint.severity),
                },
                help: SarifMessage { text: format!("Sanitize data before it reaches {}", taint.sink.sink_type) },
                properties: SarifRuleProperties {
                    tags: vec!["security".into(), "taint-analysis".into()],
                    precision: Some(if taint.confidence == "HIGH" { "high" } else { "medium" }.into()),
                    security_severity: Some(severity_to_score(&taint.severity)),
                },
            });
            idx
        });

        let relative_path = make_relative(&taint.file_path, target_path);

        let mut fingerprints = std::collections::HashMap::new();
        fingerprints.insert("primaryLocationLineHash".to_string(),
            format!("taint-{}-{}-{}", taint.source.line_number, taint.sink.line_number, taint.sink.sink_type));

        // Build code flow (source → sink path visualization)
        let code_flow = SarifCodeFlow {
            thread_flows: vec![SarifThreadFlow {
                locations: vec![
                    SarifThreadFlowLocation {
                        location: SarifLocation {
                            physical_location: SarifPhysicalLocation {
                                artifact_location: SarifArtifactLocation {
                                    uri: relative_path.clone(),
                                    uri_base_id: "%SRCROOT%".into(),
                                },
                                region: SarifRegion {
                                    start_line: taint.source.line_number,
                                    start_column: 1, end_line: None,
                                    snippet: Some(SarifSnippet { text: taint.source.line_content.clone() }),
                                },
                            },
                        },
                        kinds: Some(vec!["source".into()]),
                        nesting_level: 0,
                    },
                    SarifThreadFlowLocation {
                        location: SarifLocation {
                            physical_location: SarifPhysicalLocation {
                                artifact_location: SarifArtifactLocation {
                                    uri: relative_path.clone(),
                                    uri_base_id: "%SRCROOT%".into(),
                                },
                                region: SarifRegion {
                                    start_line: taint.sink.line_number,
                                    start_column: 1, end_line: None,
                                    snippet: Some(SarifSnippet { text: taint.sink.line_content.clone() }),
                                },
                            },
                        },
                        kinds: Some(vec!["sink".into()]),
                        nesting_level: 0,
                    },
                ],
            }],
        };

        results.push(SarifResult {
            rule_id: rule_id.clone(),
            rule_index,
            level: severity_to_sarif_level(&taint.severity),
            message: SarifMessage { text: taint.flow_description.clone() },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: relative_path,
                        uri_base_id: "%SRCROOT%".into(),
                    },
                    region: SarifRegion {
                        start_line: taint.sink.line_number,
                        start_column: 1, end_line: None,
                        snippet: Some(SarifSnippet { text: taint.sink.line_content.clone() }),
                    },
                },
            }],
            fingerprints,
            code_flows: vec![code_flow],
            related_locations: vec![SarifRelatedLocation {
                id: 1,
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: make_relative(&taint.file_path, target_path),
                        uri_base_id: "%SRCROOT%".into(),
                    },
                    region: SarifRegion {
                        start_line: taint.source.line_number,
                        start_column: 1, end_line: None,
                        snippet: Some(SarifSnippet { text: taint.source.line_content.clone() }),
                    },
                },
                message: SarifMessage { text: format!("Taint source: {} via {}", taint.source.variable, taint.source.source_type) },
            }],
            properties: SarifResultProperties {
                confidence: Some(taint.confidence.clone()),
                category: Some("taint-flow".into()),
            },
        });
    }

    // Process secret findings
    for secret in &result.secret_findings {
        let rule_id = format!("SECRET-{}", secret.rule_name.replace(' ', "-").to_uppercase());
        let rule_index = *rule_map.entry(rule_id.clone()).or_insert_with(|| {
            let idx = rule_descriptors.len();
            rule_descriptors.push(SarifRuleDescriptor {
                id: rule_id.clone(),
                name: secret.rule_name.clone(),
                short_description: SarifMessage { text: secret.description.clone() },
                full_description: SarifMessage { text: secret.description.clone() },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(&secret.severity),
                },
                help: SarifMessage { text: "Remove hardcoded secret and use environment variables or a secrets manager".into() },
                properties: SarifRuleProperties {
                    tags: vec!["security".into(), "secret".into()],
                    precision: Some("high".into()),
                    security_severity: Some(severity_to_score(&secret.severity)),
                },
            });
            idx
        });

        let relative_path = make_relative(&secret.file_path, target_path);
        let mut fingerprints = std::collections::HashMap::new();
        fingerprints.insert("primaryLocationLineHash".to_string(),
            format!("secret-{}-{}", secret.line_number, secret.rule_name));

        results.push(SarifResult {
            rule_id,
            rule_index,
            level: severity_to_sarif_level(&secret.severity),
            message: SarifMessage { text: format!("{}: {}", secret.rule_name, secret.description) },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: relative_path,
                        uri_base_id: "%SRCROOT%".into(),
                    },
                    region: SarifRegion {
                        start_line: secret.line_number,
                        start_column: 1, end_line: None,
                        snippet: Some(SarifSnippet { text: secret.line_content.clone() }),
                    },
                },
            }],
            fingerprints,
            code_flows: Vec::new(),
            related_locations: Vec::new(),
            properties: SarifResultProperties {
                confidence: Some("HIGH".into()),
                category: Some("secret-detection".into()),
            },
        });
    }

    // Process dependency findings
    for dep in &result.dep_findings {
        let dep_key = dep.vulnerability.replace(' ', "-").chars().take(40).collect::<String>();
        let rule_id = format!("DEP-{}", dep_key.to_uppercase());
        let rule_index = *rule_map.entry(rule_id.clone()).or_insert_with(|| {
            let idx = rule_descriptors.len();
            rule_descriptors.push(SarifRuleDescriptor {
                id: rule_id.clone(),
                name: format!("Vulnerable Dependency: {}", dep.package_name),
                short_description: SarifMessage { text: dep.vulnerability.clone() },
                full_description: SarifMessage { text: format!("{} {} — {}", dep.package_name, dep.version, dep.vulnerability) },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(&dep.severity),
                },
                help: SarifMessage { text: dep.advice.clone() },
                properties: SarifRuleProperties {
                    tags: vec!["security".into(), "dependency".into()],
                    precision: Some("high".into()),
                    security_severity: Some(severity_to_score(&dep.severity)),
                },
            });
            idx
        });

        let relative_path = make_relative(&dep.file_path, target_path);
        let mut fingerprints = std::collections::HashMap::new();
        fingerprints.insert("primaryLocationLineHash".to_string(),
            format!("dep-{}-{}", dep.package_name, dep.vulnerability));

        results.push(SarifResult {
            rule_id,
            rule_index,
            level: severity_to_sarif_level(&dep.severity),
            message: SarifMessage { text: format!("{}@{}: {}", dep.package_name, dep.version, dep.vulnerability) },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: relative_path,
                        uri_base_id: "%SRCROOT%".into(),
                    },
                    region: SarifRegion {
                        start_line: 1,
                        start_column: 1, end_line: None,
                        snippet: Some(SarifSnippet { text: format!("{}@{}", dep.package_name, dep.version) }),
                    },
                },
            }],
            fingerprints,
            code_flows: Vec::new(),
            related_locations: Vec::new(),
            properties: SarifResultProperties {
                confidence: Some("HIGH".into()),
                category: Some("dependency-vulnerability".into()),
            },
        });
    }

    // Process composite rule findings
    for cf in &result.composite_findings {
        let rule_index = *rule_map.entry(cf.rule_id.clone()).or_insert_with(|| {
            let idx = rule_descriptors.len();
            rule_descriptors.push(SarifRuleDescriptor {
                id: cf.rule_id.clone(),
                name: cf.rule_name.clone(),
                short_description: SarifMessage { text: cf.rule_name.clone() },
                full_description: SarifMessage { text: cf.description.clone() },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(&cf.severity),
                },
                help: SarifMessage { text: cf.remediation.clone() },
                properties: SarifRuleProperties {
                    tags: vec!["security".into(), "composite-rule".into(), cf.cwe.clone()],
                    precision: Some(cf.confidence.to_lowercase()),
                    security_severity: Some(severity_to_score(&cf.severity)),
                },
            });
            idx
        });

        let relative_path = make_relative(&cf.file_path, target_path);
        let mut fingerprints = std::collections::HashMap::new();
        fingerprints.insert("primaryLocationLineHash".to_string(),
            format!("comp-{}-{}-{}", cf.rule_id, cf.file_path, cf.line_number));

        results.push(SarifResult {
            rule_id: cf.rule_id.clone(),
            rule_index,
            level: severity_to_sarif_level(&cf.severity),
            message: SarifMessage { text: format!("{}: {}", cf.rule_name, cf.description) },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: relative_path,
                        uri_base_id: "%SRCROOT%".into(),
                    },
                    region: SarifRegion {
                        start_line: cf.line_number,
                        start_column: 1, end_line: None,
                        snippet: Some(SarifSnippet { text: cf.line_content.clone() }),
                    },
                },
            }],
            fingerprints,
            code_flows: Vec::new(),
            related_locations: Vec::new(),
            properties: SarifResultProperties {
                confidence: Some(cf.confidence.clone()),
                category: Some("composite-rule".into()),
            },
        });
    }

    // Process IaC findings
    for iac in &result.iac_findings {
        let rule_index = *rule_map.entry(iac.rule_id.clone()).or_insert_with(|| {
            let idx = rule_descriptors.len();
            rule_descriptors.push(SarifRuleDescriptor {
                id: iac.rule_id.clone(),
                name: iac.rule_name.clone(),
                short_description: SarifMessage { text: iac.rule_name.clone() },
                full_description: SarifMessage { text: iac.description.clone() },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(&iac.severity),
                },
                help: SarifMessage { text: iac.remediation.clone() },
                properties: SarifRuleProperties {
                    tags: vec!["security".into(), "iac".into(), iac.category.clone(), iac.cwe.clone()],
                    precision: Some("high".into()),
                    security_severity: Some(severity_to_score(&iac.severity)),
                },
            });
            idx
        });

        let relative_path = make_relative(&iac.file_path, target_path);
        let mut fingerprints = std::collections::HashMap::new();
        fingerprints.insert("primaryLocationLineHash".to_string(),
            format!("iac-{}-{}-{}", iac.rule_id, iac.file_path, iac.line_number));

        results.push(SarifResult {
            rule_id: iac.rule_id.clone(),
            rule_index,
            level: severity_to_sarif_level(&iac.severity),
            message: SarifMessage { text: format!("[{}] {}: {}", iac.category, iac.rule_name, iac.description) },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: relative_path,
                        uri_base_id: "%SRCROOT%".into(),
                    },
                    region: SarifRegion {
                        start_line: iac.line_number,
                        start_column: 1, end_line: None,
                        snippet: Some(SarifSnippet { text: iac.line_content.clone() }),
                    },
                },
            }],
            fingerprints,
            code_flows: Vec::new(),
            related_locations: Vec::new(),
            properties: SarifResultProperties {
                confidence: Some("HIGH".into()),
                category: Some(format!("iac-{}", iac.category.to_lowercase())),
            },
        });
    }

    // Process data flow paths
    for flow in &result.flow_paths {
        if flow.is_sanitized { continue; } // Skip sanitized flows
        let rule_id = format!("FLOW-{}", flow.sink_type.to_uppercase().replace(' ', "-"));
        let rule_index = *rule_map.entry(rule_id.clone()).or_insert_with(|| {
            let idx = rule_descriptors.len();
            rule_descriptors.push(SarifRuleDescriptor {
                id: rule_id.clone(),
                name: format!("Data Flow to {}", flow.sink_type),
                short_description: SarifMessage { text: flow.description.clone() },
                full_description: SarifMessage { text: flow.description.clone() },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(&flow.severity),
                },
                help: SarifMessage { text: format!("Sanitize data before reaching {} sink", flow.sink_type) },
                properties: SarifRuleProperties {
                    tags: vec!["security".into(), "data-flow".into(), flow.cwe.clone()],
                    precision: Some(flow.confidence.to_string().to_lowercase()),
                    security_severity: Some(severity_to_score(&flow.severity)),
                },
            });
            idx
        });

        let relative_src = make_relative(&flow.source_file, target_path);
        let relative_sink = make_relative(&flow.sink_file, target_path);
        let mut fingerprints = std::collections::HashMap::new();
        fingerprints.insert("primaryLocationLineHash".to_string(),
            format!("flow-{}-{}-{}", flow.source_line, flow.sink_line, flow.sink_type));

        // Build code flow with intermediate steps
        let mut thread_flow_locations = vec![
            SarifThreadFlowLocation {
                location: SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: relative_src.clone(),
                            uri_base_id: "%SRCROOT%".into(),
                        },
                        region: SarifRegion {
                            start_line: flow.source_line,
                            start_column: 1, end_line: None,
                            snippet: Some(SarifSnippet { text: format!("Source: {} ({})", flow.source_var, flow.source_type) }),
                        },
                    },
                },
                kinds: Some(vec!["source".into()]),
                nesting_level: 0,
            },
        ];
        for step in &flow.intermediate_steps {
            thread_flow_locations.push(SarifThreadFlowLocation {
                location: SarifLocation {
                    physical_location: SarifPhysicalLocation {
                        artifact_location: SarifArtifactLocation {
                            uri: make_relative(&step.file, target_path),
                            uri_base_id: "%SRCROOT%".into(),
                        },
                        region: SarifRegion {
                            start_line: step.line,
                            start_column: 1, end_line: None,
                            snippet: Some(SarifSnippet { text: step.content.clone() }),
                        },
                    },
                },
                kinds: Some(vec!["pass-through".into()]),
                nesting_level: 1,
            });
        }
        thread_flow_locations.push(SarifThreadFlowLocation {
            location: SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: relative_sink.clone(),
                        uri_base_id: "%SRCROOT%".into(),
                    },
                    region: SarifRegion {
                        start_line: flow.sink_line,
                        start_column: 1, end_line: None,
                        snippet: Some(SarifSnippet { text: format!("Sink: {}", flow.sink_type) }),
                    },
                },
            },
            kinds: Some(vec!["sink".into()]),
            nesting_level: 0,
        });

        results.push(SarifResult {
            rule_id,
            rule_index,
            level: severity_to_sarif_level(&flow.severity),
            message: SarifMessage { text: flow.description.clone() },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: relative_sink,
                        uri_base_id: "%SRCROOT%".into(),
                    },
                    region: SarifRegion {
                        start_line: flow.sink_line,
                        start_column: 1, end_line: None,
                        snippet: None,
                    },
                },
            }],
            fingerprints,
            code_flows: vec![SarifCodeFlow {
                thread_flows: vec![SarifThreadFlow { locations: thread_flow_locations }],
            }],
            related_locations: Vec::new(),
            properties: SarifResultProperties {
                confidence: Some(flow.confidence.to_string()),
                category: Some("data-flow".into()),
            },
        });
    }

    // Process vulnerability chains as informational findings
    for (ci, chain) in result.vuln_chains.iter().enumerate() {
        let rule_id = format!("CHAIN-{:03}", ci + 1);
        let rule_index = *rule_map.entry(rule_id.clone()).or_insert_with(|| {
            let idx = rule_descriptors.len();
            rule_descriptors.push(SarifRuleDescriptor {
                id: rule_id.clone(),
                name: chain.title.clone(),
                short_description: SarifMessage { text: chain.title.clone() },
                full_description: SarifMessage { text: chain.description.clone() },
                default_configuration: SarifConfiguration {
                    level: severity_to_sarif_level(&chain.severity),
                },
                help: SarifMessage { text: chain.impact.clone() },
                properties: SarifRuleProperties {
                    tags: vec!["security".into(), "attack-chain".into()],
                    precision: Some("medium".into()),
                    security_severity: Some(format!("{:.1}", chain.cvss_estimate)),
                },
            });
            idx
        });

        // Use the first step's location
        let first_step = chain.steps.first();
        let (file_path, line_number) = first_step
            .map(|s| (s.file_path.clone(), s.line_number))
            .unwrap_or_else(|| ("unknown".into(), 1));
        let relative_path = make_relative(&file_path, target_path);

        let mut fingerprints = std::collections::HashMap::new();
        fingerprints.insert("primaryLocationLineHash".to_string(),
            format!("chain-{}-{}", ci, chain.title));

        // Build related locations from chain steps
        let related: Vec<SarifRelatedLocation> = chain.steps.iter().enumerate().map(|(si, step)| {
            SarifRelatedLocation {
                id: si + 1,
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: make_relative(&step.file_path, target_path),
                        uri_base_id: "%SRCROOT%".into(),
                    },
                    region: SarifRegion {
                        start_line: step.line_number,
                        start_column: 1, end_line: None,
                        snippet: Some(SarifSnippet { text: step.description.clone() }),
                    },
                },
                message: SarifMessage { text: format!("Step {}: {}", step.step_number, step.description) },
            }
        }).collect();

        results.push(SarifResult {
            rule_id,
            rule_index,
            level: severity_to_sarif_level(&chain.severity),
            message: SarifMessage { text: format!("{} (CVSS ~{:.1}): {}", chain.title, chain.cvss_estimate, chain.description) },
            locations: vec![SarifLocation {
                physical_location: SarifPhysicalLocation {
                    artifact_location: SarifArtifactLocation {
                        uri: relative_path,
                        uri_base_id: "%SRCROOT%".into(),
                    },
                    region: SarifRegion {
                        start_line: line_number,
                        start_column: 1, end_line: None,
                        snippet: None,
                    },
                },
            }],
            fingerprints,
            code_flows: Vec::new(),
            related_locations: related,
            properties: SarifResultProperties {
                confidence: Some("MEDIUM".into()),
                category: Some("attack-chain".into()),
            },
        });
    }

    let sarif = SarifReport {
        schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json".into(),
        version: "2.1.0".into(),
        runs: vec![SarifRun {
            tool: SarifTool {
                driver: SarifDriver {
                    name: "VulnChain".into(),
                    version: env!("CARGO_PKG_VERSION").into(),
                    information_uri: "https://github.com/vulnchain/vulnchain".into(),
                    rules: rule_descriptors,
                },
            },
            results,
            invocations: vec![SarifInvocation {
                execution_successful: true,
            }],
        }],
    };

    serde_json::to_string_pretty(&sarif).unwrap_or_else(|e| format!("{{\"error\": \"{}\"}}", e))
}

fn severity_to_sarif_level(severity: &str) -> String {
    match severity.to_uppercase().as_str() {
        "CRITICAL" | "HIGH" => "error".into(),
        "MEDIUM" => "warning".into(),
        "LOW" | "INFO" => "note".into(),
        _ => "warning".into(),
    }
}

fn severity_to_score(severity: &str) -> String {
    match severity.to_uppercase().as_str() {
        "CRITICAL" => "9.5".into(),
        "HIGH" => "7.5".into(),
        "MEDIUM" => "5.0".into(),
        "LOW" => "2.5".into(),
        _ => "1.0".into(),
    }
}

fn make_relative(file_path: &str, target_path: &str) -> String {
    file_path.strip_prefix(target_path)
        .map(|p| p.trim_start_matches('/').to_string())
        .unwrap_or_else(|| file_path.to_string())
}
