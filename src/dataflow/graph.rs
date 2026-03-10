use std::collections::HashMap;
use serde::{Deserialize, Serialize};

/// Data Flow Graph - inspired by CodeQL's data flow analysis
/// Represents how data moves through a program from sources to sinks
/// Includes local (intra-procedural) and global (inter-procedural) analysis

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowNode {
    pub id: usize,
    pub node_type: DFNodeType,
    pub file_path: String,
    pub line_number: usize,
    pub column: usize,
    pub content: String,
    pub variable: Option<String>,
    pub scope: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum DFNodeType {
    Source,
    Sink,
    Sanitizer,
    Transform,
    Assignment,
    Parameter,
    ReturnValue,
    CallArgument,
    PropertyAccess,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowEdge {
    pub from: usize,
    pub to: usize,
    pub edge_type: EdgeType,
    pub label: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeType {
    /// Direct assignment: x = y
    Assignment,
    /// Passed as function argument
    CallArgument,
    /// Returned from function
    ReturnFlow,
    /// Property access: obj.prop
    PropertyAccess,
    /// String concatenation or template
    StringConcat,
    /// Array/collection element
    CollectionElement,
    /// Taint propagation through transform (e.g. x + 1 where x is tainted)
    TaintPropagation,
}

#[derive(Debug)]
pub struct DataFlowGraph {
    pub nodes: Vec<DataFlowNode>,
    pub edges: Vec<DataFlowEdge>,
    node_counter: usize,
}

impl DataFlowGraph {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
            edges: Vec::new(),
            node_counter: 0,
        }
    }

    pub fn add_node(&mut self, node_type: DFNodeType, file_path: &str, line: usize,
                    content: &str, variable: Option<&str>, scope: &str) -> usize {
        let id = self.node_counter;
        self.node_counter += 1;
        self.nodes.push(DataFlowNode {
            id,
            node_type,
            file_path: file_path.to_string(),
            line_number: line,
            column: 0,
            content: content.to_string(),
            variable: variable.map(|s| s.to_string()),
            scope: scope.to_string(),
        });
        id
    }

    pub fn add_edge(&mut self, from: usize, to: usize, edge_type: EdgeType, label: &str) {
        self.edges.push(DataFlowEdge {
            from,
            to,
            edge_type,
            label: label.to_string(),
        });
    }

    /// Find all paths from source nodes to sink nodes (BFS)
    pub fn find_source_to_sink_paths(&self) -> Vec<DataFlowPath> {
        let sources: Vec<usize> = self.nodes.iter()
            .filter(|n| n.node_type == DFNodeType::Source)
            .map(|n| n.id)
            .collect();

        let sinks: Vec<usize> = self.nodes.iter()
            .filter(|n| n.node_type == DFNodeType::Sink)
            .map(|n| n.id)
            .collect();

        let sanitizers: Vec<usize> = self.nodes.iter()
            .filter(|n| n.node_type == DFNodeType::Sanitizer)
            .map(|n| n.id)
            .collect();

        // Build adjacency list
        let mut adj: HashMap<usize, Vec<usize>> = HashMap::new();
        for edge in &self.edges {
            adj.entry(edge.from).or_default().push(edge.to);
        }

        let mut paths = Vec::new();

        for &source in &sources {
            // BFS from source
            let mut queue: Vec<Vec<usize>> = vec![vec![source]];
            let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();

            const MAX_PATH_DEPTH: usize = 20;
            const MAX_PATHS_PER_SOURCE: usize = 50;
            const MAX_QUEUE_SIZE: usize = 10_000;
            let mut paths_found = 0usize;

            while let Some(path) = queue.pop() {
                if paths_found >= MAX_PATHS_PER_SOURCE || queue.len() > MAX_QUEUE_SIZE {
                    break;
                }

                let current = *path.last().unwrap();

                if visited.contains(&current) && current != source {
                    continue;
                }
                visited.insert(current);

                if sinks.contains(&current) && path.len() > 1 {
                    // Check if any sanitizer is on the path
                    let is_sanitized = path.iter().any(|n| sanitizers.contains(n));

                    let steps: Vec<PathStep> = path.iter().filter_map(|&nid| {
                        let node = self.nodes.get(nid)?;
                        Some(PathStep {
                            node_id: nid,
                            file_path: node.file_path.clone(),
                            line_number: node.line_number,
                            content: node.content.clone(),
                            node_type: node.node_type.clone(),
                        })
                    }).collect();

                    paths.push(DataFlowPath {
                        source_id: source,
                        sink_id: current,
                        steps,
                        is_sanitized,
                        length: path.len(),
                    });
                    paths_found += 1;
                    continue;
                }

                // Depth limit to prevent exponential blowup
                if path.len() >= MAX_PATH_DEPTH {
                    continue;
                }

                if let Some(neighbors) = adj.get(&current) {
                    for &next in neighbors {
                        if !path.contains(&next) {
                            let mut new_path = path.clone();
                            new_path.push(next);
                            queue.push(new_path);
                        }
                    }
                }
            }
        }

        paths
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataFlowPath {
    pub source_id: usize,
    pub sink_id: usize,
    pub steps: Vec<PathStep>,
    pub is_sanitized: bool,
    pub length: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathStep {
    pub node_id: usize,
    pub file_path: String,
    pub line_number: usize,
    pub content: String,
    pub node_type: DFNodeType,
}
