use std::collections::HashSet;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub static SOURCE_EXTENSIONS: &[&str] = &[
    // Python
    "py", "pyw",
    // JavaScript / TypeScript
    "js", "jsx", "ts", "tsx", "mjs", "cjs",
    // Java / Kotlin / Scala
    "java", "kt", "kts", "scala",
    // C / C++
    "c", "h", "cpp", "hpp", "cc", "cxx", "hh", "hxx",
    // Go
    "go",
    // Rust
    "rs",
    // Ruby
    "rb", "erb",
    // PHP
    "php", "phtml",
    // C#
    "cs", "cshtml",
    // Swift
    "swift",
    // Objective-C
    "m", "mm",
    // Shell
    "sh", "bash", "zsh", "fish",
    // Perl
    "pl", "pm",
    // Lua
    "lua",
    // R
    "r",
    // Haskell
    "hs",
    // Elixir
    "ex", "exs",
    // Clojure
    "clj", "cljs",
    // Dart
    "dart",
    // HTML/Templates
    "html", "htm", "ejs", "hbs", "vue", "svelte",
    // Config/Data
    "xml", "yaml", "yml", "json", "toml", "ini", "cfg", "conf",
    // Docker/CI
    "dockerfile",
    // Terraform / IaC
    "tf", "hcl",
    // SQL
    "sql",
];

pub static DEPENDENCY_FILES: &[&str] = &[
    "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "requirements.txt", "Pipfile", "Pipfile.lock", "setup.py", "setup.cfg", "pyproject.toml",
    "pom.xml", "build.gradle", "build.gradle.kts",
    "go.mod", "go.sum",
    "Gemfile", "Gemfile.lock",
    "Cargo.toml", "Cargo.lock",
    "composer.json", "composer.lock",
    "mix.exs", "pubspec.yaml",
];

pub static CONFIG_FILES: &[&str] = &[
    ".env", ".env.local", ".env.production", ".env.staging", ".env.development",
    ".htaccess", "nginx.conf", "httpd.conf", "apache2.conf",
    "docker-compose.yml", "docker-compose.yaml", "Dockerfile",
    ".dockerignore", ".gitignore",
    "Makefile", "Jenkinsfile", ".travis.yml", ".github/workflows",
    "serverless.yml", "terraform.tfvars",
    "web.config", "appsettings.json",
    "config.yml", "config.yaml", "config.json",
    "settings.py", "settings.json",
];

static SKIP_DIRS: &[&str] = &[
    "node_modules", ".git", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", "target", "build", "dist", "bin", "obj",
    ".gradle", ".mvn", ".idea", ".vscode", ".vs",
    "vendor", "venv", ".venv", "env", ".env",
    ".eggs", "*.egg-info", "bower_components",
    ".next", ".nuxt", ".output", "coverage",
];

/// Max file size to scan (1 MB) — skip minified JS, generated code, binaries
const MAX_FILE_SIZE: u64 = 1_048_576;

pub struct FileCollector {
    extensions: HashSet<String>,
    dep_files: HashSet<String>,
    config_files: HashSet<String>,
}

#[derive(Debug)]
pub struct CollectedFile {
    pub path: PathBuf,
    pub file_type: FileType,
}

#[derive(Debug, PartialEq)]
pub enum FileType {
    Source,
    Dependency,
    Config,
}

impl FileCollector {
    pub fn new() -> Self {
        Self {
            extensions: SOURCE_EXTENSIONS.iter().map(|s| s.to_string()).collect(),
            dep_files: DEPENDENCY_FILES.iter().map(|s| s.to_string()).collect(),
            config_files: CONFIG_FILES.iter().map(|s| s.to_string()).collect(),
        }
    }

    pub fn collect(&self, root: &Path) -> Vec<CollectedFile> {
        let skip_set: HashSet<&str> = SKIP_DIRS.iter().copied().collect();
        let mut files = Vec::new();

        let walker = WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if e.file_type().is_dir() {
                    let name = e.file_name().to_string_lossy();
                    !skip_set.contains(name.as_ref()) && !name.starts_with('.')
                        || e.depth() == 0
                } else {
                    true
                }
            });

        for entry in walker.filter_map(|e| e.ok()) {
            if !entry.file_type().is_file() {
                continue;
            }

            let path = entry.path().to_path_buf();
            let file_name = entry.file_name().to_string_lossy().to_string();

            // Check dependency files
            if self.dep_files.contains(&file_name) {
                files.push(CollectedFile {
                    path,
                    file_type: FileType::Dependency,
                });
                continue;
            }

            // Check config files
            if self.config_files.contains(&file_name) || file_name.starts_with(".env") {
                files.push(CollectedFile {
                    path,
                    file_type: FileType::Config,
                });
                continue;
            }

            // Check Dockerfile (any file starting with Dockerfile)
            if file_name.starts_with("Dockerfile") || file_name == "docker-compose.yml" || file_name == "docker-compose.yaml" {
                files.push(CollectedFile {
                    path,
                    file_type: FileType::Config,
                });
                continue;
            }

            // Check source files by extension
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy().to_lowercase();
                if self.extensions.contains(&ext_str) {
                    // Skip files that are too large (likely generated/minified)
                    if let Ok(meta) = std::fs::metadata(&path) {
                        if meta.len() > MAX_FILE_SIZE {
                            continue;
                        }
                    }
                    // Skip likely binary files by quick byte check
                    if Self::is_likely_binary(&path) {
                        continue;
                    }
                    files.push(CollectedFile {
                        path,
                        file_type: FileType::Source,
                    });
                }
            }
        }
        files
    }

    /// Quick heuristic: read first 512 bytes and check for null bytes
    fn is_likely_binary(path: &Path) -> bool {
        use std::io::Read;
        if let Ok(mut f) = std::fs::File::open(path) {
            let mut buf = [0u8; 512];
            if let Ok(n) = f.read(&mut buf) {
                return buf[..n].contains(&0);
            }
        }
        false
    }
}
