use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::{Error, Result, invalid};

const REQUIRED_IDS: [u32; 3] = [0x9b, 0x9d, 0x9e];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Artifact {
    pub path: PathBuf,
    pub size: u64,
}

pub(crate) fn load_artifacts(index_path: &Path) -> Result<BTreeMap<u32, Artifact>> {
    let text = std::fs::read_to_string(index_path)
        .map_err(|error| Error::io("read module index", index_path, error))?;
    let document: Value = serde_json::from_str(&text)?;
    let root = index_path.parent().unwrap_or_else(|| Path::new("."));
    let mut result = BTreeMap::new();

    if let Some(items) = document.get("module_registry").and_then(Value::as_array) {
        for item in items {
            let Some(command_id) = item.get("command_id").and_then(Value::as_u64) else {
                continue;
            };
            let command_id = u32::try_from(command_id)
                .map_err(|_| Error::Invalid("module command ID exceeds u32".to_owned()))?;
            if !REQUIRED_IDS.contains(&command_id) {
                continue;
            }
            let Some(path) = item.get("image_path").and_then(Value::as_str) else {
                continue;
            };
            let size = item
                .get("size")
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::Invalid(format!("module 0x{command_id:02X} lacks size")))?;
            result.insert(
                command_id,
                Artifact {
                    path: root.join(path),
                    size,
                },
            );
        }
    }
    if let Some(streams) = document.get("streams").and_then(Value::as_array) {
        for stream in streams {
            let Some(records) = stream.get("records").and_then(Value::as_array) else {
                continue;
            };
            for record in records {
                let Some(command_id) = record.get("command_id").and_then(Value::as_u64) else {
                    continue;
                };
                let command_id = u32::try_from(command_id)
                    .map_err(|_| Error::Invalid("record command ID exceeds u32".to_owned()))?;
                if !REQUIRED_IDS.contains(&command_id) {
                    continue;
                }
                let Some(image) = record.get("image") else {
                    continue;
                };
                let Some(path) = image.get("path").and_then(Value::as_str) else {
                    continue;
                };
                let size = image.get("size").and_then(Value::as_u64).ok_or_else(|| {
                    Error::Invalid(format!("record 0x{command_id:02X} lacks image size"))
                })?;
                result.insert(
                    command_id,
                    Artifact {
                        path: root.join(path),
                        size,
                    },
                );
            }
        }
    }

    let missing = REQUIRED_IDS
        .iter()
        .filter(|id| !result.contains_key(id))
        .map(|id| format!("0x{id:02X}"))
        .collect::<Vec<_>>();
    if !missing.is_empty() {
        return invalid(format!(
            "module index lacks required IDs: {}",
            missing.join(", ")
        ));
    }
    for (&command_id, artifact) in &result {
        let metadata = std::fs::metadata(&artifact.path)
            .map_err(|error| Error::io("inspect artifact", &artifact.path, error))?;
        if !metadata.is_file() || metadata.len() != artifact.size {
            return invalid(format!(
                "invalid artifact for module 0x{command_id:02X}: {}",
                artifact.path.display()
            ));
        }
    }
    Ok(result)
}
