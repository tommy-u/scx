// Copyright (c) Meta Platforms, Inc. and affiliates.
//
// This software may be used and distributed according to the terms of the
// GNU General Public License version 2.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OptionStatus {
    Explicit,
    Default,
    Disabled,
    Unset,
}

#[derive(Clone, Debug, PartialEq)]
pub struct OptionDefinition {
    pub name: String,
    pub aliases: Vec<String>,
    pub value_name: Option<String>,
    pub default: Option<String>,
    pub possible_values: Vec<String>,
    pub description: String,
    pub group: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SchedulerOptionView {
    pub name: String,
    pub value_name: Option<String>,
    pub current_value: String,
    pub status: OptionStatus,
    pub default: Option<String>,
    pub possible_values: Vec<String>,
    pub description: String,
    pub group: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct SchedulerConfigSnapshot {
    pub available: bool,
    pub error: Option<String>,
    pub pid: Option<u32>,
    pub executable: Option<String>,
    pub version: Option<String>,
    pub command_line: Vec<String>,
    pub options: Vec<SchedulerOptionView>,
}

impl Default for SchedulerConfigSnapshot {
    fn default() -> Self {
        Self {
            available: false,
            error: Some("running scx_mitosis process not found".into()),
            pid: None,
            executable: None,
            version: None,
            command_line: Vec::new(),
            options: Vec::new(),
        }
    }
}

#[derive(Default)]
struct DefinitionBuilder {
    name: String,
    aliases: Vec<String>,
    value_name: Option<String>,
    default: Option<String>,
    possible_values: Vec<String>,
    description: Vec<String>,
    group: String,
}

impl DefinitionBuilder {
    fn finish(self) -> OptionDefinition {
        OptionDefinition {
            name: self.name,
            aliases: self.aliases,
            value_name: self.value_name,
            default: self.default,
            possible_values: self.possible_values,
            description: self.description.join(" "),
            group: self.group,
        }
    }
}

fn parse_header(header: &str, group: &str) -> Option<DefinitionBuilder> {
    let mut names = header
        .split_whitespace()
        .map(|token| token.trim_end_matches(','))
        .filter(|token| token.starts_with('-'))
        .map(str::to_owned)
        .collect::<Vec<_>>();
    let name_index = names.iter().position(|name| name.starts_with("--"))?;
    let name = names.remove(name_index);
    let value_name = header
        .split_once('<')
        .and_then(|(_, suffix)| suffix.split_once('>'))
        .map(|(value, _)| value.to_owned());
    Some(DefinitionBuilder {
        name,
        aliases: names,
        value_name,
        group: group.to_owned(),
        ..Default::default()
    })
}

pub fn parse_help(help: &str) -> Vec<OptionDefinition> {
    let mut definitions = Vec::new();
    let mut current = None::<DefinitionBuilder>;
    let mut group = String::new();

    for line in help.lines() {
        let trimmed = line.trim();
        if !line.starts_with(char::is_whitespace) && trimmed.ends_with(':') {
            if let Some(builder) = current.take() {
                definitions.push(builder.finish());
            }
            group = trimmed.trim_end_matches(':').to_owned();
            continue;
        }
        if trimmed.starts_with('-') {
            if let Some(builder) = current.take() {
                definitions.push(builder.finish());
            }
            current = parse_header(trimmed, &group);
            continue;
        }
        let Some(builder) = current.as_mut() else {
            continue;
        };
        if trimmed.is_empty() {
            continue;
        }
        if let Some(value) = trimmed
            .strip_prefix("[default: ")
            .and_then(|value| value.strip_suffix(']'))
        {
            builder.default = Some(value.to_owned());
        } else if let Some(values) = trimmed
            .strip_prefix("[possible values: ")
            .and_then(|value| value.strip_suffix(']'))
        {
            builder.possible_values = values
                .split(',')
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned)
                .collect();
        } else if !trimmed.starts_with('[') {
            builder.description.push(trimmed.to_owned());
        }
    }
    if let Some(builder) = current {
        definitions.push(builder.finish());
    }
    definitions
}

pub fn resolve_options(
    definitions: &[OptionDefinition],
    command_line: &[String],
) -> Vec<SchedulerOptionView> {
    let lookup = definitions
        .iter()
        .enumerate()
        .flat_map(|(index, definition)| {
            std::iter::once((definition.name.as_str(), index)).chain(
                definition
                    .aliases
                    .iter()
                    .map(move |alias| (alias.as_str(), index)),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut explicit = BTreeMap::<usize, Vec<String>>::new();
    let mut index = 1;
    while index < command_line.len() {
        let argument = &command_line[index];
        let (name, inline_value) = argument
            .split_once('=')
            .map_or((argument.as_str(), None), |(name, value)| {
                (name, Some(value.to_owned()))
            });
        let Some(&definition_index) = lookup.get(name) else {
            index += 1;
            continue;
        };
        let definition = &definitions[definition_index];
        let value = if definition.value_name.is_some() {
            inline_value.or_else(|| {
                command_line.get(index + 1).map(|value| {
                    index += 1;
                    value.clone()
                })
            })
        } else {
            Some("enabled".into())
        };
        if let Some(value) = value {
            explicit.entry(definition_index).or_default().push(value);
        }
        index += 1;
    }

    definitions
        .iter()
        .enumerate()
        .map(|(index, definition)| {
            let (status, current_value) = if let Some(values) = explicit.get(&index) {
                (OptionStatus::Explicit, values.join(", "))
            } else if let Some(default) = &definition.default {
                (OptionStatus::Default, default.clone())
            } else if definition.value_name.is_none() {
                (OptionStatus::Disabled, "disabled".into())
            } else {
                (OptionStatus::Unset, "unset".into())
            };
            SchedulerOptionView {
                name: definition.name.clone(),
                value_name: definition.value_name.clone(),
                current_value,
                status,
                default: definition.default.clone(),
                possible_values: definition.possible_values.clone(),
                description: definition.description.clone(),
                group: definition.group.clone(),
            }
        })
        .collect()
}

fn read_command_line(pid: u32) -> Option<Vec<String>> {
    let contents = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let arguments = contents
        .split(|byte| *byte == 0)
        .filter(|argument| !argument.is_empty())
        .map(|argument| String::from_utf8_lossy(argument).into_owned())
        .collect::<Vec<_>>();
    (!arguments.is_empty()).then_some(arguments)
}

fn scheduler_process() -> Option<(u32, PathBuf, Vec<String>)> {
    let mut candidates = fs::read_dir("/proc")
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_name().to_string_lossy().parse::<u32>().ok())
        .filter_map(|pid| {
            let command_line = read_command_line(pid)?;
            let name = Path::new(command_line.first()?)
                .file_name()?
                .to_string_lossy();
            (name.starts_with("scx_mitosis") && !name.contains("inspector"))
                .then(|| (pid, PathBuf::from(format!("/proc/{pid}/exe")), command_line))
        })
        .filter(|(_, _, command_line)| !command_line.iter().any(|arg| arg == "--monitor"))
        .collect::<Vec<_>>();
    candidates.sort_unstable_by_key(|(pid, _, _)| *pid);
    candidates.into_iter().next()
}

pub fn metadata_output(
    success: bool,
    stdout: &[u8],
    stderr: &[u8],
    argument: &str,
) -> Result<String, String> {
    let bytes = if stdout.is_empty() { stderr } else { stdout };
    let text = String::from_utf8_lossy(bytes).trim().to_owned();
    if success || (argument == "--help" && !text.is_empty()) {
        Ok(text)
    } else {
        Err(text.lines().next().unwrap_or("no output").to_owned())
    }
}

fn run_metadata(executable: &Path, argument: &str) -> Result<String, String> {
    let output = Command::new(executable)
        .arg(argument)
        .output()
        .map_err(|error| format!("running {} {argument}: {error}", executable.display()))?;
    metadata_output(
        output.status.success(),
        &output.stdout,
        &output.stderr,
        argument,
    )
    .map_err(|error| {
        format!(
            "{} {argument} exited with {}: {error}",
            executable.display(),
            output.status
        )
    })
}

pub fn discover() -> SchedulerConfigSnapshot {
    let Some((pid, proc_executable, command_line)) = scheduler_process() else {
        return SchedulerConfigSnapshot::default();
    };
    let executable = fs::read_link(&proc_executable)
        .unwrap_or_else(|_| proc_executable.clone())
        .to_string_lossy()
        .into_owned();
    let version = run_metadata(&proc_executable, "--version")
        .ok()
        .and_then(|value| value.lines().next().map(str::to_owned));
    match run_metadata(&proc_executable, "--help") {
        Ok(help) => {
            let definitions = parse_help(&help);
            let error = definitions
                .is_empty()
                .then(|| "running binary returned no option definitions".into());
            SchedulerConfigSnapshot {
                available: error.is_none(),
                error,
                pid: Some(pid),
                executable: Some(executable),
                version,
                command_line: command_line.clone(),
                options: resolve_options(&definitions, &command_line),
            }
        }
        Err(error) => SchedulerConfigSnapshot {
            available: false,
            error: Some(error),
            pid: Some(pid),
            executable: Some(executable),
            version,
            command_line,
            options: Vec::new(),
        },
    }
}
