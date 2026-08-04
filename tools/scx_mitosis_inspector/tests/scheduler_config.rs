use scx_mitosis_inspector::scheduler_config::{
    metadata_output, parse_help, resolve_options, OptionStatus,
};

const HELP: &str = r#"scx_mitosis: A dynamic affinity scheduler

Usage: scx_mitosis [OPTIONS]

Options:
      --log-level <LOG_LEVEL>
          Specify the logging level

          [default: info]

      --debug-events
          Enable debug event tracking

      --cell-parent-cgroup <CELL_PARENT_CGROUP>
          Parent cgroup path whose direct children become cells

      --cell-exclude <CELL_EXCLUDE>
          Exact directory name to exclude. Can be specified multiple times

      --run-id <RUN_ID>
          Optional run ID

Libbpf Options:
      --relaxed-maps <RELAXED_MAPS>
          Parse map definitions non-strictly

          [possible values: true, false]
"#;

#[test]
fn parses_clap_help_into_option_definitions() {
    let options = parse_help(HELP);
    assert_eq!(options.len(), 6);

    let log_level = options
        .iter()
        .find(|option| option.name == "--log-level")
        .unwrap();
    assert_eq!(log_level.value_name.as_deref(), Some("LOG_LEVEL"));
    assert_eq!(log_level.default.as_deref(), Some("info"));
    assert_eq!(log_level.description, "Specify the logging level");
    assert_eq!(log_level.group, "Options");

    let relaxed = options
        .iter()
        .find(|option| option.name == "--relaxed-maps")
        .unwrap();
    assert_eq!(relaxed.group, "Libbpf Options");
    assert_eq!(relaxed.possible_values, vec!["true", "false"]);
}

#[test]
fn resolves_explicit_defaults_disabled_and_unset_options() {
    let definitions = parse_help(HELP);
    let command_line = vec![
        "/usr/local/bin/scx_mitosis".to_owned(),
        "--cell-parent-cgroup".to_owned(),
        "/workload.slice".to_owned(),
        "--cell-exclude=first.service".to_owned(),
        "--cell-exclude".to_owned(),
        "second.service".to_owned(),
        "--debug-events".to_owned(),
    ];
    let rows = resolve_options(&definitions, &command_line);

    let row = |name: &str| rows.iter().find(|row| row.name == name).unwrap();
    assert_eq!(row("--log-level").status, OptionStatus::Default);
    assert_eq!(row("--log-level").current_value, "info");
    assert_eq!(row("--debug-events").status, OptionStatus::Explicit);
    assert_eq!(row("--debug-events").current_value, "enabled");
    assert_eq!(row("--cell-parent-cgroup").current_value, "/workload.slice");
    assert_eq!(
        row("--cell-exclude").current_value,
        "first.service, second.service"
    );
    assert_eq!(row("--run-id").status, OptionStatus::Unset);
    assert_eq!(row("--run-id").current_value, "unset");
    assert_eq!(row("--relaxed-maps").status, OptionStatus::Unset);
}

#[test]
fn accepts_clap_help_emitted_on_a_nonzero_exit() {
    assert_eq!(
        metadata_output(false, b"", HELP.as_bytes(), "--help").unwrap(),
        HELP.trim()
    );
    assert!(metadata_output(false, b"", b"load failed", "--version").is_err());
}
