# Per-model overrides for command-r-plus.
# Only declare variables that differ from the base rules/rules.rego.
# These values replace the corresponding base defaults at merge time.

default ExecProcessRequest := true
default CopyFileRequest := true
