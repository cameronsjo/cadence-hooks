## ADDED Requirements

### Requirement: Schema drift rows name the tool and field
Each `schema_drift` row in `failopen.jsonl` SHALL carry `toolName` and `field`. `toolName` MUST be the payload's `tool_name` when it is 1 to 64 ASCII letters, digits or `_`, `"other"` for any other value, and `null` when the payload has none. `field` MUST be the alphabetically first modeled field of the drifted key whose value fails its typed shape on its own, or the key itself when every field passes alone. Both MUST be static or charset-checked names, never payload values.

#### Scenario: Mistyped tool_input field
- **WHEN** a Bash payload's `tool_input.description` is an object
- **THEN** the `schema_drift` row has `toolName` `Bash` and `field` `description`, and does not contain the object's text

#### Scenario: Unplain tool name
- **WHEN** a drifted payload's `tool_name` is `Bash; rm -rf ~`
- **THEN** the row's `toolName` is `other`

#### Scenario: Matching payload
- **WHEN** a Bash payload's `tool_input` matches its typed shape
- **THEN** no `schema_drift` row is written
