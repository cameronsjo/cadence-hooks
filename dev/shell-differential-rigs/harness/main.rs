use cadence_hooks_core::shell::command_segments;
fn main() {
    for cmd in [
        "echo hi # cat <<EOF\nrm -rf ~/Documents\nEOF",
        "echo hi # x <<EOF\nrm -rf ~/Documents\nEOF",
        "bash -c -- 'rm -rf ~/Documents'",
    ] {
        println!("{cmd:?}\n   -> {:?}", command_segments(cmd));
    }
}
