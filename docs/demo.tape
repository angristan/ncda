# Regenerate from the repository root:
#   cargo build --release --locked
#   sudo -v
#   vhs docs/demo.tape

Require bash
Require dd
Require sudo

Output docs/assets/ncda-demo.gif

Set Shell "bash"
Set Width 1500
Set Height 760
Set FontSize 18
Set FontFamily "JetBrains Mono"
Set LineHeight 1.05
Set Framerate 15
Set TypingSpeed 35ms
Set Theme "GruvboxDark"
Set Padding 8
Set CursorBlink false

Hide
Type "export PS1='❯ '"
Enter
Type "clear"
Enter
Type "./scripts/demo-workload.sh >/dev/null 2>&1 &"
Enter
Type "demo_pid=$!"
Enter
Sleep 1s
Show

Type "sudo -n ./target/release/ncda --rate-window 5"
Enter
Sleep 1s
Type "r"
Sleep 2s

Type "/"
Type "path:/tmp/ncda-demo"
Enter
Sleep 750ms
Enter
Sleep 500ms
Enter
Sleep 2s

Type "P"
Sleep 2s
Type "P"

Tab
Sleep 500ms
Enter
Type "j"
Enter
Sleep 2s

Type "?"
Sleep 1500ms
Type "x"
Sleep 500ms

Hide
Type "q"
Type "kill \\$demo_pid; wait \\$demo_pid 2>/dev/null || true"
Enter
Sleep 500ms
