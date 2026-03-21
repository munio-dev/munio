Output "assets/demo-config-scan.gif"

Set Shell "bash"
Set FontSize 13
Set Width 920
Set Height 500
Set Padding 15
Set Theme "GitHub Dark"
Set TypingSpeed 50ms

Hide
Type "PS1='munio ~$ ' && munio() { cat /tmp/config-scan-demo.txt; }"
Enter
Sleep 1s
Type "clear"
Enter
Sleep 500ms
Show

Sleep 300ms

Type "munio config-scan --config mcp-config.json"
Sleep 200ms
Enter
Sleep 1s

Sleep 6s
