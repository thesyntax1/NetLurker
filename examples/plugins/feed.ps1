$ip = [Console]::In.ReadLine()
$bad = @('203.0.113.7','198.51.100.23')
if ($bad -contains $ip) {
  '{"risk": 85, "verdict": "malicious", "note": "local blocklist"}'
} else {
  '{"risk": 5, "verdict": "clean", "note": ""}'
}
