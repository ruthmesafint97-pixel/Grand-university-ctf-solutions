# Grand University CTF Solutions

![Leaderboard](leadership%20board.jpg)

**Rank:** 2nd Place  
**Solves:** 12/12 (100%)  
**CTF Date:** April 25, 2026

---

## Overall Progress
![Overall Challenges](overall%20challange.jpg)

---

### 🔐 Crypto (3/3)

![Crypto Solved](crypto%20solved.jpg)

#### 1. C43SAR (100 pts) - Caesar Cipher

**Given:** `havpgs{e0g4g3_hag1y_1g_z4x3f_f3af3}`

**Solution:** ROT13 on letters, keep leet numbers

**PowerShell:**
```powershell
$text = "havpgs{e0g4g3_hag1y_1g_z4x3f_f3af3}"
$result = ""
foreach ($ch in $text.ToCharArray()) {
    if ($ch -ge 'a' -and $ch -le 'z') {
        $newChar = [char]((([int][char]$ch - 97 + 13) % 26) + 97)
        $result += $newChar
    } else {
        $result += $ch
    }
}
```


Write-Host $result
unictf{r0t4t3_unt1l_1t_m4k3s_s3ns3}

