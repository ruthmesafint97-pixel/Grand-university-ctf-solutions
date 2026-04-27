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
```
unictf{r0t4t3_unt1l_1t_m4k3s_s3ns3}
```

#### 2. 64ESAB (100 pts) - Base64

**Given:** `VjJ0YWFrMVhUa2RoTTNCV1lsUkdjMVJYZEhKa01XdDZZMFU1WVdGNlZuaFdWekZoVjIxV2MxTnFSbGhTUlRWUVZGVlZNVk5HVW5WVGJHeE9Za2QzZWxkVVNuZFVNREZ5VFVod1ZHRnRjems9`

**Solution:** Base64 decoded 4 times

**PowerShell:**
```powershell
$text = "VjJ0YWFrMVhUa2RoTTNCV1lsUkdjMVJYZEhKa01XdDZZMFU1WVdGNlZuaFdWekZoVjIxV2MxTnFSbGhTUlRWUVZGVlZNVk5HVW5WVGJHeE9Za2QzZWxkVVNuZFVNREZ5VFVod1ZHRnRjems9"
while ($true) {
    $text = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($text))
    Write-Host $text
    if (-not ($text -match '^[A-Za-z0-9+/=]+$')) { break }
}
```
Output
```
V2taak1XTkdhM3BWYlRGc1RXdHJkMWt6Y0U5YWF6VnhWVzFhV21Wc1NqRlhSRTVQVFVVMVNGUnVTbGxOYkd3eldUSndUMDFyTUhwVGFtczk=
WkZjMWNGa3pVbTFsTWtrd1kzcE9aazVxVW1aWmVsSjFXRE5PTUU1SFRuSllNbGwzWTJwT01rMHpTams9
ZFc1cFkzUm1lMkkwY3pOZk5qUmZZelJ1WDNOME5HTnJYMll3Y2pOMk0zSjk=
dW5pY3Rme2I0czNfNjRfYzRuX3N0NGNrX2YwcjN2M3J9
unictf{b4s3_64_c4n_st4ck_f0r3v3r}
```
so the flag is 
```
unictf{b4s3_64_c4n_st4ck_f0r3v3r}
```
