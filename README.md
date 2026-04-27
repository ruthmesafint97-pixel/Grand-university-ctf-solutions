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

**What I did:**

1. I looked at the ciphertext and noticed it had the format `xxxxx{...}` which looked like a flag.

2. The challenge name "C43SAR" looked like "CAESAR" with leet speak (4=A, 3=E), so I guessed it was a Caesar cipher.

3. I tried ROT13 on the first word `havpgs` and got `unictf` — that matched the flag format for this CTF.

4. So I applied ROT13 to all the letters in the ciphertext (A-Z becomes N-M, a-z becomes n-m).

5. The numbers inside stayed the same because they were already in leet format (0,3,4,1).

6. After decoding, I got `unictf{r0t4t3_unt1l_1t_m4k3s_s3ns3}`.

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
Write-Host $result
```
```
unictf{r0t4t3_unt1l_1t_m4k3s_s3ns3}
```

#### 2. 64ESAB (100 pts) - Base64

**Given:** `VjJ0YWFrMVhUa2RoTTNCV1lsUkdjMVJYZEhKa01XdDZZMFU1WVdGNlZuaFdWekZoVjIxV2MxTnFSbGhTUlRWUVZGVlZNVk5HVW5WVGJHeE9Za2QzZWxkVVNuZFVNREZ5VFVod1ZHRnRjems9`

**Solution:** Base64 decoded 4 times

**What I did:**

1. The challenge name "64ESAB" looked like "BASE64" spelled backwards, so I knew it was a Base64 challenge.

2. I tried decoding the given string once using Base64. It gave me another string that also looked like Base64.

3. I kept decoding again and again — each time the output still looked like Base64.

4. After decoding 4 times, I got a string that started with `unictf{` — that was the flag.

5. I decoded one more time just to be sure, and got the final flag.

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

#### 3. One Byte (200 pts) - Single XOR

**Given:** A file named `cipher.hex.txt` with this content: 
```
372c2b213624393a72301d3573362a1d722c711d203b36711d73311d357176293f
```

**What I did:**

1. First, I looked at the file contents. It was a long string of hex characters, numbers and letters from 0-9 and a-f.

2. I recognized this was likely a ciphertext encoded in hex, and since the challenge was called "One Byte", it probably meant the data was XORed with a single byte key.

3. I converted the hex string to raw bytes so I could work with it.

4. Then I brute forced all 256 possible single-byte keys (from 0 to 255). For each key, I XORed every byte and converted the result to text.

5. I filtered the output to only show results that contained "unictf" (the flag format for this CTF).

6. The correct result appeared with Key 66, giving me the flag.

**PowerShell command I used:**
```powershell
$hex = "372c2b213624393a72301d3573362a1d722c711d203b36711d73311d357176293f"
$bytes = [byte[]]::new($hex.Length / 2)
for ($i = 0; $i -lt $hex.Length; $i += 2) {
    $bytes[$i / 2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
}
0..255 | ForEach-Object {
    $key = $_
    $result = -join ($bytes | ForEach-Object { [char]($_ -bxor $key) })
    if ($result -match "unictf") { Write-Host "Key $key : $result" }
}
```
Flag: `unictf{x0r_w1th_0n3_byt3_1s_w34k}`
