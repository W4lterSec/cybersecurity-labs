# 🔴 Red Team


[← Inicio](../README.md) · [Blue Team](../blue-team/README.md)


Writeups de máquinas y laboratorios de seguridad ofensiva.


## Máquinas completadas


| Máquina | Plataforma | Sistema | Dificultad | Técnicas | Estado |
| --- | --- | --- | --- | --- | --- |
| [BitB · Abrir writeup visual](https://w4ltersec.github.io/cybersecurity-labs/red-team/hackmyvm/bitb/BitB-Writeup.html) | HackMyVM | Linux / Ubuntu | — | BitB phishing · Artifactory PUT · cron RCE · reutilización de credenciales · LXD | ✅ Completada |
| [Government](hackmyvm/government/README.md) | HackMyVM | Linux / Ubuntu | — | SSRF · gopher · RCE · reutilización de credenciales · sudo.ws · command injection | ✅ Completada |
| [DC02](hackmyvm/dc02/README.md) | HackMyVM | Windows Server 2022 / AD | — | Kerberos · password spraying · AS-REP Roasting · Backup Operators · DCSync · Pass-the-Hash | ✅ Completada |
| [Banner](hackmyvm/banner/README.md) | HackMyVM | Linux / Debian | — | cookie del quiz · banner FTP · SSH · sshd_config escribible · sudo | ✅ Completada |
| [Earth](vulnhub/earth/README.md) | VulnHub | Linux / Fedora | Fácil (oficial) | vhosts · XOR · RCE autenticada · ingeniería inversa · SUID | ✅ Completada |
| [Aegis](hackmyvm/aegis/README.md) | HackMyVM | Linux | Media | rsync anónimo · HMAC en Git · pickle RCE · path traversal IPC · sudo/source | ✅ Completada |
| [MadLabs](hackmyvm/madlabs/README.md) | HackMyVM | Linux | Media | File upload bypass · RCE · PATH hijacking · inyección de comandos · clave SSH | ✅ Completada |


## Cómo se organiza


Una carpeta por plataforma y una subcarpeta por máquina. Cada writeup reúne reconocimiento, acceso inicial, escalada, evidencias y lecciones aprendidas.
