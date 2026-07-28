# Lab 04 - Persistência via Serviços
## Objetivo
Detectar uma tentativa de persistência que utilize serviços em ambiente Windows, utilizando Sysmon como gerador de eventos e Splunk como SIEM.

## Cenário Geral
Um atacante obteve acesso inicial ao host e executa tentativas de estabelecer persistência. Para isto, ele faz upload de executável e o salva como "*C:\Users\Lenovo\persistence.exe*". Logo após, executou o seguinte comando no Prompt de Comandos:
```bash
sc create Persistence binpath= C:\Users\Lenovo\persistence.exe start= auto
```
criando um serviço chamado "*Persistence*".
## Telemetria Gerada
### Primeiro Método de Detecção: Sysmon Event ID 1
Executar o comando citado anteriormente para criar o serviço dispara o evento "Process Creation" de ID 1 do Sysmon. Para detectar esta execução suspeita, basta procurar por eventos de criação de processo relacionados ao utilitário "*sc*":<br>
<img width="718" height="462" alt="image" src="https://github.com/user-attachments/assets/4a801de1-76f9-4f6f-b2f8-0580cc0f2a77" /><br>
A command line do evento comprova que é esta atividade que estamos buscando:<br>
<img width="512" height="87" alt="image" src="https://github.com/user-attachments/assets/2a07f8b6-d5c9-4cba-906b-ef2eec7fc432" /><br>
<br>
### Segundo Método de Detecção: Sysmon Event ID 13
Uma vez criado um serviço, alguns registros também são criados no sistema para garantir a execução e os direitos do mesmo após reboots e logouts. A modificação e criação de registros/Values no Windows dispara o evento de ID 13 do Sysmon. Uma query envolvendo modificações de registros atrelados aos serviços é capaz de mostrar o valor atrelado a um serviço suspeito:<br>
<img width="756" height="449" alt="image" src="https://github.com/user-attachments/assets/0194c2c0-b03b-477d-b7e1-8c0d2a5d20e2" /><br>
Os detalhes do evento confirmam nossa busca:<br>
<img width="703" height="574" alt="image" src="https://github.com/user-attachments/assets/f735e788-9707-407a-8149-93fc34113d6b" /><br>
<br><br>
O primeiro método é eficiente em captar a criação de serviços via *sc*/*cmd*. O segundo método no entanto consiste em uma busca mais geral acerca da criação de um serviço através de qualquer utilitário no sistema. O primeiro pode ser mais preciso e gerar menos falsos positivos embora seja específico demais, enquanto o segundo apesar de trazer um resultado mais poluído é sem dúvidas o método certeiro e definitivo para encontrar a criação de um serviço. 
## Investigação
### Quem Criou?
O evento encontrado pelo primeiro método de detecção revela que o usuário "*Lenovo*" foi utilizado para criar o serviço suspeito.<br>
<img width="835" height="249" alt="image" src="https://github.com/user-attachments/assets/a8bba585-c295-4bf2-8c45-5a43cd5b3572" /><br>
Entretanto, a execução deste script requer privilégios de administrador no sistema, e o usuário "Lenovo" é um usuário comum. Portanto, infere-se desta execução bem sucedida que o usuário *Administrador* foi utilizado.
### Quando Criou?
O horário marcado do mesmo evento nos diz que o horário de criação foi às 20:47 do dia 27/07/2026:<br>
<img width="369" height="64" alt="image" src="https://github.com/user-attachments/assets/362eb1d1-873d-4fe2-bcb0-96f1b3b9e710" /><br>
### Que Payload Será Executado?
O mesmo evento mostra que o executável configurado para executar é `C:\Users\Lenovo\persistence.exe`.<br>
<img width="495" height="77" alt="image" src="https://github.com/user-attachments/assets/60e2e26a-4f4f-450f-80c9-ebc3fed101bc" /><br>
#### Análise Estática
Utilizando o *CAPA* (software de engenharia reversa) para analisar as capacidades deste executável, obtive o seguinte output mostrando que o mesmo provavelmente se trata de um loader que performa a técnica de process injection para executar um shellcode:<br>
<img width="1007" height="593" alt="image" src="https://github.com/user-attachments/assets/9731d9af-8ccb-4634-9cb1-e730ff205ce7" /><br>
Algumas funções importadas no executável, utilizadas para acessar a memória e criar threads em outros processos, batem com o palpite do *CAPA*, como nos mostra o PE-Bear (analisador de metadados PE):<br>
<img width="656" height="454" alt="image" src="https://github.com/user-attachments/assets/769549b8-cc6f-4275-bbf6-d37a94e028ed" /><br>
Uma string presente no arquivo aponta que possivelmente o executável injecta seu shellcode malicioso no utilitário nativo do Windows "*Vincular ao Celular*". Além disto, uma outra string indica que *persistence.exe* faz uso da *ws2_32* (Winsocks 2), uma API de criação e gerenciamento de sockets, indicando que o shellcode em questão estabelece conexão remota via sockets.<br>
<img width="255" height="124" alt="image" src="https://github.com/user-attachments/assets/dc332e36-be2f-4d84-bfe8-b44f157cebae" /><br>
Finalmente, uma análise no **VirusTotal** reúne diversas assinaturas apontando que o shellcode utilizado pelo executável provavelmente foi gerado pelo Metasploit Framework:<br>
<img width="762" height="218" alt="image" src="https://github.com/user-attachments/assets/6c71f610-1288-43a7-94d8-8ce16c2cb219" /><br>
<img width="1188" height="434" alt="image" src="https://github.com/user-attachments/assets/67ec1080-b121-42f2-bbd8-7a27e8303ec0" /><br><br>
Esta rápida análise estática nos permite concluir que *persistence.exe* foi programado para iniciar uma conexão remota via sockets a partir de um shellcode do Metasploit, utilizando *process injection* para ocultar a execução do malware em um processo do "*PhoneExperienceHost.exe*" de modo a tentar evadir detecções.
### Quando Será Executado?
O primeiro evento detectado mostra que a execução do serviço é do tipo "auto", ou seja, a cada inicialização do sistema.<br>
<img width="525" height="84" alt="image" src="https://github.com/user-attachments/assets/316f3cc4-4514-4d6d-a764-06dd950b853e" />

### Oportunidades de Detecção
* Execução de *sc* para criação de serviços via prompt de comandos (extremamente suspeito).
* Criação do registro de *ImagePath* do serviço.
* Criação do arquivo **persistence.exe** no sistema de arquivos.
### Indicadores de Compromisso (IOCs)
* **Usuários comprometidos**: Lenovo e Administrador
* **Malware utilizado para persistência**: C:\Users\Lenovo\persistence.exe
* **Registro do serviço malicioso**: *HKLM\System\CurrentControlSet\Services\Persistence\Start* 
## Queries SPL Utilizadas
* Encontrar execuções de `sc create`:
        ```SPL
        index="main" EventID="1" sc create
        ```
* Encontrar modificações de registros ligados a serviços:
        ```SPL
        index="main" EventID="13" *Services* 
        ```
## Principais ATT&CK
* **T1543.003** - *Create or Modify System Process: Windows Service*
* **T1055.003** - *Process Injection: Thread Execution Hijacking*
## Falsos Positivos
Serviços legítimos podem gerar eventos do tipo do segundo método de detecção casualmente, pois é o funcionamento padrão do Windows para criar serviços. Além disto, usuários comuns podem empregar o utilitário *sc* no gerenciamento legítimo de serviços do sistema.
## Conclusão
O Sysmon e o Splunk são duas ótimas ferramentas para abstrair, em poucos logs, o evento de criação de serviços. Com eles podemos traçar o momento de criação e a frequência de execução do payload, que por sua vez deve ser encaminhado a um analista de malware para uma avaliação profunda de suas capacidades além de adquirir valiosos artefatos, possibilitando ações posteriores de threat hunting e incident response ao ataque.
