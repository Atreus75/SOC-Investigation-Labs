# CVE-2024-49138 Exploitation Detected
Toda a investigação neste artigo gira em torno da resolução do alerta da [LetsDefend](https://app.letsdefend.io/monitoring) de regra **SOC335**, ID 313.
## Objetivo
Um alerta de *privilege escalation* foi disparado em 22/01/2025, se tratando de uma possível exploração do *CVE-2024-49138* contra o host de nome *Victor*. Segundo a mensagem do alerta: "*
Não usuais ou suspeitos padrões de comportamento ligados à hash foram identificadas, indicando potencial exploração do *CVE-2024-49138*". A investigação a seguir deve:
* identificar a veracidade do alerta;
* definir a superfície e nível de impacto do ataque;
* encontrar indicadores de comprometimento (IOCs);
* construir threat intelligence sobre o atacante.

## Dados do Alerta
* **Data e hora**: 22/01/2025 14:37
* **Hostname da vítima**: Victor
* **Hash de arquivo suspeito**: b432dcf4a0f0b601b1d79848467137a5e25cab5a0b7b1224be9d3b6540122db9
* **Nome do processo suspeito**: svohost.exe
* **Caminho do processo suspeito**: C:\temp\service_installer\svohost.exe
* **Usuário do processo suspeito**: EC2AMAZ-ILGVOIN\LetsDefend
* **Processo pai do processo suspeito**: C:\Windows\System32\WINDOWSPOWERSHELL\V1.0\powershell.exe
* **PID de processo suspeito**: 7640
* **Command line**: \??\C:\Windows\system32\conhost.exe 0xffffffff -ForceV1


## Investigação
### Threat Intelligence
Como triagem para pré-determinar a direção desta investigação, vamos utilizar fontes públicas de threat intelligence para obter informações sobre a hash obtida pelo sistema de segurança.<br>
<img width="1253" height="599" alt="image" src="https://github.com/user-attachments/assets/0c95eb2a-9418-412b-84a3-367695b52b95" />
<br>
A reputação deste arquivo no **VirusTotal** é altamente maliciosa. Com dados atualizados há apenas 15 dias, 50 detecções e a correspondência exata até mesmo do nome do arquivo são motivos suficientes para aprofundar a investigação.<br>
Foram encontrados *resources* em italiano no executável, o que pode indicar a origem geográfica do criador do malware.<br>
<img width="800" height="213" alt="image" src="https://github.com/user-attachments/assets/7f3b79a0-8f95-4fc6-bc08-09dc6201cbd3" /><br>
O arquivo carrega 10 outros arquivos empacotados dentro de si, além de contatar 100 IPs dos Estados Unidos.<br>
<img width="383" height="186" alt="image" src="https://github.com/user-attachments/assets/ff6a7411-f612-43ce-8580-475f7f9b2bc0" /><br>
<img width="581" height="202" alt="image" src="https://github.com/user-attachments/assets/ea3f1886-9fff-4bcc-8c68-332b82a05e12" /><br>
Por último mas não menos interessante, o ambiente sandbox do VirusTotal foi capaz de detectar capacidades maliciosas neste arquivo, o que vai nos ajudar a determinar o impacto do ataque.<br>
* carregar DLLs em tempo de execução: dificulta a análise estática das capacidades e funções presentes no arquivo.<br>
  <img width="153" height="214" alt="image" src="https://github.com/user-attachments/assets/fc60cdb8-3ab3-4d59-a4a9-9004f6a76f50" /><br>
* ler políticas de execução de software através do registro *HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Safer\CodeIdentifiers*: obtém informações sobre processos e suas permissões no sistema.<br>
<img width="466" height="91" alt="image" src="https://github.com/user-attachments/assets/fdf0039b-6e7c-4f48-993c-ec80a018af18" /><br>
* injeção de código em processos: utilizado para passar despercebido a quem analisa os processos do sistema buscando execuções maliciosas.<br>
<img width="449" height="167" alt="image" src="https://github.com/user-attachments/assets/195300db-f415-42bf-9b8b-97b92bf79f73" /><br>

<br>Além de tudo isto, pelo cabeçalho do arquivo **PE** obtivemos o caminho do arquivo *.pdb* (relativo a uma sessão de debugging) linkado ao malware: *C:\Users\LetsDefend\Downloads\CVE-2024-49138-POC-master\x64\Debug\CVE-2024-49138-POC.pdb*<br>
<img width="769" height="156" alt="image" src="https://github.com/user-attachments/assets/2c92a8df-549c-4e1f-86bd-36144e6e28bf" /><br>
Este caminho revela que o atacante utilizou um repositório com uma *PoC* (proof of concept) da *CVE-2024-49138*, baixado na pasta de Downloads do usuário atacado *LetsDefend*. Isto também acaba por confirmar a suspeita de exploração da *CVE* mencionada no alerta.<br>

### Análise do Endpoint
Todos os eventos se passam no dia 22/01/2025.<br><br>

Dadas as informações obtidas por threat intelligence acima, é crucial isolar o host *Victor* do restante da rede para assegurar que o atacante seja mal-sucedido em tentativas de pivoting.<br>
<img width="884" height="369" alt="image" src="https://github.com/user-attachments/assets/824b456c-f840-40f1-abd1-9db11faa34b7" /><br>
#### 14:36
O usuário *Victor* loga no sistema utilizando o Powershell.<br>
<img width="604" height="143" alt="image" src="https://github.com/user-attachments/assets/a8933aba-cfde-4955-bef5-fe0531342310" /><br>
Em seguida, verifica o usuário atual (*Victor*) e seus privilégios no sistema com o comando `whoami /priv`.<br>
<img width="501" height="126" alt="image" src="https://github.com/user-attachments/assets/77510095-9ce1-4f30-94ef-a8a833479aba" /><br>


O usuário *Victor* utiliza um script Powershell para acessar o servidor remoto malicioso *https://files-ld.s3.us-east-2.amazonaws.com/* e baixar o arquivo *service-installer.zip*, depois extraí-lo com a senha "infected" para *C:\temp\"e obter o malware *svohost.exe* analisado anteriormente. O passo final é a execução do malware, o que confirma que esta sessão do usuário *Victor* não está sendo utilizada pelo real dono da conta, mas sim pelo invasor que disparou o alerta.<br>
<img width="602" height="221" alt="image" src="https://github.com/user-attachments/assets/6983be9d-771d-4813-ba89-861bca6a6c79" /><br>
<img width="1277" height="196" alt="image" src="https://github.com/user-attachments/assets/8b8aaf74-b0be-491e-84c5-6eae696cf3b7" /><br>

#### 14:37
O exploit é executado, e uma janela gráfica do Powershell foi iniciada pelo usuário *SYSTEM*, a partir do processo *svohost.exe*, indicando que o exploit de privilege escalation foi executado com sucesso.<br>
<img width="675" height="219" alt="image" src="https://github.com/user-attachments/assets/4a71e555-bf4d-48e5-8116-65ee3099ccd5" /><br>
<img width="619" height="153" alt="image" src="https://github.com/user-attachments/assets/f8d64f0a-2ae6-405f-9bbb-79f3724f13bd" /><br>


O primeiro de seus comandos é justamente checar se o exploit de privilege escalation funcionou corretamente, ao rodar *whoami* para saber o nome do usuário atual:<br>
<img width="851" height="255" alt="image" src="https://github.com/user-attachments/assets/d2fe1caf-b2ef-44cd-912b-af24ad72353d" /><br>

