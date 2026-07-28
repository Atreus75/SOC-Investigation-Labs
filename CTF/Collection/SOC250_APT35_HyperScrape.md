# SOC250 - APT35 HyperScrape Data Exfiltration Tool Detected
Alerta do Lets Defend: https://app.letsdefend.io/monitoring
## Objetivo
Um alerta foi disparado dizendo que o famoso grupo Charming Kitten, ligado ao Irã, utilizou uma nova ferramenta para rouba e-mails de suas vítimas. O objetivo desta investigação é coletar informações sobre o ataque, sobre o atacante e determinar o impacto gerado sobre os alvos.

## Dados do Alerta
* **Hora do Ataque**: 27 de dezembro de 2023, 11:22 AM
* **Hostname do alvo afetado**: Arthur
* **IP do alvo**: 172.16.17.72
* **Nome do Processo**: EmailDownloader.exe
* **Caminho do Processo** : C:\Users\LetsDefend\Downloads\EmailDownloader.exe
* **Processo pai**: C:\Windows\Explorer.EXE
* **Command line**: C:\Users\LetsDefend\Downloads\EmailDownloader.exe
* **Hash do arquivo**: cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa
## Triage Inicial
Para avaliar a prioridade de análise deste alerta, podemos enviar a hash encontrada para o VirusTotal, e ver que tipo de Threat Intelligence já foi gerado sobre o arquivo.<br>
<img width="1298" height="310" alt="image" src="https://github.com/user-attachments/assets/6909f0b4-a0d4-459b-be70-9de50fc5640c" /><br>
Cinquenta fontes apontaram que o arquivo em questão é malicioso, e isto é mais do que uma justificativa para prosseguir com a análise.

## Investigação
### Threat Intelligence
Prosseguindo com a análise da Threat Intelligence gerada pelo VirusTotal, o executável ativou uma regra da CrowdStrike que confirma a informação presente no alerta: o arquivo de fato se trata da ferramental Hyprscrape de extração de emails.<br>
<img width="899" height="152" alt="image" src="https://github.com/user-attachments/assets/93fef8a0-73dc-4d64-be20-493c45f01d94" /><br>

Na aba de relações é revelado que o malware se conecta a uma URL detectada por 8 fontes públicas de inteligência como *command and control* .<br>e
<img width="807" height="300" alt="image" src="https://github.com/user-attachments/assets/b25f12c7-e426-409f-bdf4-21636f32dc8d" /><br><br>
O endereço IP - nativo da Alemanha - por sua vez parece ser frequentemente utilizado para ataques de phishing.<br>
<img width="1253" height="512" alt="image" src="https://github.com/user-attachments/assets/970198e9-0046-4201-bc08-ee6ac7d25023" /><br>

Analisando as capacidades do executável, descobrimos que uma das técnicas empregadas pelo malware para se esconder no sistema é o *Process Injection*, onde o malware injeta código malicioso em outro processo já em execução para evadir detecções do antivírus. Além disto, muitas outras técnicas de ofuscação são observadas embora este não seja um artigo de malware analysis especificamente.<br>
<img width="1279" height="499" alt="image" src="https://github.com/user-attachments/assets/5f9d5c57-b135-4298-8cfd-d878782df22f" /><br>
### Análise do Endpoint
#### 11:21
Agora que temos informações que confirmam o alto nível de ameaça do executável encontrado na máquina "Arthur", a primeira coisa a se fazer no **EDR** é isolar o host da rede.<br>
<img width="902" height="376" alt="image" src="https://github.com/user-attachments/assets/3f054963-bf42-4589-a62b-a8f38fd84740" /><br><br>
A seguir, o histórico de processos do host mostra que o malware encontrado foi executado a partir do *explorer.exe* (o gerenciador de arquivos do Windows), às 11:21 de 27/12.<br>
<img width="629" height="292" alt="image" src="https://github.com/user-attachments/assets/2a6a4621-2be3-4f78-b386-1be57d498f08" /><br>

### Análise de Logs
#### 11:17
Um host de IP *173.209.51.54* teve uma conexão barrada pelo firewall com o host *Arthur*, contra a porta 3389 tipicamente utilizada por servidores *RDP*.<br>
<img width="455" height="285" alt="image" src="https://github.com/user-attachments/assets/5f911256-c56d-4647-adca-f4908231deb6" /><br>
<br>
O IP do host que tentou se conectar possui má reputação no VirusTotal e pertence a uma ISP canadense.<br>
<img width="1293" height="501" alt="image" src="https://github.com/user-attachments/assets/ce3572d3-433e-413e-b3ac-1148ffa8c231" /><br>

O host de IP *173.209.51.54* logou interativamente na máquina *Arthur*, obtendo acesso visual à área de trabalho.<br> 
<img width="659" height="339" alt="image" src="https://github.com/user-attachments/assets/0944f1d0-38e1-449e-b9bf-5fa407e4b971" /><br>

#### 11:21
Um dos logs ligados ao host "Arthur" registrou uma requisição de download de emails pertencentes a *arthur@letsdefend.io*, para o mail server de IP *172.16.20.3*. Uma mensagem de aviso no evento alerta para o download simultâneo de múltiplos emails.<br>
<img width="761" height="418" alt="image" src="https://github.com/user-attachments/assets/261a281d-5f62-4481-babe-959d785f337e" /><br>
<img width="386" height="278" alt="image" src="https://github.com/user-attachments/assets/41db350e-1ab0-48cf-8d7a-25ddeb8e078e" /><br>

Não existem mais logs relevantes.
 ### Determinação de Impacto
 Os entes impactados foram o usuário *Arthur*, a máquina *Arthur* e o email *arthur@letsdefend.io*. Todos comprometidos por um malware da inteligência iraniana.
 ### IOCs (Indicadores de Compromisso)
 * **Usuário comprometido**: Arthur
 * **Máquina comprometida**: 172.16.17.72
 * **IP do atacante**: 173.209.51.54
 * **Stealer utilizado no ataque**:  C:\Users\LetsDefend\Downloads\EmailDownloader.exe
 * **Hash do stealer**: cd2ba296828660ecd07a36e8931b851dda0802069ed926b3161745aae9aa6daa
 * **Email empresarial comprometido**: arthur@letsdefend.io
### ATT&CK
* **T1078**: Valid Accounts
* **T1133**: External Remote Services
* **T1114**: Email collection
## Conclusão
O incidente se mostrou ser um bem sucedido ataque contra o usuário *Arthur*, roubando suas informações utilizando um malware de última geração desenvolvido por uma entidade estatal. A investigação provou que o alerta se trata de um **positivo verdadeiro**.
