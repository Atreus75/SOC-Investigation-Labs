# PsExec Hunt Lab
https://cyberdefenders.org/blueteam-ctf-challenges/psexec-hunt/
## Objetivo
Um alerta do Sistema de Detecção de Intrusão (IDS) sinalizou uma atividade suspeita de movimentação lateral envolvendo o PsExec. Isso indica um possível acesso não autorizado e movimentação pela rede. Como analista de SOC, sua tarefa é investigar o arquivo PCAP fornecido para rastrear as atividades do invasor. Identifique o ponto de entrada, as máquinas alvo, a extensão da violação e quaisquer indicadores críticos que revelem as táticas e os objetivos do invasor no ambiente comprometido.
## Investigação
### Análise dos Eventos (Timeline)
Todos os eventos datam de 11 de outubro de 2023.
### [07:42]
O host *10.0.0.130* inicia uma sequência de autenticação SMB contra o servidor *10.0.0.133*.<br>
<img width="710" height="139" alt="image" src="https://github.com/user-attachments/assets/4ee5d7dc-d199-464d-a0b0-dabacc294cad" />
<br>
Na sequência de pacotes, o host *10.0.0.130* requisita autenticação como usuário "*ssales*" no host "*HR-PC*", e é respondido com uma mensagem de "sucesso" pelo servidor.
<img width="680" height="295" alt="Captura de tela 2026-07-07 123205" src="https://github.com/user-attachments/assets/105b94d6-1421-4900-b9d4-27cf36b5f0a2" /><br>
<img width="480" height="148" alt="image" src="https://github.com/user-attachments/assets/f11bd743-c022-4d6d-ab7d-3adb9a92032e" /><br>
Autenticado, o host *10.0.0.130* acessa o share "*ADMIN$*" e cria o arquivo "*PSEXESVC.exe*".<br>
<img width="1177" height="145" alt="image" src="https://github.com/user-attachments/assets/5fbe30c8-67d1-45da-b863-e02cdf585db2" /><br>
[WIP]
