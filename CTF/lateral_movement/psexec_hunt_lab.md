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
Na sequência de pacotes, o host *10.0.0.130* requisita autenticação como usuário "*ssales*", no share "IPC$" do host "*HR-PC*", e é respondido com uma mensagem de "sucesso" pelo servidor.<br>
<img width="680" height="295" alt="Captura de tela 2026-07-07 123205" src="https://github.com/user-attachments/assets/105b94d6-1421-4900-b9d4-27cf36b5f0a2" /><br>
<img width="480" height="148" alt="image" src="https://github.com/user-attachments/assets/f11bd743-c022-4d6d-ab7d-3adb9a92032e" /><br>
Posteriormente, o host *10.0.0.130* acessa o share "*ADMIN$*" e cria o arquivo "*PSEXESVC.exe*". Tipicamente, o PsExec cria um executável de serviço com este mesmo nome "PSEXECSVC.exe" no share "ADMIN$" para que um host obtenha um prompt de comando remoto em outro host na mesma rede através do SMB.<br>
<img width="1177" height="145" alt="image" src="https://github.com/user-attachments/assets/5fbe30c8-67d1-45da-b863-e02cdf585db2" /><br>
O host *10.0.0.130* tenta autenticar-se anonimamente no servidor *10.0.0.133*, e esta a resposta do processo de autenticação do SMB revela o nome do host *10.0.0.133*:<br>
<img width="1064" height="378" alt="image" src="https://github.com/user-attachments/assets/c40c6ca1-4627-4cfb-a7ed-a9312984ac84" /><br>
O host em questão se chama "Sales-PC", ou "Vendas-PC".<br>
### [07:46]
O host *10.0.0.130* inicia mais uma sequência de autenticação SMB, desta vez para o servidor *10.0.0.131*. Muito provavelmente, se trata de mais uma tentativa de movimentação lateral na rede.<br>
<img width="990" height="248" alt="image" src="https://github.com/user-attachments/assets/45bb3134-eee3-4662-922c-0cc7e6a0fcb2" /><br>
As mensagens de autenticação mostraram que o host *10.0.0.131* possui o nome "Marketing-PC", e que permitiu autenticação como usuário "IEUser".<br>
<img width="763" height="259" alt="image" src="https://github.com/user-attachments/assets/213cef50-7df3-4615-bd02-bdb5d0dbf9c7" />

## Determinação de Impacto
Houve um alto impacto na rede durante o ataque, com o comprometimento de 2 máquinas e 2 contas de usuário.
## IOCs Encontrados
* **IP do Atacante**: 10.0.0.130
* **Contas Comprometidas:**:
  * ssales
  * IEUser
* **Hosts Comprometidos**
* * **Sales-PC**
  * **Marketing-PC**
## ATT&CK
* T1021: Remote Services. PsExec e SMB são serviços remotos legítimos que foram utilizados para controle não autorizado das máquinas afetadas.
* T1078: Valid Accounts. Credenciais de contas válidas foram obtidas pelo atacante e utilizadas no ataque.

## Resultado da Investigação
O ataque se resume a um *lateral movement* na rede comprometida por PsExec e SMB, utilizando credenciais de usuários legítimos. Por isto, se classifica como **Positivo Verdadeiro**.
