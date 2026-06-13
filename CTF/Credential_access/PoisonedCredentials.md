# Poisoned Credentials Lab
https://cyberdefenders.org/blueteam-ctf-challenges/poisonedcredentials/

## Objetivo

A equipe de segurança detectou um aumento repentino na atividade suspeita da rede. Há preocupações de que ataques de envenenamento de LLMNR (Link-Local Multicast Name Resolution) e NBT-NS (NetBIOS Name Service) possam estar ocorrendo na rede. Esta investigação tem como objetivo analisar os logs de rede e examinar o tráfego de rede capturado.

----
## Investigação
### Análise dos Eventos (Timeline)
Todos os eventos datam de 21/10/2023
#### 20:27
Um broadcast NBNS e um multicast MDNS foram iniciados por 192.168.232.162 em sua subrede. Ambos requisitando o endereço que responde ao nome "fileshaare". O nome requisitado aparenta conter um erro de digitação, referenciando-se na verdade a "fileshare".<br>  
<img width="907" height="142" alt="image" src="https://github.com/user-attachments/assets/f930c3e8-7e62-4718-ade2-423e0ac56cdc" /><br>
Uma resposta vinda de 192.168.232.215 foi dada às queries enviadas anteriormente, apresentando-se como "localshaare.local". Esta resposta evidencia um aparente comportamento suspeito, ao tratar um nome supostamente incorreto ("localshaare" e não "localshare") como legítimo e referenciar a si mesmo como portador deste nome.<br>
<img width="771" height="38" alt="image" src="https://github.com/user-attachments/assets/cf0f6024-d2d1-4809-bf19-db3a36ff4089" /><br>
<img width="464" height="131" alt="image" src="https://github.com/user-attachments/assets/d0460e1b-08e8-46cf-9796-58f7dbf3eaa3" /><br>
#### 20:30
Um novo broadcast NBNS foi iniciado na rede, desta vez pelo host 192.168.232.176 requisitando o endereço que atende por "cybercactus".<br>
<img width="706" height="28" alt="image" src="https://github.com/user-attachments/assets/dc593c9c-8fd0-47c3-b837-fcec544eeaf8" /><br>
Desta vez, dois hosts respondem à query: 192.168.232.148 e 192.168.232.215, resultando em conflito de endereços.<br>
<img width="1012" height="82" alt="image" src="https://github.com/user-attachments/assets/1af86330-f8d3-4c5d-883e-355ab7345381" /><br>
Os logs mostram que isto se repete diversas vezes, até que apenas 192.168.232.215 responde, acabando com o conflito de endereços na rede em relação ao nome "cybercactus".<br>
<img width="788" height="41" alt="image" src="https://github.com/user-attachments/assets/6910a627-ff58-41d9-be4c-039c6563ee2f" /><br>
O host 192.168.232.176 inicia então um broadcast NBNS perguntando pelo nome "prinetr", e é respondido novamente por 192.168.232.215. O nome aqui mais uma vez aparenta conter um erro de digitação, refereciando-se na verdade a "printer". Este nome sugere que o host possivelmente se trata de uma impressora na rede.<br>
<img width="964" height="85" alt="image" src="https://github.com/user-attachments/assets/955dfa23-6546-419a-a11c-5324ba089f16" /><br>
A multiplicidade de nomes autoreferenciados pelo host 192.168.232.215 demonstra um forte indício de NBNS/LLMNR poisoning por parte do mesmo.
#### 20:33
Uma sessão SMB como usuário "janesmith" na máquina "AccountingPC" é requisitada por 192.168.232.215 a 192.168.232.176.<br>
<img width="811" height="63" alt="image" src="https://github.com/user-attachments/assets/475d1b7e-d76c-492c-9ec9-45bff60a94fc" /><br>
<img width="1254" height="314" alt="image" src="https://github.com/user-attachments/assets/6c05ea08-9541-4401-a935-87e29bbda205" /><br>
A mensagem final de resposta ao grupo de requisições feitas por 192.168.232.215 mostra que a sessão foi criada com sucesso. Os demais pacotes SMB foram então criptografados e o tráfego restante na captura não apresenta informações relevantes sobre o ataque.<br>
<img width="700" height="104" alt="image" src="https://github.com/user-attachments/assets/809b864a-0474-40d7-8a32-49e30e2f33fa" /><br>
<img width="744" height="61" alt="image" src="https://github.com/user-attachments/assets/3459684e-8e75-4eb3-9dd7-b474ca7a1b6a" /><br>

### Determinação de Impacto
O usuário "janesmith" bem como sua máquina "AccountingPC" foram comprometidas pelo invasor.
## IOCs Encontrados
* **IP de origem**: !92.168.232.215
* **Username afetado**: janesmith
* **Máquina afetada**: AccountingPC
## ATT&CKs
* **T1557**: Adversary in The Middle
* * NBNS/LLMNR poisoning utilizado na rede interna para roubar credenciais de usuário SMB.
* **T1078**
* * Credenciais legítimas utilizadas para acessar uma máquina da rede.
## Resultado da Investigação
O ataque abusou de uma falha de protocolo de rede para roubar credenciais de um usuário e performar movimento lateral na rede da empresa, aumentando seu alcance na mesma. Por isto, se classifica como **Positivo Verdadeiro**.
