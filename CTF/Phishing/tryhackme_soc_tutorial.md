# SOC Simulation
## Alertas
### Primeiro Alerta
O primeiro alerta se trata de uma suspeita de phishing por email.<br>
<img width="983" height="392" alt="image" src="https://github.com/user-attachments/assets/c590a31b-857c-4996-8f7f-c5f5102ff805" /><br>
Parece uma mensagem de aviso para finalização da criação de uma conta.<br>
Procurando no Splunk por qualquer evento envolvendo esta URL, não encontrei nada que sugerisse acesso ao link ou outros tipos de interação. Apenas 2 resultados foram encontrados, ambos se tratando do mesmo email, porém enviados em momentos diferentes:<br>
<img width="1327" height="582" alt="image" src="https://github.com/user-attachments/assets/7805e526-f51f-4130-b8ab-7693426ea1bf" />
Fechei o alerta como **falso positivo**, pelo fato de não ter havido interação com a URL, e fontes de threat intelligence como a *VirusTotal* não possuírem registros sobre ela.<br>
<img width="997" height="463" alt="image" src="https://github.com/user-attachments/assets/d576188c-7cc5-4534-b28f-44c13235bcd9" /><br>
### Segundo Alerta
O segundo alerta tem o mesmo título do primeiro: se trata de um alerta relacionado à phishing por email. Desta vez, o *sender* de email *urgents@amazon.biz* alega que é necessário uma URL para corrigir informações de entrega de um pacote da **Amazon**.<br>
<img width="1047" height="473" alt="image" src="https://github.com/user-attachments/assets/c74a5368-33f8-498e-9c1a-bdf98e92c52c" /><br>
O *VirusTotal* mostra flags de **phishing** relacionadas à URL presente. Além disto, o domínio ***bit.ly*** é frequentemente utilizado para monetizar acessos à links.<br>
<img width="1299" height="479" alt="image" src="https://github.com/user-attachments/assets/88d06d26-2e6b-4887-adae-badccb8f4c18" /><br>
O Splunk aponta que houve uma tentativa de acesso à URL por um host, mas foi bloqueada pelo firewall.<br>
<img width="727" height="603" alt="image" src="https://github.com/user-attachments/assets/7e7030b1-3c7e-4623-ae71-8fe8adc489dd" /><br>
No report, incluí informações necessárias para justificar a confirmação como **positivo verdadeiro**, mas não é necessário escalação do alerta.<br>
<img width="994" height="543" alt="image" src="https://github.com/user-attachments/assets/38c69b35-2a93-40cd-acd3-debc77cc5902" /><br>
### Terceiro Alerta
Este alerta relaciona-se com o último, pois se trata especificamente da tentativa de acesso à URL contida no corpo do email de phishing: *http://bit.ly/3sHkX3da12340*. Como sabemos, a tentativa foi única e frustrada pelo firewall que já possuía a URL numa blacklist e foi capaz de impedir a efetivação do ataque de phishing.
#### Quarto Alerta
Mais um alerta relacionado à phishing, desta vez de um *sender* chamado **no-reply@m1crosoftsupport.co**. O domínio deste endereço de email possui o número "**1**" no lugar da letra "**i**" na palavra "*microsoft*": um truque tipicamente utilizado para criar domínios ilegítimos parecidos com os utilizados por grandes empresas legítimas.<br>
<img width="1038" height="468" alt="image" src="https://github.com/user-attachments/assets/aad19a7d-ee2b-4fc6-8866-1e010c18543f" /><br>
Há um link no corpo da mensagem que aponta para um site no domínio ilegítimo: **https://m1crosoftsupport.co/login**. Sendo uma página de login, o acesso de um usuário com credenciais reais de uma conta da Microsoft pode dar acesso à mesma ao atacante.<br>
O Splunk revelou um log do firewall que evidencia acesso ao link mencionado, o que caracteriza um bom motivo para escalar o alerta, visando averiguar a possibilidade de comprometimento de credenciais da vítima.<br>
<img width="1330" height="669" alt="image" src="https://github.com/user-attachments/assets/d0e7558e-6bac-452a-a1dc-635469cc956d" /><br>
<br>Pelo domínio enganoso e o acesso ao link de phishing, classifico este alerta como positivo verdadeiro.<br>
