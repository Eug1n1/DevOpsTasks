# **Задача №4** Nginx + Apache + PHP + SSL

Нужно реализовать обратный прокси на базе NGINX, который будет проксировать запросы: 
•что-то на локальную машину
•что-то на другой порт
•что-то на другой сервер.

1. Зарегистрируйся на сайте: https://www.noip.com/
2. Разобраться в типах днс записей, и сделать днс запись типа А, для своего тестового сервера.
3. Затем используй 2 метода получения сертификатов для nginx.
4. Добавить редирект с 80 на 443 порт для всех подключений (cайт должен работать только по HTTPS).

В помощь:
- Letsencrypt
- webroot

Концепция такая:
- Я стучусь на сервер (NGINX) по 80 порту и должен видеть описание, что-то типа:
- Если вы хотите попасть на страницу с контентом 1, то нажмите сюда (и мы попадаем на другую страничку, которую обрабатывает этот же NGINX просто по другому порту или днс имени).
- Если вы хотите скачать файл с музыкой нажмите сюда и по ссылке ты качаешь mp3. (IP/music)
- Если нужен сервер, работающий на Apache+PHP нажмите сюда и по ссылке отдаётся информация о PHP сервере (IP/info.php)
- Если вы хотите получить респонс с другого сервера жмите сюда и тут ты видишь уже сайт который отдается не проксёй, а другим сервером (IP/secondserver)

# Code

### Creating SSL Certificate


```bash
# self-signed
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365
# using certbot
certbot --nginx # certbot automatic configure your server
# or
certbot certonly --nginx # certbot only generates certificate
```

### File Structure

```
/var/www/html:
    ./apache:
        ./index.php
        ./info.php
    ./app:
        ./fcontent.html
    ./ip:
        ./music:
            ./music.mp3
    ./index.html
```

### Nginx configs

```nginx
# /etc/nginx/sites-available/default

server {
        listen 443 ssl;
        listen [::]:443 ssl;
        server_name yakula.ddns.net;

        ssl_certificate /etc/letsencrypt/live/yakula.ddns.net/fullchain.pem;    # path to cert file
        ssl_certificate_key /etc/letsencrypt/live/yakula.ddns.net/privkey.pem;  # path to cert key file

        root /var/www/html;                     # define server root directory

        location / {                            # show main page
                try_files $uri $uri/ =404;
        }


        location /app {                         # proxing another nginx server
                proxy_set_header Host $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_pass http://localhost:8080/;
        }

        location /ip/music {                    # get .mp3 file
                index music.mp3;
                #return 200 $uri;
        }

        location /ip/info.php {                 # proxing apache server
                proxy_set_header Host $host;
                proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
                proxy_set_header X-Real-IP $remote_addr;
                proxy_pass http://localhost:8000/info.php;
        }

        location /ip/secondserver {             # redirecting to apache server
                return 301 http://yakula.ddns.net:8000; 
        }
}

server {
        if ($host = yakula.ddns.net) {          # if url address equal to our domain name, 
                                                # then redirect client to HTTPS server
                return 301 https://$server_name$request_uri;
        }


        listen 80 ;
        listen [::]:80;
        server_name yakula.ddns.net;

        return 404;                             # otherwise error
}

server {                                        # default server just to proxing him
        listen 8080;
        listen [::]:8080 ;
        server_name _;

        root /var/www/html/app;
        index fcontent.html;

        access_log /var/log/nginx/8080.log;


        location / {
                try_files $uri $uri/ =404;
        }
}

```

### Apache config

```apache
# /etc/apache/ports.conf
Listen 8000

<IfModule ssl_module>
        Listen 443
</IfModule>

<IfModule mod_gnutls.c>
        Listen 443
</IfModule>
```

```apache
# /etc/apache/sites-available/000-default.conf 
<VirtualHost *:8000>

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html/apache

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

</VirtualHost>
```

### Main Html Page

```html
# /var/www/html/index.html
<head>
        <meta charset="UTF-8">
</head>
<body bgcolor="#fff">
    <a href="/app">Если вы хотите попасть на страницу с контентом 1, то нажмите сюда</a>
    <hr>
    <a href="/ip/music" download>Если вы хотите скачать файл с музыкой нажмите сюда</a>
    <hr>
    <a href="/ip/info.php">Если нужен сервер, работающий на Apache+PHP нажмите сюда</a>
    <hr>
    <a href="/ip/secondserver">Если вы хотите получить респонс с другого сервера жмите сюда</a>
</body>
```

### PHP scripts


```php
# /var/www/html/apache/index.php
<?php
        echo "My first PHP script!";
?>
```

```php
# /var/www/html/apache/info.php
<?php
        phpinfo();
?>
```

# THEORY

## Nginx
- ("engine x") is an HTTP web server, reverse proxy, content cache, load balancer, TCP/UDP proxy server, and mail proxy server.
## SSL (Secure Sockets Layer)
- <div style="text-align: justify">an Internet security protocol that encrypts data to keep it safe.</div>
- <div style="text-align: justify"><b>Encryption:</b> SSL encrypts data transmitted over the web, ensuring privacy. If someone intercepts the data, they will see only a jumble of characters that is nearly impossible to decode.</div>
- <div style="text-align: justify"><b>Authentication:</b> SSL starts an authentication process called a handshake between two devices to confirm their identities, making sure both parties are who they claim to be.</div>
- <div style="text-align: justify"><b>Data Integrity:</b> SSL digitally signs data to ensure it hasn’t been tampered with, verifying that the data received is exactly what was sent by the sender.</div>

## TLS (Transpoert Layer Security)
- <div style="text-align: justify">is a cryptographic protocol designed to provide communications security over a computer network, such as the Internet. The protocol is widely used in applications such as email, instant messaging, and voice over IP, but its use in securing HTTPS remains the most publicly visible.</div>
- <div style="text-align: justify">The server usually then provides identification in the form of a digital certificate. The certificate contains the server name, the trusted certificate authority (CA) that vouches for the authenticity of the certificate, and the server's public encryption key.</div>
- To generate the session keys used for the secure connection, the client either:
    - <div style="text-align: justify">encrypts a random number (PreMasterSecret) with the server's public key and sends the result to the server (which only the server should be able to decrypt with its private key); both parties then use the random number to generate a unique session key for subsequent encryption and decryption of data during the session, or</div>
    - <div style="text-align: justify">uses Diffie–Hellman key exchange (or its variant elliptic-curve DH) to securely generate a random and unique session key for encryption and decryption that has the additional property of forward secrecy: if the server's private key is disclosed in future, it cannot be used to decrypt the current session, even if the session is intercepted and recorded by a third party.</div>

## PHP (PHP: Hypertext Preprocessor)
- <div style="text-align: justify">PHP is a general-purpose scripting language geared towards web development.</div>
- <div style="text-align: justify">PHP code is usually processed on a web server by a PHP interpreter implemented as a module, a daemon or a Common Gateway Interface (CGI) executable.</div>
- <div style="text-align: justify">PHP was originally an abbreviation of Personal Home Page, but it now stands for the recursive acronym PHP: Hypertext Preprocessor.</div>

## Apache
- <div style="text-align: justify">is a free and open-source cross-platform web server software.</div>

## CA (Certificate Authority) 
- <div style="text-align: justify">In cryptography, a certificate authority or certification authority (CA) is an entity that stores, signs, and issues digital certificates. A digital certificate certifies the ownership of a public key by the named subject of the certificate.</div>
- <div style="text-align: justify">The commercial CAs that issue the bulk of certificates for HTTPS servers typically use a technique called "domain validation" to authenticate the recipient of the certificate. The techniques used for domain validation vary between CAs, but in general domain validation techniques are meant to prove that the certificate applicant controls a given domain name, not any information about the applicant's identity.</div>

### Top CAs

<table class="wikitable">
<tbody><tr>
<th>Rank</th>
<th>Issuer</th>
<th>Usage</th>
<th>Market Share
</th></tr>
<tr>
<td>1</td>
<td><a href="/wiki/Let%27s_Encrypt" title="Let's Encrypt">Let's Encrypt</a></td>
<td>52.5%</td>
<td>56.3%
</td></tr>
<tr>
<td>2</td>
<td><a href="/wiki/GlobalSign" title="GlobalSign">GlobalSign</a></td>
<td>13.1%</td>
<td>14.0%
</td></tr>
<tr>
<td>3</td>
<td><a href="/wiki/IdenTrust" title="IdenTrust">IdenTrust</a></td>
<td>11.6%</td>
<td>12.4%
</td></tr>
<tr>
<td>4</td>
<td><a href="/wiki/Comodo_Cybersecurity" title="Comodo Cybersecurity">Comodo Cybersecurity</a></td>
<td>6.8%</td>
<td>7.3%
</td></tr>
<tr>
<td>5</td>
<td><a href="/wiki/DigiCert" title="DigiCert">DigiCert</a> Group</td>
<td>5.0%</td>
<td>5.3%
</td></tr>
<tr>
<td>6</td>
<td><a href="/wiki/GoDaddy" title="GoDaddy">GoDaddy</a> Group</td>
<td>4.2%</td>
<td>4.4%
</td></tr>
</tbody></table>




<table class="has-fixed-layout"><thead><tr><th class="has-text-align-center" data-align="center">RECORD TYPE</th><th>DESCRIPTION</th></tr></thead><tbody><tr><td class="has-text-align-center" data-align="center"><strong>A</strong></td><td>Maps a domain to an IPv4 address.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>AAAA</strong></td><td>Maps a domain to an IPv6 address.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>CNAME</strong></td><td>Aliases one domain name to another.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>MX</strong></td><td>Directs email to mail servers.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>NS</strong></td><td>Specifies the authoritative nameserver for a domain.</td></tr><tr><td class="has-text-align-center" data-align="center"><a href="https://phoenixnap.com/glossary/dns-soa" target="_blank" rel="noreferrer noopener">SOA</a></td><td>Contains administrative information about the domain, like the primary nameserver and zone update settings.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>TXT</strong></td><td>Stores text information, often used for verification.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>SRV</strong></td><td>Specifies a service location for certain services, like servers handling VoIP.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>PTR</strong></td><td>Maps an IP address to a domain name for <a href="https://phoenixnap.com/kb/reverse-dns-lookup" target="_blank" rel="noreferrer noopener">reverse DNS lookups</a>.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>AFSDB</strong></td><td class="has-text-align-left" data-align="left">Specifies the location of Andrew File System (AFS) cells.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>ATMA</strong></td><td class="has-text-align-left" data-align="left">Maps a domain name to an ATM address used for ATM networks.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>CAA</strong></td><td class="has-text-align-left" data-align="left">Specifies which <a href="https://phoenixnap.com/glossary/certificate-authority-ca" target="_blank" rel="noreferrer noopener">certificate authorities (CAs)</a> are allowed to issue certificates for a domain.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>CERT</strong></td><td class="has-text-align-left" data-align="left">Stores certificates and certificate-related information, such as public keys.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>DHCID</strong></td><td class="has-text-align-left" data-align="left">Used in DHCP to associate DNS names with dynamically assigned IP addresses.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>DNAME</strong></td><td class="has-text-align-left" data-align="left">Provides redirection of a subtree of the DNS namespace to another domain.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>DNSKEY</strong></td><td class="has-text-align-left" data-align="left">Contains public keys used to verify DNSSEC signatures.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>DS</strong></td><td class="has-text-align-left" data-align="left">Used in DNSSEC to identify a DNSKEY record in the delegated zone.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>HINFO</strong></td><td class="has-text-align-left" data-align="left">Provides information about the <a href="https://phoenixnap.com/glossary/what-is-hardware" target="_blank" rel="noreferrer noopener">hardware</a> and <a href="https://phoenixnap.com/glossary/operating-system" target="_blank" rel="noreferrer noopener">operating system</a> used by a <a href="https://phoenixnap.com/glossary/what-is-a-host" target="_blank" rel="noreferrer noopener">host</a>.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>ISDN</strong></td><td class="has-text-align-left" data-align="left">Stores ISDN addresses associated with a domain name.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>MB, MG, MINFO, MR</strong></td><td class="has-text-align-left" data-align="left">Legacy records related to mailbox information, with specific uses for mapping and informational purposes.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>NAPTR</strong></td><td class="has-text-align-left" data-align="left">Used for Uniform Resource Identifier (URI) and E.164 Number Mapping (ENUM) applications to define rules for rewriting domain names.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>NSAP</strong></td><td class="has-text-align-left" data-align="left">Maps a domain name to an NSAP address used in OSI networks.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>NSEC</strong></td><td class="has-text-align-left" data-align="left">Used in DNSSEC to prove the non-existence of a DNS record by listing the next record in the zone.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>NSEC3</strong></td><td class="has-text-align-left" data-align="left">An enhanced version of NSEC for DNSSEC that includes hashed domain names to prevent enumeration.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>NSEC3PARAM</strong></td><td class="has-text-align-left" data-align="left">Stores parameters for NSEC3 records, including <a href="https://phoenixnap.com/glossary/file-hash" target="_blank" rel="noreferrer noopener">hashing</a> algorithms and iterations.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>RP</strong></td><td class="has-text-align-left" data-align="left">Provides information about the person responsible for a domain, including contact details.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>RRSIG</strong></td><td class="has-text-align-left" data-align="left">Contains a cryptographic signature used to verify DNSSEC-signed data.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>RT</strong></td><td class="has-text-align-left" data-align="left">Specifies a route through a specific intermediate host, used for non-IP networks.</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>TLSA</strong></td><td class="has-text-align-left" data-align="left">Links a domain name with a <a href="https://phoenixnap.com/kb/what-is-an-ssl-certificate" target="_blank" rel="noreferrer noopener">TLS certificate</a>, used in DNS-based Authentication of Named Entities (DANE).</td></tr><tr><td class="has-text-align-center" data-align="center"><strong>X25</strong></td><td class="has-text-align-left" data-align="left">Stores an X.25 network address used in older <a href="https://phoenixnap.com/glossary/packet-switched-network" target="_blank" rel="noreferrer noopener">packet-switched networks</a>.</td></tr></tbody></table>