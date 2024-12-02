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

<table class="wikitable sortable jquery-tablesorter">

<thead><tr>
<th class="headerSort" tabindex="0" role="columnheader button" title="Sort ascending">Type
</th>
<th class="headerSort" tabindex="0" role="columnheader button" title="Sort ascending">Type id (decimal)
</th>
<th width="90pt" class="headerSort" tabindex="0" role="columnheader button" title="Sort ascending">Defining RFC
</th>
<th class="headerSort" tabindex="0" role="columnheader button" title="Sort ascending">Description
</th>
<th class="headerSort" tabindex="0" role="columnheader button" title="Sort ascending">Function
</th></tr></thead><tbody>
<tr>
<td><div id="A"></div>A
</td>
<td>1
</td>
<td>RFC 1035<sup id="cite_ref-RFC1035_page-12_1-0" class="reference"><a href="#cite_note-RFC1035_page-12-1"><span class="cite-bracket">[</span>1<span class="cite-bracket">]</span></a></sup>
</td>
<td>Address record</td>
<td>Returns a 32-bit <a href="/wiki/IPv4" title="IPv4">IPv4</a> address, most commonly used to map <a href="/wiki/Hostname" title="Hostname">hostnames</a> to an IP address of the host, but it is also used for <a href="/wiki/DNSBL" class="mw-redirect" title="DNSBL">DNSBLs</a>, storing <a href="/wiki/Subnet_mask" class="mw-redirect" title="Subnet mask">subnet masks</a> in RFC 1101, etc.
</td></tr>
<tr>
<td><div id="AAAA"></div>AAAA
</td>
<td>28
</td>
<td>RFC 3596<sup id="cite_ref-2" class="reference"><a href="#cite_note-2"><span class="cite-bracket">[</span>2<span class="cite-bracket">]</span></a></sup>
</td>
<td><a href="/wiki/IPv6" title="IPv6">IPv6</a> address record</td>
<td>Returns a 128-bit <a href="/wiki/IPv6" title="IPv6">IPv6</a> address, most commonly used to map <a href="/wiki/Hostname" title="Hostname">hostnames</a> to an IP address of the host.
</td></tr>
<tr>
<td><div id="AFSDB"></div>AFSDB
</td>
<td>18
</td>
<td>RFC 1183
</td>
<td>AFS database record
</td>
<td>Location of database servers of an <a href="/wiki/Andrew_File_System" title="Andrew File System">AFS</a> cell. This record is commonly used by AFS clients to contact AFS cells outside their local domain. A subtype of this record is used by the obsolete <a href="/wiki/DCE_Distributed_File_System" title="DCE Distributed File System">DCE/DFS</a> file system.
</td></tr>
<tr>
<td><div id="APL"></div>APL
</td>
<td>42
</td>
<td>RFC 3123
</td>
<td>Address Prefix List
</td>
<td>Specify lists of address ranges, e.g. in <a href="/wiki/Classless_Inter-Domain_Routing" title="Classless Inter-Domain Routing">CIDR</a> format, for various address families. Experimental.
</td></tr>
<tr>
<td><div id="CAA"></div><a href="/wiki/CAA_record" class="mw-redirect" title="CAA record">CAA</a>
</td>
<td>257
</td>
<td>RFC 6844</a>
</td>
<td>Certification Authority Authorization
</td>
<td><a href="/wiki/DNS_Certification_Authority_Authorization" title="DNS Certification Authority Authorization">DNS Certification Authority Authorization</a>, constraining acceptable CAs for a host/domain
</td></tr>
<tr>
<td><div id="CDNSKEY"></div>CDNSKEY
</td>
<td>60
</td>
<td>RFC 7344
</td>
<td>
</td>
<td>Child copy of DNSKEY record, for transfer to parent
</td></tr>
<tr>
<td><div id="CDS"></div>CDS
</td>
<td>59
</td>
<td>RFC 7344
</td>
<td>Child DS
</td>
<td>Child copy of DS record, for transfer to parent
</td></tr>
<tr>
<td><div id="CERT"></div>CERT</td>
<td>37</td>
<td>RFC 4398</td>
<td>Certificate record</td>
<td>Stores <a href="/wiki/PKIX" class="mw-redirect" title="PKIX">PKIX</a>, <a href="/wiki/SPKI" class="mw-redirect" title="SPKI">SPKI</a>, <a href="/wiki/Pretty_Good_Privacy" title="Pretty Good Privacy">PGP</a>, etc.
</td></tr>
<tr>
<td><a href="/wiki/CNAME_record" title="CNAME record">CNAME</a>
</td>
<td>5
</td>
<td><a rel="nofollow" class="external text" href="https://datatracker.ietf.org/doc/html/rfc1035#page-12">RFC 1035</a><sup id="cite_ref-RFC1035_page-12_1-1" class="reference"><a href="#cite_note-RFC1035_page-12-1"><span class="cite-bracket">[</span>1<span class="cite-bracket">]</span></a></sup>
</td>
<td><a href="/wiki/Canonical_name_record" class="mw-redirect" title="Canonical name record">Canonical name record</a></td>
<td>Alias of one name to another: the DNS lookup will continue by retrying the lookup with the new name.
</td></tr>
<tr>
<td><div id="CSYNC"></div>CSYNC
</td>
<td>62
</td>
<td>RFC 7477
</td>
<td>Child-to-Parent Synchronization
</td>
<td>Specify a synchronization mechanism between a child and a parent DNS zone. Typical example is declaring the same NS records in the parent and the child zone
</td></tr>
<tr>
<td><div id="DHCID"></div>DHCID</td>
<td>49</td>
<td>RFC 4701</td>
<td>DHCP identifier</td>
<td>Used in conjunction with the FQDN option to <a href="/wiki/DHCP" class="mw-redirect" title="DHCP">DHCP</a>
</td></tr>
<tr>
<td><div id="DLV"></div>DLV</td>
<td>32769</td>
<td>RFC 4431</td>
<td>DNSSEC Lookaside Validation record</td>
<td>For publishing <a href="/wiki/DNSSEC" class="mw-redirect" title="DNSSEC">DNSSEC</a> trust anchors outside of the DNS delegation chain.  Uses the same format as the DS record. RFC 5074 describes a way of using these records.
</td></tr>
<tr>
<td><div id="DNAME"></div><a href="/wiki/DNAME_record" class="mw-redirect" title="DNAME record">DNAME</a>
</td>
<td>39
</td>
<td>RFC 6672
</td>
<td>Delegation name record</td>
<td>Alias for a name and all its subnames, unlike CNAME, which is an alias for only the exact name. Like a CNAME record, the DNS lookup will continue by retrying the lookup with the new name.
</td></tr>
<tr>
<td><div id="DNSKEY"></div><a href="/wiki/DNSKEY" class="mw-redirect" title="DNSKEY">DNSKEY</a></td>
<td>48</td>
<td>RFC 4034</td>
<td>DNS Key record</td>
<td>The key record used in <a href="/wiki/DNSSEC" class="mw-redirect" title="DNSSEC">DNSSEC</a>. Uses the same format as the KEY record.
</td></tr>
<tr>
<td><div id="DS"></div>DS</td>
<td>43</td>
<td>RFC 4034</td>
<td>Delegation signer</td>
<td>The record used to identify the DNSSEC signing key of a delegated zone
</td></tr>
<tr>
<td>EUI48</td>
<td>108</td>
<td>RFC 7043</td>
<td><a href="/wiki/Mac_address" class="mw-redirect" title="Mac address">MAC address (EUI-48)</a></td>
<td>A 48-bit IEEE Extended Unique Identifier.
</td></tr>
<tr>
<td>EUI64</td>
<td>109</td>
<td>RFC 7043</td>
<td><a href="/wiki/Mac_address" class="mw-redirect" title="Mac address">MAC address (EUI-64)</a></td>
<td>A 64-bit IEEE Extended Unique Identifier.
</td></tr>
<tr>
<td><div id="HINFO"></div>HINFO</td>
<td>13</td>
<td>RFC 8482</td>
<td>Host Information</td>
<td>Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY
</td></tr>
<tr>
<td><div id="HIP"></div><a href="/wiki/Host_Identity_Protocol" title="Host Identity Protocol">HIP</a>
</td>
<td>55
</td>
<td>RFC 8005
</td>
<td><a href="/wiki/Host_Identity_Protocol" title="Host Identity Protocol">Host Identity Protocol</a>
</td>
<td>Method of separating the end-point identifier and locator roles of IP addresses.
</td></tr>
<tr>
<td><div id="HTTPS"></div>HTTPS
</td>
<td>65
</td>
<td><a rel="nofollow" class="external text" href="https://datatracker.ietf.org/doc/rfc9460/?include_text=1">RFC 9460</a>
</td>
<td>HTTPS Binding
</td>
<td>RR that improves performance for clients that need to resolve many resources to access a domain.
</td></tr>
<tr>
<td><div id="IPSECKEY"></div>IPSECKEY</td>
<td>45</td>
<td>RFC 4025</td>
<td>IPsec Key</td>
<td>Key record that can be used with <a href="/wiki/IPsec" title="IPsec">IPsec</a>
</td></tr>
<tr>
<td><div id="KEY"></div>KEY</td>
<td>25</td>
<td>RFC 2535<sup id="cite_ref-3" class="reference"><a href="#cite_note-3"><span class="cite-bracket">[</span>3<span class="cite-bracket">]</span></a></sup> and RFC 2930<sup id="cite_ref-rfc3445_sec1_def_4-0" class="reference"><a href="#cite_note-rfc3445_sec1_def-4"><span class="cite-bracket">[</span>4<span class="cite-bracket">]</span></a></sup></td>
<td>Key record</td>
<td>Used only for SIG(0) (RFC 2931) and TKEY (RFC 2930).<sup id="cite_ref-5" class="reference"><a href="#cite_note-5"><span class="cite-bracket">[</span>5<span class="cite-bracket">]</span></a></sup> RFC 3445 eliminated their use for application keys and limited their use to DNSSEC.<sup id="cite_ref-rfc3445_sec1_subtype_6-0" class="reference"><a href="#cite_note-rfc3445_sec1_subtype-6"><span class="cite-bracket">[</span>6<span class="cite-bracket">]</span></a></sup> RFC 3755 designates DNSKEY as the replacement within DNSSEC.<sup id="cite_ref-rfc3755_sec3_7-0" class="reference"><a href="#cite_note-rfc3755_sec3-7"><span class="cite-bracket">[</span>7<span class="cite-bracket">]</span></a></sup> RFC 4025 designates IPSECKEY as the replacement for use with IPsec.<sup id="cite_ref-8" class="reference"><a href="#cite_note-8"><span class="cite-bracket">[</span>8<span class="cite-bracket">]</span></a></sup>
</td></tr>
<tr>
<td><div id="KX"></div>KX
</td>
<td>36
</td>
<td>RFC 2230
</td>
<td>Key Exchanger record
</td>
<td>Used with some cryptographic systems (not including DNSSEC) to identify a key management agent for the associated domain-name.  Note that this has nothing to do with DNS Security.  It is Informational status, rather than being on the IETF standards-track.  It has always had limited deployment, but is still in use.
</td></tr>
<tr>
<td><a href="/wiki/LOC_record" title="LOC record">LOC</a>
</td>
<td>29
</td>
<td>RFC 1876
</td>
<td>Location record
</td>
<td>Specifies a geographical location associated with a domain name
</td></tr>
<tr>
<td><a href="/wiki/MX_record" title="MX record">MX</a>
</td>
<td>15
</td>
<td><a rel="nofollow" class="external text" href="https://datatracker.ietf.org/doc/html/rfc1035#page-12">RFC 1035</a><sup id="cite_ref-RFC1035_page-12_1-2" class="reference"><a href="#cite_note-RFC1035_page-12-1"><span class="cite-bracket">[</span>1<span class="cite-bracket">]</span></a></sup> and RFC 7505
</td>
<td>Mail exchange record
</td>
<td>List of mail exchange servers that accept email for a domain
</td></tr>
<tr>
<td><a href="/wiki/NAPTR_record" title="NAPTR record">NAPTR</a>
</td>
<td>35
</td>
<td>RFC 3403
</td>
<td>Naming Authority Pointer
</td>
<td>Allows regular-expression-based rewriting of domain names which can then be used as <a href="/wiki/URI" class="mw-redirect" title="URI">URIs</a>, further domain names to lookups, etc.
</td></tr>
<tr>
<td><div id="NS"></div>NS
</td>
<td>2
</td>
<td><a rel="nofollow" class="external text" href="https://datatracker.ietf.org/doc/html/rfc1035#page-12">RFC 1035</a><sup id="cite_ref-RFC1035_page-12_1-3" class="reference"><a href="#cite_note-RFC1035_page-12-1"><span class="cite-bracket">[</span>1<span class="cite-bracket">]</span></a></sup>
</td>
<td>Name server record
</td>
<td>Delegates a <a href="/wiki/DNS_zone" title="DNS zone">DNS zone</a> to use the given <a href="/wiki/Authoritative_name_server" class="mw-redirect" title="Authoritative name server">authoritative name servers</a>
</td></tr>
<tr>
<td><div id="NSEC"></div>NSEC</td>
<td>47</td>
<td>RFC 4034</td>
<td>Next Secure record</td>
<td>Part of DNSSEC—used to prove a name does not exist. Uses the same format as the (obsolete) NXT record.
</td></tr>
<tr>
<td><div id="NSEC3"></div>NSEC3</td>
<td>50</td>
<td>RFC 5155</td>
<td>Next Secure record version 3</td>
<td>An extension to DNSSEC that allows proof of nonexistence for a name without permitting zonewalking
</td></tr>
<tr>
<td><div id="NSEC3PARAM"></div>NSEC3PARAM</td>
<td>51</td>
<td>RFC 5155</td>
<td>NSEC3 parameters</td>
<td>Parameter record for use with NSEC3
</td></tr>
<tr>
<td>OPENPGPKEY
</td>
<td>61
</td>
<td>RFC 7929
</td>
<td>OpenPGP public key record
</td>
<td>A <a href="/wiki/DNS-based_Authentication_of_Named_Entities" title="DNS-based Authentication of Named Entities">DNS-based Authentication of Named Entities</a> (DANE) method for publishing and locating OpenPGP public keys in DNS for a specific email address using an OPENPGPKEY DNS resource record.
</td></tr>
<tr>
<td><div id="PTR"></div>PTR
</td>
<td>12
</td>
<td><a rel="nofollow" class="external text" href="https://datatracker.ietf.org/doc/html/rfc1035#page-12">RFC 1035</a><sup id="cite_ref-RFC1035_page-12_1-4" class="reference"><a href="#cite_note-RFC1035_page-12-1"><span class="cite-bracket">[</span>1<span class="cite-bracket">]</span></a></sup>
</td>
<td><a href="/w/index.php?title=PTR_Resource_Record&amp;action=edit&amp;redlink=1" class="new" title="PTR Resource Record (page does not exist)">PTR Resource Record</a><span class="noprint" style="font-size:85%; font-style: normal;">&nbsp;[<a href="https://de.wikipedia.org/wiki/PTR_Resource_Record" class="extiw" title="de:PTR Resource Record">de</a>]</span>
</td>
<td>Pointer to a <a href="/wiki/Canonical_name" class="mw-redirect" title="Canonical name">canonical name</a>. Unlike a CNAME, DNS processing stops and just the name is returned.  The most common use is for implementing <a href="/wiki/Reverse_DNS_lookup" title="Reverse DNS lookup">reverse DNS lookups</a>, but other uses include such things as <a href="/wiki/DNS-SD" class="mw-redirect" title="DNS-SD">DNS-SD</a>.
</td></tr>
<tr>
<td><div id="RP"></div>RP</td>
<td>17</td>
<td>RFC 1183</td>
<td>Responsible Person</td>
<td>Information about the responsible person(s) for the domain. Usually an email address with the @ replaced by a .
</td></tr>
<tr>
<td><div id="RRSIG"></div>RRSIG</td>
<td>46</td>
<td>RFC 4034</td>
<td>DNSSEC signature</td>
<td>Signature for a DNSSEC-secured record set. Uses the same format as the SIG record.
</td></tr>
<tr>
<td><div id="SIG"></div>SIG</td>
<td>24</td>
<td>RFC 2535</td>
<td>Signature</td>
<td>Signature record used in SIG(0) (RFC 2931) and TKEY (RFC 2930).<sup id="cite_ref-rfc3755_sec3_7-1" class="reference"><a href="#cite_note-rfc3755_sec3-7"><span class="cite-bracket">[</span>7<span class="cite-bracket">]</span></a></sup> RFC 3755 designated RRSIG as the replacement for SIG for use within DNSSEC.<sup id="cite_ref-rfc3755_sec3_7-2" class="reference"><a href="#cite_note-rfc3755_sec3-7"><span class="cite-bracket">[</span>7<span class="cite-bracket">]</span></a></sup>
</td></tr>
<tr id="SMIMEA">
<td>SMIMEA
</td>
<td>53
</td>
<td>RFC 8162<sup id="cite_ref-RFC8162_section-2_9-0" class="reference"><a href="#cite_note-RFC8162_section-2-9"><span class="cite-bracket">[</span>9<span class="cite-bracket">]</span></a></sup>
</td>
<td>S/MIME cert association<sup id="cite_ref-IANA_DNS_Parameters_10-0" class="reference"><a href="#cite_note-IANA_DNS_Parameters-10"><span class="cite-bracket">[</span>10<span class="cite-bracket">]</span></a></sup>
</td>
<td>Associates an S/MIME certificate with a domain name for sender authentication.
</td></tr>
<tr id="SOA">
<td><a href="/wiki/SOA_record" title="SOA record">SOA</a>
</td>
<td>6
</td>
<td><a rel="nofollow" class="external text" href="https://datatracker.ietf.org/doc/html/rfc1035#page-12">RFC 1035</a><sup id="cite_ref-RFC1035_page-12_1-5" class="reference"><a href="#cite_note-RFC1035_page-12-1"><span class="cite-bracket">[</span>1<span class="cite-bracket">]</span></a></sup> and RFC 2308<sup id="cite_ref-11" class="reference"><a href="#cite_note-11"><span class="cite-bracket">[</span>11<span class="cite-bracket">]</span></a></sup>
</td>
<td>Start of [a zone of] authority record
</td>
<td>Specifies <i>authoritative</i> information about a <a href="/wiki/DNS_zone" title="DNS zone">DNS zone</a>, including the primary name server, the email of the domain administrator, the domain serial number, and several timers relating to refreshing the zone.
</td></tr>
<tr>
<td><a href="/wiki/SRV_record" title="SRV record">SRV</a>
</td>
<td>33
</td>
<td>RFC 2782
</td>
<td>Service locator
</td>
<td>Generalized service location record, used for newer protocols instead of creating protocol-specific records such as MX.
</td></tr>
<tr>
<td><div id="SSHFP"></div><a href="/wiki/SSHFP_record" title="SSHFP record">SSHFP</a>
</td>
<td>44
</td>
<td>RFC 4255
</td>
<td>SSH Public Key Fingerprint
</td>
<td>Resource record for publishing <a href="/wiki/Secure_Shell" title="Secure Shell">SSH</a> public host key fingerprints in the DNS, in order to aid in verifying the authenticity of the host. RFC 6594 defines <a href="/wiki/Elliptic-curve_cryptography" title="Elliptic-curve cryptography">ECC</a> SSH keys and SHA-256 hashes. See the <a rel="nofollow" class="external text" href="https://www.iana.org/assignments/dns-sshfp-rr-parameters/dns-sshfp-rr-parameters.xml">IANA SSHFP RR parameters registry</a> for details.
</td></tr>
<tr>
<td><div id="SVCB"></div>SVCB
</td>
<td>64
</td>
<td><a rel="nofollow" class="external text" href="https://datatracker.ietf.org/doc/rfc9460/?include_text=1">RFC 9460</a>
</td>
<td>Service Binding
</td>
<td>RR that improves performance for clients that need to resolve many resources to access a domain.
</td></tr>
<tr>
<td><div id="TA"></div>TA</td>
<td>32768</td>
<td data-sort-value="" style="background: var(--background-color-interactive, #ececec); color: var(--color-base, inherit); vertical-align: middle; text-align: center;" class="table-na">—</td>
<td>DNSSEC Trust Authorities</td>
<td>Part of a deployment proposal for DNSSEC without a signed DNS root. See the <a rel="nofollow" class="external text" href="https://www.iana.org/assignments/dns-parameters">IANA database</a> and <a rel="nofollow" class="external text" href="http://www.watson.org/~weiler/INI1999-19.pdf">Weiler Spec</a> for details.   Uses the same format as the DS record.
</td></tr>
<tr>
<td><div id="TKEY"></div><a href="/wiki/TKEY_record" title="TKEY record">TKEY</a>
</td>
<td>249
</td>
<td>RFC 2930
</td>
<td>Transaction Key record
</td>
<td>A method of providing keying material to be used with <a href="/wiki/TSIG" title="TSIG">TSIG</a> that is encrypted under the public key in an accompanying KEY RR.<sup id="cite_ref-12" class="reference"><a href="#cite_note-12"><span class="cite-bracket">[</span>12<span class="cite-bracket">]</span></a></sup>
</td></tr>
<tr>
<td><div id="TLSA"></div><a href="/wiki/TLSA" class="mw-redirect" title="TLSA">TLSA</a>
</td>
<td>52
</td>
<td>RFC 6698
</td>
<td>TLSA certificate association
</td>
<td>A record for <a href="/wiki/DNS-based_Authentication_of_Named_Entities" title="DNS-based Authentication of Named Entities">DANE</a>. RFC 6698 defines "The TLSA DNS resource record is used to associate a TLS server certificate or public key with the domain name where the record is found, thus forming a 'TLSA certificate association'".
</td></tr>
<tr>
<td><div id="TSIG"></div><a href="/wiki/TSIG" title="TSIG">TSIG</a>
</td>
<td>250
</td>
<td>RFC 2845
</td>
<td>Transaction Signature
</td>
<td>Can be used to authenticate <a href="/wiki/Dynamic_DNS" title="Dynamic DNS">dynamic updates</a> as coming from an approved client, or to authenticate responses as coming from an approved recursive name server<sup id="cite_ref-13" class="reference"><a href="#cite_note-13"><span class="cite-bracket">[</span>13<span class="cite-bracket">]</span></a></sup> similar to DNSSEC.
</td></tr>
<tr>
<td><div id="TXT"></div><a href="/wiki/TXT_record" title="TXT record">TXT</a>
</td>
<td>16
</td>
<td><a rel="nofollow" class="external text" href="https://datatracker.ietf.org/doc/html/rfc1035#page-12">RFC 1035</a><sup id="cite_ref-RFC1035_page-12_1-6" class="reference"><a href="#cite_note-RFC1035_page-12-1"><span class="cite-bracket">[</span>1<span class="cite-bracket">]</span></a></sup>
</td>
<td>Text record
</td>
<td>Originally for arbitrary human-readable <i>text</i> in a DNS record. Since the early 1990s, however, this record more often carries <a href="/wiki/Machine-readable_data" class="mw-redirect" title="Machine-readable data">machine-readable data</a>, such as specified by RFC 1464, <a href="/wiki/Opportunistic_encryption" title="Opportunistic encryption">opportunistic encryption</a>, <a href="/wiki/Sender_Policy_Framework" title="Sender Policy Framework">Sender Policy Framework</a>, <a href="/wiki/DKIM" class="mw-redirect" title="DKIM">DKIM</a>, <a href="/wiki/DMARC" title="DMARC">DMARC</a>, <a href="/wiki/DNS-SD" class="mw-redirect" title="DNS-SD">DNS-SD</a>, etc.
</td></tr>
<tr>
<td><div id="URI"></div><a href="/wiki/URI_record" title="URI record">URI</a>
</td>
<td>256
</td>
<td>RFC 7553
</td>
<td>Uniform Resource Identifier
</td>
<td>Can be used for publishing mappings from hostnames to URIs.
</td></tr>
<tr>
<td><div id="ZONEMD"></div><a href="/w/index.php?title=ZONEMD_record&amp;action=edit&amp;redlink=1" class="new" title="ZONEMD record (page does not exist)">ZONEMD</a>
</td>
<td>63
</td>
<td>RFC 8976
</td>
<td>Message Digests for DNS Zones
</td>
<td>Provides a <a href="/wiki/Cryptographic_message_digest" class="mw-redirect" title="Cryptographic message digest">cryptographic message digest</a> over DNS zone data at rest.
</td></tr></tbody><tfoot></tfoot></table>
