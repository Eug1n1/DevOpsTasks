## Task
**Задача №5** Nginx header + proxy + upstream + regex 

1. На основе прошлой задачи, нужно создать ещё два сервера, в nginx и сделать переход по /redblue что бы:

    - после первого перехода на этот путь была красная страница 
    - после второго перехода по этому адресу нужно получить синюю страницу. 

    (для этого задействовать балансировку и проксирование.)

2. нужно создать переход на /image1 там будет jpg и /image2 где будет png. 
3. Сделать регулярное выражение для картинок. 
   - Если формат jpg, то картинка будет перевёрнута с помощью nginx.
4. при выводе логов, показать куда проксировал запрос клиента.


(3 дня)

## Code

### Upstream Config

```nginx
upstream redblue {
        server yakula.ddns.net:8001;
        server yakula.ddns.net:8002;
}

server {
    ...
}
```

### New Server Routes

```nginx
sever {
    ...
    location /redblue {
            proxy_pass http://redblue/;
            proxy_next_upstream error timeout http_500 http_404;
            proxy_read_timeout 15;
            proxy_connect_timeout 3;
            include proxy_params;
    }

    location ~* ^/images/(?<file>.+)\.(?<extension>jpeg|jpg)$ {
            image_filter rotate 180;
    }
    ...
}
```

### Additional Servers

```nginx
server {                                # red
        listen 8001;
        listen [::]:8001 ;
        server_name _;

        root /var/www/html;
        index red.html;

        location / {
                try_files $uri $uri/ =404;
        }
}
server {                                # blue
        listen 8002;
        listen [::]:8002 ;
        server_name _;

        root /var/www/html;
        index blue.html;

        location / {
                try_files $uri $uri/ =404;
        }
}
```

### Red and Blue HTML Pages 

```html
<head>
        <meta charset="UTF-8">
</head>
<body bgcolor="red">
        red
</body>
```


### Logging
```nginx
log_format upstreamlog '$request_time: $server_name --> $upstream_addr [$request]';

server {
    ...
    access_log /var/log/nginx/task_log.log upstreamlog;
    ...
}
```



## Theory

### 1. Nginx Upstream

```nginx
upstream example {
    # ip_hash    
    # least_conn


    server example.server1.net max_fails=2 fail_timeout=11s \
    weight=2; # default weight=1
    server example.server2.net max_conns=10;
    server example.server3.net down;
    server example.server4.net backup;
}

server {
    listem 80;
    server_name example.server.net;

    location / {
        proxy_pass https://example/;
        proxy_next_upstream error timout http_500, http_404

    }
}
```

### 2. Regex (Reqular Expression)

- <div style="text-align: justify"> is a sequence of characters that specifies a match pattern in text. Usually such patterns are used by string-searching algorithms for "find" or "find and replace" operations on strings, or for input validation.</div>

### 3. Load Balancing
   
- <div style="text-align: justify">load balancing is the process of distributing a set of tasks over a set of resources, with the aim of making their overall processing more efficient. Load balancing can optimize response time and avoid unevenly overloading some compute nodes while other compute nodes are left idle.</div>

### 4. HTTP Headers

- <div style="text-align: justify">HTTP header fields are a list of strings sent and received by both the client program and server on every HTTP request and response. These headers are usually invisible to the end-user and are only processed or logged by the server and client applications.</div>

- #### Request headers

  - Contain more information about the resource to be fetched, or about the client requesting the resource.

    - Host
    - User-Agent
    - Accept
    - Accept-Language
    - Accept-Encoding
    - Connection

- #### Response headers

    - Hold additional information about the response, like its location or about the server providing it.

        - Connection
        - Content-Type
        - Date
        - Server

- #### Representation headers

    - Contain information about the body of the resource, like its MIME type, or encoding/compression applied.

        - Content-Length
        - Content-Range
        - Content-Type
        - Content-Encoding
        - Content-Location
        - Content-Language

- #### Payload headers

    - Contain representation-independent information about payload data, including content length and the encoding used for transport.
