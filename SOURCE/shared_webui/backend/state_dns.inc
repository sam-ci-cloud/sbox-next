    if 'global' in client_dns:dns['nameserver']=list(client_dns['global'])
    if 'bootstrap' in client_dns:dns['default-nameserver']=list(client_dns['bootstrap'])
    if 'proxy' in client_dns:dns['proxy-server-nameserver']=list(client_dns['proxy'])
    if profile=='cn' and 'cn' in client_dns:
        dns['nameserver-policy']={'geosite:cn':list(client_dns['cn'])}
        dns['direct-nameserver']=list(client_dns['cn'])
