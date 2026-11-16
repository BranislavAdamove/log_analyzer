import re 


LOG_PATTERN = r'^(?P<vhost>\S+)\s+(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d+)\s+(?P<bytes>\S+)\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"\s+(?P<response_time>\S+)'


def parse_line(line:str) -> dict | None:
    line = line.strip()

    if not line:
        return None 

    match = re.match(LOG_PATTERN,line)

    if not match:
        return None 


    data = match.groupdict()

    request_str = data.get('request','')
    user_agent_str = data.get('user_agent','')
    request_prts = request_str.split(' ')

    if len(request_prts) == 3:
        data["method"] = request_prts[0]
        data["path"] = request_prts[1]
        data["protocol"] = request_prts[2]

    else:
        data["method"] = None
        data["path"] = request_str
        data["protocol"] = None 
        

    try:
        data["status"] = int(data["status"])
        data["response_time"] = float(data["response_time"])

    except ValueError:
        pass

    if(user_agent_str != ''):
        data['user_agent'] = user_agent_str

    return data
        

if __name__ == "__main__":
    log = 'domenkazadarmenko.eu 172.70.230.50 - - [06/Nov/2026:18:56:35 +0100] "GET /wp-login.php HTTP/1.1" 509 2534 "-" "Mozilla/5.0" 0.000 - - - (CU)'
    print(parse_line(log))



