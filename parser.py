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

    return data





