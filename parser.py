import re 


LOG_PATTERN = re.compile(
    r'^(?P<vhost>\S+)\s+'
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<bytes>\S+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"\s+'
    r'(?P<response_time>\S+)')


def parse_line(line:str) -> dict[str,any] | None:
    line = line.strip()

    if not line:
        return None 

    match = LOG_PATTERN.match(line)

    if not match:
        return None 


    data: dict[str,any] = match.groupdict()

    request_str = data.get('request','')
    request_prts = request_str.split()

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

    if not data.get("user_agent"):
        data["user_agent"] = None

    return data
        




