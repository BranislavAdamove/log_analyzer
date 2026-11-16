from config import BOT_CATEGORIES,WP_PATHS,SENSITIVE_PATHS
from collections import Counter
from parser import parse_line
import sys




def analyze_log_file(path_to_file:str):
    wp_attack_counter = Counter()
    sensitive_scans = Counter()
    ip_count = Counter()
    path_count = Counter()
    status_count = Counter()
    bot_count = Counter()

    total = 0 
    parsed = 0 

    try:
        with open(path_to_file,'r') as f:
            for line in f:
                total += 1
                data = parse_line(line)

                if not data:
                    continue
                parsed += 1 
                if data["path"]:
                    path = data["path"]
                else:
                    path = ""
                if data["user_agent"]:
                    user_agent = data["user_agent"]
                else:
                     user_agent = ""

                for wp_path in WP_PATHS:
                    if wp_path in path:
                        wp_attack_counter[(data["ip"],path)] += 1 
                        break


                for sens_path in SENSITIVE_PATHS:
                    if sens_path in path:
                        sensitive_scans[(data["ip"],path)] += 1 
                        break

                ua_lower = user_agent.lower()
                bot_found = False

                for category,bot_list in BOT_CATEGORIES.items():
                    for bot_name in bot_list:
                        if bot_name in ua_lower:
                            bot_count[(category,bot_name)] += 1 
                            bot_found = True
                            break
                    if bot_found:
                        break

                ip_count[data['ip']] += 1 
                status_count[data['status']] += 1 

                if data['path']:
                    path_count[data['path']] += 1 

            
    except FileNotFoundError:
        print(f'Error file {path_to_file} was not found ')
        return None 

    return {
        "total":total,
        "parsed":parsed,
        "top_ips":ip_count.most_common(5),
        "top_paths":path_count.most_common(5),
        "statuses":status_count,
        "wp_attack":wp_attack_counter,
        "sensitive_scans":sensitive_scans,
        "bots":bot_count
    }



def print_summary(report:dict):
    if not report:
        return None 


    print("="*45)
    print("     APACHE LOG ANALYSIS     ")
    print('='*45)
    print(f'Parsed lines: {report['parsed']}/{report['total']}')
    print('-'*45)

    print('\n[TOP 5 IP]')
    for ip,count in report['top_ips']:
        print(f'    {ip:<18} -> {count} requests')

    print('\n[TOP 5 PATHS]')
    for path,count in report['top_paths']:
        print(f'    {path:<18} -> {count}x')

    print('\n[HTTP STATUSES]')

    for status,count in sorted(report['statuses'].items()):
        print(f'    {status:<18} -> {count}x')
    print('=' * 45) 

    print("\n[SECURITY AND BOT REPORT]")
    print("\nBrute-force attempts:")
    for (ip,path),count in report["wp_attack"].most_common():
        print(f'    IP:{ip:<16} | Path:{path:<25} ->{count}x')

    print("\nSensitive file scans:")
    if(len(report["sensitive_scans"]) > 0):
        for (ip,path), count in report["sensitive_scans"].most_common():
            print(f'    IP:{ip:<16} | Path:{path:<25} ->{count}x')
    else:
        print(" No scans found")
    
    print("\nDetected bots and crawlers:")
    if (len(report["bots"]) > 0):
        for (category,bot_name),count in report["bots"].most_common():
            cat_label = f'[{category}]'
            print(f'    {cat_label:<20} {bot_name:<25} -> {count}x')
    else:
        print(" No known bots found")
    

if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else "sample.log"
    
    report = analyze_log_file(target_file)
    if report:
        print_summary(report)
