from collections import Counter
from parser import parse_line
import sys


def analyze_log_file(path_to_file:str):
    ip_count = Counter()
    path_count = Counter()
    status_count = Counter()

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
        "statuses":status_count
    }



def print_summary(report:dict):
    if not report:
        return None 


    print("="*45)
    print("     APACHE LOG ANALYSIS     ")
    print('='*45)
    print(f'Parsed lines: {report['parsed']}/{report['total']}')
    print('-'*45)

    print('\n [TOP 5 IP]')
    for ip,count in report['top_ips']:
        print(f'{ip:<18} -> {count} requests')

    print('\n [TOP 5 PATHS]')
    for path,count in report['top_paths']:
        print(f'{path:<18} -> {count}x')

    print('\n [HTTP STATUSES]')

    for status,count in sorted(report['statuses'].items()):
        print(f'{status:<18} -> {count}x')
    print('=' * 45) 


if __name__ == "__main__":
    target_file = sys.argv[1] if len(sys.argv) > 1 else "sample.log"
    
    report = analyze_log_file(target_file)
    if report:
        print_summary(report)
