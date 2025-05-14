import sys
import time
from zapv2 import ZAPv2
from http.client import IncompleteRead

def zap_scan(target_url):
    api_key = '3j0lvhvmocjvd3koh7omf0kkoc'
    zap = ZAPv2(apikey=api_key, proxies={'http': 'http://127.0.0.1:8090', 'https': 'http://127.0.0.1:8090'})

    try:
        print(f'Scanning {target_url} with OWASP ZAP...')

        # Load the target URL
        zap.urlopen(target_url)
        time.sleep(2)

        # Spider the target
        print("Starting Spider...")
        spider_id = zap.spider.scan(target_url)
        time.sleep(2)

        while int(zap.spider.status(spider_id)) < 100:
            print(f"Spider progress: {zap.spider.status(spider_id)}%")
            time.sleep(2)

        print("Spider complete. Starting Active Scan...")
        scan_id = zap.ascan.scan(target_url)
        time.sleep(2)

        if not scan_id.isdigit():
            print(f"Error: Invalid scan ID returned: {scan_id}")
            return "Scan failed to start. Please check ZAP settings."

        while int(zap.ascan.status(scan_id)) < 100:
            print(f"Scan progress: {zap.ascan.status(scan_id)}%")
            time.sleep(2)

        print("Scan complete. Fetching alerts...")

        # Fetch alerts in chunks to avoid IncompleteRead error
        start = 0
        count = 100
        scan_report = []

        while True:
            try:
                batch = zap.core.alerts(baseurl=target_url, start=start, count=count)
                if not batch:
                    break
                scan_report.extend(batch)
                start += count
            except IncompleteRead as e:
                print(f"IncompleteRead occurred: {e}. Retrying batch from {start}...")
                time.sleep(2)
                continue
            except Exception as e:
                print(f"Error while fetching alerts: {e}")
                break

        formatted_results = []
        for alert in scan_report:
            formatted_results.append({
                'alert': alert.get('alert', 'N/A'),
                'url': alert.get('url', 'N/A'),
                'risk': alert.get('risk', 'N/A'),
                'description': alert.get('description', 'N/A')
            })

        if formatted_results:
            for result in formatted_results:
                print(f"Alert: {result['alert']}")
                print(f"URL: {result['url']}")
                print(f"Risk: {result['risk']}")
                print(f"Description: {result['description']}\n")

        return formatted_results

    except Exception as e:
        return {"error": str(e)}

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python zap_scan.py <target_url>")
        sys.exit(1)

    target_url = sys.argv[1]
    result = zap_scan(target_url)
    print("Scan Results:")
    for res in result:
        print(res)