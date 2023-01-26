from IPython import embed
import requests
import json
import pandas as pd
import time


results_table = {
	'no_result':0,
    'malicious_count':0,
    'suspicious_count':0, 
    'results':[]
}

def get_request_id(request_string):

    print("Searching : {}".format(request_string))

    host='cybergordon.com'
    endpoint='/request/form'
    url="https://{}{}".format(host, endpoint)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/109.0', 
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8' ,
        'Accept-Language': 'en-GB,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': 'https://cybergordon.com/',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': 'https://cybergordon.com'
    }

    payload = "obs={}".format(request_string)

    print("Payload = {}".format(payload))

    res = requests.post(url, headers=headers, data=payload, allow_redirects=False)
    id = res.headers['Location'].split('=')[1]
    # print(res.headers)
    print("\nHash : {}".format(id))
    return id

def get_report(id):

    host='cybergordon.com'
    endpoint='/get-request/{}/results?_={}'.format(id, int(time.time()))
    url="https://{}{}".format(host, endpoint)
    headers = {
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:109.0) Gecko/20100101 Firefox/109.0', 
        'Accept': 'application/json, text/javascript, */*; q=0.01' ,
        'Accept-Language': 'en-GB,en;q=0.5',
        'Accept-Encoding': 'gzip, deflate',
        'Referer': 'https://cybergordon.com/result.html?id={}'.format(id),
        'X-Requested-With': 'XMLHttpRequest',
    }

    for i in range(0,3):
        res = requests.get(url, headers=headers).json()
        i+=1

    return res

def format_dict(engine, result, link):

    finding_dict = {'engine_name':engine, 'description':result, 'verdict':None, 'engine_url':link}

    return finding_dict

def main():

    res = get_report(get_request_id('5v0.nl'))
    print('{}\n'.format(res))

    for finding in res['data']:
        if 'not found' in finding['result'].lower():
            results_table['no_result']+=1
        else:
            finding_dict = format_dict(finding['engine'], finding['result'], finding['link'])

            if 'malicious' in finding.keys():
                if finding['malicious'] == True:
                    finding_dict['verdict'] = 'Malicious'
                    results_table['malicious_count']+=1

            elif 'suspicious' in finding.keys():
                if finding['suspicious'] == True:
                    finding_dict['verdict'] = 'Suspicious'
                    results_table['suspicious_count']+=1
                    
            else:
                print("Key Error!")

            results_table['results'].append(finding_dict)

    df = pd.DataFrame(results_table['results'])
    print("\nNo-Result: {}, Suspicious: {}, Malicious: {}\n".format(results_table['no_result'], results_table['suspicious_count'], results_table['malicious_count']))
    print(df)

    embed()
    return 


if __name__ == '__main__':
    main()