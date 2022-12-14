import requests
import json


def scan(url):
    print("Scanning " + url)
    headers = {'API-Key': '0d6990d9-45e0-4421-9f96-d349f659743a', 'Content-Type': 'application/json'}
    data = {"url": url, "visibility": "public"}
    response = requests.post('https://urlscan.io/api/v1/scan/', headers=headers, data=json.dumps(data))
    uuid = response.json()['uuid']
    get_urlscan_result(uuid)


def get_urlscan_result(uuid):
    # Use the urlscan.io API to get the result for the given UUID
    #wait for the scan to return a http 200
    while True:
        response = requests.get('https://urlscan.io/api/v1/result/' + uuid)
        if response.status_code == 200:
            break
    response = requests.get(f'https://urlscan.io/api/v1/result/{uuid}')

    # Parse the response as JSON
    result = json.loads(response.text)

    # Print the result
    print(result)
    # Clean the result to make it more human-readable
    cleaned_result = {}
    cleaned_result['task'] = result.get('task', '')
    cleaned_result['url'] = result.get('url', '')
    cleaned_result['domain'] = result.get('domain', '')
    cleaned_result['page'] = result.get('page', '')
    cleaned_result['virustotal'] = result.get('virustotal', '')

    # Print the cleaned result
    print(cleaned_result)
    return cleaned_result


def main():
    scan("https://google.com/path")


if __name__ == "__main__":
    main()
