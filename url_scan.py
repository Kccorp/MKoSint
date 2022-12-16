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
    data = json.loads(response.text)

    print_summary(data)

def print_summary(content):
    ### relevant aggregate data
    request_info = content.get("data").get("requests")
    meta_info = content.get("meta")
    verdict_info = content.get("verdicts")
    list_info = content.get("lists")
    stats_info = content.get("stats")
    page_info = content.get("page")

    ### more specific data
    geoip_info = meta_info.get("processors").get("geoip")
    web_apps_info = meta_info.get("processors").get("wappa")
    resource_info = stats_info.get("resourceStats")
    protocol_info = stats_info.get("protocolStats")
    ip_info = stats_info.get("ipStats")

    ### enumerate countries
    countries = []
    for item in resource_info:
        country_list = item.get("countries")
        for country in country_list:
            if country not in countries:
                countries.append(country)

    ### enumerate web apps
    web_apps = []
    for app in web_apps_info.get("data"):
        web_apps.append(app.get("app"))

    ### enumerate domains pointing to ip
    pointed_domains = []
    for ip in ip_info:
        domain_list = ip.get("domains")
        for domain in domain_list:
            if domain not in pointed_domains:
                pointed_domains.append(domain)


    ### data for summary
    page_domain = page_info.get("domain")
    page_ip = page_info.get("ip")
    page_country = page_info.get("country")
    page_server = page_info.get("server")
    ads_blocked = stats_info.get("adBlocked")
    https_percentage = stats_info.get("securePercentage")
    ipv6_percentage = stats_info.get("IPv6Percentage")
    country_count = stats_info.get("uniqCountries")
    num_requests = len(request_info)
    is_malicious = verdict_info.get("overall").get("malicious")
    malicious_total = verdict_info.get("engines").get("maliciousTotal")
    ip_addresses = list_info.get("ips")
    urls = list_info.get("urls")


    ### print data
    if str(page_ip) != "None":
        print("Domain: " + page_domain)
        print("IP Address: " + str(page_ip))
        print("Country: " + page_country)
        print("Server: " + str(page_server))
        print("Web Apps: " + str(web_apps))
        print("Number of Requests: " + str(num_requests))
        print("Ads Blocked: " + str(ads_blocked))
        print("HTTPS Requests: " + str(https_percentage) + "%")
        print("IPv6: " + str(ipv6_percentage) + "%")
        print("Unique Country Count: " + str(country_count))
        print("Malicious: " + str(is_malicious))
        print("Malicious Requests: " + str(malicious_total))
        print("Pointed Domains: " + str(pointed_domains))





def main():
    scan("https://lazyapeyachtclub.com")


if __name__ == "__main__":
    main()
