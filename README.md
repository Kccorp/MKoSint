
# MKoSint

MKoSint is an OSINT (Open Source Intelligence) tool that can be used to gather information about a target from publicly available sources. It is composed of several smaller tools, including TheHarvester, dnscan, urlscan, and shodan. 

These tools allow MKoSint to gather information about subdomains and email addresses, as well as other types of information. MKoSint is useful for anyone looking to gather information about a target without having to rely on more expensive or specialized tools. It is particularly useful for security professionals, researchers, and others who need to gather information about a target quickly and efficiently.


## Prerequisites 

Before installing MKoSint, you will need to make sure you have the 
following dependencies installed:

```bash
>=Python3.7
>=pip22.3
shodan
requests
```
    
## Installation


### Option 1: install from source

To install MKoSint, simply clone the repository and run the setup script:

```bash
git clone https://github.com/Kccorp/MKoSint.git
cd MKoSint
sudo python3 install.py
``` 

### Option 2: Docker

To install MKoSint using Docker, simply run the following command:

```bash
mkdir -p results/{easy/{theHarvester,dnscan,urlscan,shodan},full/{theHarvester,dnscan,urlscan,shodan}}
docker pull kccorp/mkosint
sudo docker run --rm -v <absolut_path_to_results>:/app/results -it kccorp/mkosint [Commande] [example : -d youtube.com -l 1]
```

## Usage

To run MKoSint, simply run the following command:

```bash
Python3 mkosint.py -d <target> -l <level>
```




## Authors

- [@Keissy](https://www.github.com/kccorp)
- [@Milan](https://www.github.com/MeKAniml)

