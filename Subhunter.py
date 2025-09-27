from urllib.parse import urlparse, unquote
from bs4 import BeautifulSoup
import requests,json,yaml,argparse,colorama,os,sys,urllib3,re,time,platform,subprocess,os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

Target= None
out= None
conf= None
word_list= None
timeout=None
delay=None
mc=None
proxy=None
httpx=False
proxies= {}
subs=[]
path = None

class Default:

    headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
        }

    def __init__(self,target,bin_path,driver_path):
        
        if proxies != None:
            self.proxies = {
                "http": proxies.get("http"),
                "https": proxies.get("https")
            }

        if self.check(bin_path,driver_path):
            
            self.Crt(target)
            self.yahoo(target)
            self.c99(target,bin_path,driver_path)
            self.netcraft(target,bin_path,driver_path)

    def check(self,bin_path,driver_path):

        if os.path.exists(bin_path) and os.path.exists(driver_path):
            return True
        else:
            print("binary/driver not found install them ot use --bin/--driver to point there location")

    def Crt (self,target):

        url= f"https://crt.sh/?q=%25.{target}&output=json"
        try:
            req = requests.get(url,proxies=self.proxies,headers=self.headers)
            time.sleep(delay)
            data = json.loads(req.text)
            for i in data:
                if 'name_value' in i:
                    sub = i['name_value']
                    subs.append(sub)
                else:
                    pass
        except requests.RequestException as e:
            pass
    
    def yahoo(self,target):

        for page in range(1, 100):
            url= f"https://search.yahoo.com/search?p=*.{target}&ei=UTF-8&fr=yfp-t&fp=1&toggle=1&cop=mss&b={page*10}&pz=10"    
            try:
                req = requests.get(url,proxies=self.proxies,headers=self.headers,timeout=timeout,allow_redirects=True)
                time.sleep(delay)
                data = req.text 
                soup = BeautifulSoup(data,'html.parser')
                subdomains = soup.find_all("a")
                for sub in subdomains:
                    href = sub['href']
                    if href.startswith("https://r.search.yahoo.com"):
                        match = re.search(r"RU=(https.*?)/RK=", href)
                        if match:
                            real_url = unquote(match.group(1))
                            parsed = urlparse(real_url)
                            domain = parsed.netloc
                            if target in domain:
                                subs.append(domain)
            except Exception as e:
                print(e)

    def c99(self, target,bin_path,driver_path):

        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.chrome.options import Options

        target_esc = re.escape(target)
        sub_re = re.compile(r"([A-Za-z0-9_\-\.]+\.%s)\b" % target_esc, flags=re.IGNORECASE)

        options = Options()
        options.binary_location= bin_path
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument(f"user-agent={self.headers.get('User-Agent')}")
        options.add_experimental_option("excludeSwitches", ["enable-logging"])
        options.add_argument("--log-level=3")
        
        if proxy != None:
            options.add_argument(f"--proxy-server={proxy}")
        else:
            pass
        

        service = Service(driver_path,log_output=subprocess.DEVNULL)
        driver = webdriver.Chrome(service=service, options=options)



        try:
            # افتح الموقع
            driver.get("https://subdomainfinder.c99.nl/")
            time.sleep(delay)

            # لاقي خانة البحث
            search_box = driver.find_element(By.XPATH, "/html/body/div[1]/div[2]/form/div[1]/input[7]")
            search_box.clear()
            search_box.send_keys(target)
            search_button = driver.find_element(By.NAME,"scan_subdomains")
            search_button.click()  # أو بدلها بزر submit

            # استنى النتيجة تتحمل
            time.sleep(timeout)

            # خد صفحة النتائج
            page = driver.page_source
            found = set()

            for m in sub_re.finditer(page):
                subdomain = m.group(1).strip().lower().lstrip("./")
                if subdomain.startswith("http"):
                    try:
                        subdomain = urlparse(unquote(subdomain)).netloc
                    except Exception:
                        pass
                if target in subdomain and subdomain not in found:
                    found.add(subdomain)
                    subs.append(subdomain)
        except Exception as e:
            print("C99 search error:", e)
        finally:
             driver.quit()

    def netcraft(self, target,bin_path,driver_path):

        from selenium import webdriver
        from selenium.webdriver.chrome.service import Service
        from selenium.webdriver.chrome.options import Options

        url = f"https://searchdns.netcraft.com/?restriction=site+contains&host={target}&lookup=wait..&position=limited"

        options = Options()
        options.binary_location= bin_path
        options.add_argument("--headless=new")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_experimental_option("excludeSwitches", ["enable-logging"])
        options.add_argument("--log-level=3")
        
        if proxy != None:
            options.add_argument(f"--proxy-server={proxy}")
        else:
            pass
        
        service = Service(driver_path,log_output=subprocess.DEVNULL)
        driver = webdriver.Chrome(service=service, options=options)


        try:
            driver.get(url)
            time.sleep(delay)  # استنى التحدي يخلص

            #page = driver.page_source

            found = set()
            for a in driver.find_elements("tag name", "a"):
                href = a.get_attribute("href")
                if href:
                    parsed = urlparse(href)
                    hostname = parsed.netloc
                    if hostname and hostname.endswith(target) and hostname not in found:
                        subs.append(hostname)
                        found.add(hostname)
        except Exception as e:
            print("Netcraft error:", e)
        finally:
            driver.quit()


class APIs:
        
    subs = []
    proxies = {}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }

    def __init__(self,target,config):

        if proxies != None:
            self.proxies = {
                "http": proxies.get("http"),
                "https": proxies.get("https")
            }

        try:

            self.api_config(config)
            self.shodan(self.config['shodan']['api_key'],target)
            self.bevigil(self.config['bevigil']['api_key'],target)
            self.digitalyama(self.config['digitalyama']['api_key'],target)
            self.dnsdumpster(self.config['dnsdumpster']['api_key'],target)
            self.fullhunt(self.config['fullhunt']['api_key'],target)
            self.leakix(self.config['leakix']['api_key'],target)
            self.netlas(self.config['netlas']['api_key'],target)
            self.pugrecon(self.config['pugrecon']['api_key'],target)
            self.rsecloud(self.config["rsecloud"]["api_key"],target)
            self.securitytrails(self.config["securitytrails"]["api_key"],target)
            self.virustotal(self.config["virustotal"]["api_key"],target)
            self.google(self.config['google']['api_key'],target)
        
        except Exception: 
            pass

    def api_config(self,config):
            with open(config,'r') as file:
                self.config = yaml.safe_load(file)


    def bevigil(self,bev_api,target):
            header = {
                "X-Access-Token": bev_api
            }
            header.update(self.headers)
            url= f"https://osint.bevigil.com/api/{target}/subdomains/"
            bev_req= requests.get(url,headers=header,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data= json.loads(bev_req.text)
            for i in data['subdomains']:
                subs.append(i)

     
    def chaos(self,chaos_api,target):
            url = f"https://dns.projectdiscovery.io/dns/{target}/subdomains"
            header = {
                "Authorization": chaos_api,
                "Connection": 'close'
            }
            header.update(self.headers)
            req= requests.get(url,headers=header,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data = json.loads(req.text)
            for i in data['subdomains']:
                subs.append(i)
    
    
    def digitalyama(self,digi_api,target):
            url= f"https://api.digitalyama.com/subdomain_finder?domain={target}"
            header= {
                "x-api-key": digi_api
            }
            header.update(self.headers)
            req = requests.get(url,headers=header,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data = json.loads(req.text)
            for i in data["subdomains"]:
                subs.append(i)


    def dnsdumpster(self,dump_api,target):
            url= f" https://api.dnsdumpster.com/domain/{target}"
            header= {
                "X-API-Key": dump_api
            }
            header.update(self.headers)
            req = requests.get(url,headers=header,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data = json.loads(req.text)
            for i in data["a"]:
                sub = i["host"]
                subs.append(sub)
    

    def fullhunt(self,full_api,target):
            url= f"https://fullhunt.io/api/v1/domain/{target}/subdomains"
            header = {
                "X-API-KEY": full_api
            }
            header.update(self.headers)
            req = requests.get(url,headers=header,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data = json.loads(req.text)
            for i in data['hosts']:
                subs.append(i)
    

    def leakix(self,leakix_api,target):
            url = f"https://leakix.net/api/subdomains/{target}"
            header = {
                "api-key": leakix_api,
                "accept": 'application/json'
            }
            header.update(self.headers)
            req = requests.get(url,headers=header,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data = json.loads(req.text)
            for i in data:
                subs.append(i['subdomain'])


    def netlas(self,netlas_api,target):
            url = f"https://app.netlas.io/api/domains/?q=domain:*.{target} a:* & fields=a"
            header = {
                "Authorization": f"Bearer {netlas_api}"
            }
            header.update(self.headers)
            req = requests.get(url,headers=header,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data = json.loads(req.text)
            for i in range(len(data['items'])):
                subs.append(data['items'][i]['data']['domain'])
    

    def pugrecon(self,pug_api,target):
            url = "https://pugrecon.com/api/v1/domains"
            header= {
                "Authorization": f"Bearer {pug_api}",
                "Content-Type": 'application/json'
            }
            header.update(self.headers)
            payload= json.dumps({'domain_name': target})
            req= requests.post(url,data=payload,headers=header,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data= json.loads(req.text)
            for i in data['results']:
                subs.append(i['name'])
 

    def rsecloud(self,rse_api,target):
            url= f'https://api.rsecloud.com/api/v2/subdomains/active/{target}?page=1'
            header = {
                "X-API-Key": rse_api
            }
            header.update(self.headers)
            req = requests.get(url,headers=header,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data = json.loads(req.text)
            for i in data["data"]:
                subs.append(i)


    def securitytrails(self,security_api,target):
            url= f"https://api.securitytrails.com/v1/domain/{target}/subdomains?apikey={security_api}"
            header={"accept": "application/json"}
            header.update(self.headers)
            req= requests.get(url,headers=header,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data = json.loads(req.text)
            for i in data["subdomains"]:
                subs.append(i+f".{target}")
    

    def virustotal(self,virus_api,target):
            url= f"https://www.virustotal.com/api/v3//domains/{target}/subdomains?limit=40"
            header = {"x-apikey": virus_api}
            header.update(self.headers)
            req = requests.get(url,headers=header,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data = json.loads(req.text)
            for i in data['data']:
                subs.append(i['id'])
        

    def google(self,google_api,target):
            dork= f"site:*.{target}"
            url= f"https://www.googleapis.com/customsearch/v1?key={google_api}&cx=b6adaf66c9e614d1b&q={dork}"
            req = requests.get(url,headers=self.headers,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            data= json.loads(req.text)
            for i in data['items']:
                subs.append(i['displayLink'])


    def shodan(self,shodan_api,target):
            url= f"https://api.shodan.io/dns/domain/{target}?key={shodan_api}"
            req=requests.get(url,headers=self.headers,proxies=self.proxies,timeout=timeout)
            time.sleep(delay)
            self.res =req.text
            data= json.loads(self.res)
            for i in data["data"]:
                domain= i["subdomain"]
                type= i["type"]
                if type == "A" or type == "CNAME":
                    subs.append(domain)


class Fuzz:

    subs = []
    proxies = {}
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3"
    }

    def __init__(self,target,Wordlist=None):
        
        if proxies != None:
            self.proxies = {
                "http": proxies.get("http"),
                "https": proxies.get("https")
            }

        self.Fuzz(Wordlist=Wordlist,target=target)

    def Fuzz(self,Wordlist,target):
            
            with open(Wordlist,'r') as word:
                for sub in word:
                    sub = sub.strip()
                    code = []
                    code.extend([c.strip() for c in str(mc).split(',') if c.strip()])
                    time.sleep(delay)
                    try:
                        req = requests.get(f"https://{sub}.{target}",headers=self.headers,proxies=self.proxies,verify=False)
                        if str(req.status_code) in code:
                            #print(f"{colorama.Fore.GREEN}[+] Found: {sub}.{target}  ==> {req.status_code} ")
                            subs.append(f"{sub}.{target}")
                        else:
                            #print(f"{colorama.Fore.RED}[-] Not Found: {sub}.{target}")
                            pass
                    except requests.exceptions.Timeout as e:
                        print(f"{colorama.Fore.RED}[-] timeout: {sub}.{target}")
                        pass
                    except requests.exceptions.ConnectionError:
                        pass


class Subhunter:
  
    def __init__(self,target,output,bin_path,driver_path,conf=None,Wordlist=None,httpx=False):

        if conf == None and Wordlist == None:
            Default(target,bin_path,driver_path)
            
        elif conf != None and Wordlist == None:
            APIs(target,conf)
            Default(target,bin_path,driver_path)
        
        elif Wordlist != None and conf == None:
            Fuzz(Wordlist=Wordlist,target=target)
            Default(target,bin_path,driver_path)
                
        if subs and httpx == False:
           self.output(output,target)
        
        elif subs and httpx == True:
            self.output(output,target,True)
        
        else:
           print ("no subdomains")
  
    def output(self,out_name,target,httpx=False):
        
        subdomains = list({subdomain for subdomain in subs if subdomain})
        sub = []

        for i in subdomains:

            if not i.endswith(target):
                sub.append(f"{i.rstrip('.')}.{target}")
                print(i.rstrip('.')+target)
            else:
                sub.append(i)
                print(i)

        if httpx == True:
            # Write subs to a temporary file for httpx input
            temp_file = "http_temp.txt"
            with open(temp_file, "w") as f:
                f.writelines(f"{sub}\n" for sub in sub)
            os.system(f"httpx -l {temp_file} -o {out_name} -silent -mc {mc} -p 80,443,8080,8443")
            os.remove(temp_file)

        else:
            with open(f'{out_name}', 'a') as output:
                output.writelines(f"{sub}\n" for sub in sub)


if __name__ == "__main__":
    
    args = argparse.ArgumentParser(description="Subhunter - Subdomain Enumeration Tool",usage='%(prog)s [options] -d domain -o output.txt',epilog="Example: python Subhunter.py -d example.com -o output.txt --httpx")
    args.add_argument('-w','--wordlist',help="wordlist to Fuzz",metavar='',required=False,)
    args.add_argument("-d",'--target',help="target domain",metavar='',required=True)
    args.add_argument('-o','--output',help="Output file name: example.txt",metavar='',required=True)
    args.add_argument('-c','--config',help="Output file name: example.txt",metavar='',required=False)
    args.add_argument('-mc',help="match response with specified status code, Work only with Wordlist option or httpx option",metavar='',required=False,type=str,default="200")
    args.add_argument('-t',help="timeout for requests (default is 20 seconds)",metavar='',required=False,type=int,default=20)
    args.add_argument('--proxy',help="proxy to use: https:// , http://",metavar='',type=str,required=False)
    args.add_argument("--httpx",help="use httpx to check for live subdomains",action="store_true",required=False)
    args.add_argument('--delay',help="delay between requests (default is 5 second)",metavar='',required=False,default=5.0)
    args.add_argument("--bin",help="Path to Chromium binary (default: /usr/local/bin/chromium )",default="/usr/local/bin/chromium",required=False)
    args.add_argument("--driver",help="Path to Chrome Driver Path (default: /usr/local/bin/chromedriver )",default="/usr/local/bin/chromedriver",required=False)
    arg = args.parse_args()

    Target = arg.target
    proxy = arg.proxy
    out = arg.output
    httpx = arg.httpx
    conf = arg.config
    word_list = arg.wordlist
    mc=arg.mc
    timeout = arg.t
    delay = float(arg.delay)
    bin_path = arg.bin
    driver_path = arg.driver

    if Target == None or out == None:
        args.print_help()
        sys.exit(1)
    
    else:
        
        if conf != None and word_list != None:
            print(f"{colorama.Fore.RED}[-] You can use either --config or --wordlist not both")
            sys.exit(1)
        
        else:
            
            if conf != None:

                if not os.path.isfile(conf):
                    print(f"{colorama.Fore.RED}[-] Config file not found")
                    sys.exit(1)
                Subhunter(Target,out,bin_path,driver_path,conf=conf,httpx=httpx)

            if word_list != None:
                if not os.path.isfile(word_list):
                    print(f"{colorama.Fore.RED}[-] Wordlist file not found")
                    sys.exit(1)
                Subhunter(Target,out,bin_path,driver_path,Wordlist=word_list,httpx=httpx)
            
            if proxy != None:
                proxies = {
                "http": proxy,
                "https": proxy
                }

            if conf == None and word_list == None:
                Subhunter(Target,out,bin_path,driver_path,httpx=httpx)