import shodan, pandas as pd
class ShodanDf :
    def __init__(self):
        self.api = ''
        self.master_dict = [{
            'IP':'',
            'Port':'',
            'Data': '',
            'Server':'',
            'Robots':'',
            'Sitemap':'',
            'CN':'',
            'Expired(BOOL)':''
        }]
        self.master_vuln_dict =[{
            'cve': "",
            'cvss': "",
            'summary': "",
            'verified': "",
            'IP':"",
            'Port':""
        }]
        self.ssh = []
        self.telnet = []
        self.ftp = []
        self.http = []
        self.https = []
        self.cve = []
        self.smb = []
        self.dns = []
        self.db = []
        self.common_ports = ['80','443','20','21','23','25','53','123']
        self.http_ = []
        self.https_ = []
        self.vulns = {
            'ip':'',
            'port':'',
            'cve':''
        }
        self.i=0
##### save dict values locally, then try
    def writer(self, banner): # Grabs ip, port, data, server, vulns, robots, sitemap, cn, expired(bool)
        try:
            ip = banner['ip_str']
        except KeyError:
            ip="Empty"
        try:
            port = banner['port']
        except KeyError:
            print("No port???")
        try:
            robots = banner['http']['robots']
        except KeyError:
            robots = "Empty"
        try:
            sitemap = banner['http']['sitemap']
        except KeyError:
            sitemap = "Empty"
        try:
            cn = banner['ssl']['cert']['subject']['CN']
            expired = banner['ssl']['cert']['expired']
        except KeyError:
            cn = "Empty"
            expired = "Empty"
        try:
            data = banner['data']
        except KeyError:
            data="Empty"
        try:
            server = banner['http']['server']
        except KeyError:
            server = "Empty"
        this_dict = {
            'IP':ip,
            'Port':port,
            'Data': data,
            'Server':server,
            'Robots':robots,
            'Sitemap':sitemap,
            'CN':cn,
            'Expired(BOOL)':expired
        }
        self.master_dict.append(this_dict.copy())
    def get_vulns(self,vulns, ip, port):
        for x in vulns:
            local_dict = {
                'cve':x,
                'cvss': vulns[x]['cvss'],
                'verified':vulns[x]['verified'],
                'summary': vulns[x]['summary'],
                'IP':ip,
                'Port':port
            }
            self.master_vuln_dict.append(local_dict.copy())
    # def organize(self, banner):
    #     None #TODO, SET UP ORGANIZE TO READ FROM DF AND DO MORE STUFF WITH DATA...
    def search(self, value):
        for self.banner in self.key.search_cursor(value):
            self.writer(banner=self.banner)
            try:
                vulns = self.banner['vulns']
                self.get_vulns(vulns = vulns, ip=self.banner['ip_str'], port=self.banner['port'])
            except KeyError:
                continue
        master_df = pd.DataFrame(self.master_dict)
        master_vuln_df = pd.DataFrame.from_dict(self.master_vuln_dict)
        try:
            with pd.ExcelWriter('shodan_df_output.xlsx') as writer:
                master_vuln_df.to_excel(excel_writer=writer,sheet_name='Vulns')
                master_df.to_excel(excel_writer=writer, sheet_name='Data')
            print("Output has been written to shodan_df_output.xlsx")
        except:
            print("Error within writing dataframe to excel. ")

    # def scan(self,alert_id):
    #     for self.banner in self.key.stream.alert(alert_id):
    #         None #TODO, SET UP SCANNING AND WRITING TO EXCEL
    # def alert(self,network):
    #     self.alert = self.key.create_alert('ACI Testing', [
    #         str(network)
    #     ])
    #     return self.alert
    def auth(self,key):
        self.key = shodan.Shodan(key)
        return self.key



