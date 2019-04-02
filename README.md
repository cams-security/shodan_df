# shodan_df
Uses the Shodan API and Pandas to create dataframes from the Shodan output. Will write those dataframes to excel sheets. I built it mostly for looking around web sites, but I'll add some more functionality for other services. 

Usage:
shodan_test = shodan_df.ShodanDf()
shodan_test.auth(key='Shodan API key')
shodan_test.search(value="org:'My Super Fake Org.org'")

Shodan's API search takes vaalues such as Organization(org:''), ASN(asn:''), Port(port:''), IP(ip:''), and many more. 
