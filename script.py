import scapy.all
from clickhouse_driver import Client
from scapy2dict import to_dict
import itertools
from datetime import datetime
from requests import get
from kiss_headers import parse_it


db_name = "nir"
metrics_table = "metrics"
data_table = "data"
def startup():
    client = Client(host='localhost')
    #create structure
    client.execute(f"CREATE DATABASE IF NOT EXISTS {db_name}")
    client.execute(f"""CREATE TABLE IF NOT EXISTS {db_name}.{data_table}
    (
        InterfaceLayer String,
        InternetLayer String,
        TransportLayer String,
        ApplicationLayer String
    ) ENGINE = Memory
    """)
    client.execute(f""" CREATE TABLE IF NOT EXISTS {db_name}.{metrics_table}
    (
        Time String,
        Ip String,
        UserAgent String
    ) ENGINE = Memory
    """)
    #TinyLog engine for not testing, right now data is in RAM
    return client

#action is called each time a packet is caught
def custom_action(packet):
    data = {'InterfaceLayer': "None", 'InternetLayer': "None", 'TransportLayer': "None", 'ApplicationLayer': "None"}
    
    d = to_dict(packet, strict=False)
    #dunno why but need to iterate over d.maps which is a [], otherwise the order is fucked up
    ip = d["IP"]["src"]
    time = datetime.now()
    user_agent = None
    try:
        if ip not in unique_ips:
            unique_ips.append(ip)
    except:
        None
    
    if "Raw" in d and d["Raw"]["load"].startswith(b"GET"):
        try:
            headers = parse_it(d["Raw"]["load"])
            user_agent = headers.user_agent
        except:
            print("Exception!!!!!")

    for layer, key in zip(d.maps, data):
        x = next(iter(layer.items())) #tuple
        data[key] = str(x[0]) + " " + str(x[1])

    client.execute(f'INSERT INTO {db_name}.{data_table} VALUES',
             [data] )
    if user_agent:
        client.execute(f'INSERT INTO {db_name}.{metrics_table} VALUES',
        [{"Time": str(time),"Ip": ip, "UserAgent": str(user_agent)}])
    print(f"Unique IP addresses: {unique_ips}, packets: {next(counter) + 1}", end='\r')
    return None

if __name__ == "__main__":
    client = startup()
    
    while True:
        counter = itertools.count()
        unique_ips=[]

        scapy.all.sniff(filter=f"src 192.168.0.100", prn=custom_action, count=int(input("Enter how much packets do you want to analyze \n")))
        print()
        print("Db is set up, waiting for packets to arrive....\n")

        if input("Enter 1 to finish..\n") == "1":
            break

    