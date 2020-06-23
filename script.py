import scapy.all
from clickhouse_driver import Client
from scapy2dict import to_dict
import itertools
from datetime import datetime

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
        StartTime String,
        EndTime String,
        UniqueIps String,
        TotalPackets String
    ) ENGINE = Memory
    """)
    #TinyLog engine for not testing, right now data is in RAM
    #print(client.execute(f'SHOW TABLES FROM {db_name}'))
    return client

#action is called each time a packet is caught
def custom_action(packet):
    data = {'InterfaceLayer': "None", 'InternetLayer': "None", 'TransportLayer': "None", 'ApplicationLayer': "None"}
    d = to_dict(packet, strict=False)
    #dunno why but need to iterate over d.maps which is a [], otherwise the order is fucked up
    try:
        if d["IP"]["src"] not in unique_ips:
            unique_ips.append(d["IP"]["src"])
    except:
        None

    for layer, key in zip(d.maps, data):
        x = next(iter(layer.items())) #tuple
        data[key] = str(x[0]) + " " + str(x[1])
    client.execute(f'INSERT INTO {db_name}.{data_table} VALUES',
             [data] )

    print(f"Unique IP addresses: {len(unique_ips)}, packets: {next(counter) + 1}", end='\r')
    return None

if __name__ == "__main__":
    client = startup()
    
    while True:
        metrics = input("Do you want to collect metrics? If yes you must let program to finish (yes/no)....")
        if metrics == "yes":
            start_time = datetime.now()
        counter = itertools.count()
        unique_ips=[]

        scapy.all.sniff(filter=f"dst {scapy.all.get_if_addr(conf.iface)}", prn=custom_action, count=int(input("Enter how much packets do you want to analyze \n")))
        print()
        print("Db is set up, waiting for packets to arrive....\n")

        if metrics == "yes":
            end_time = datetime.now()
            client.execute(f"INSERT INTO {db_name}.{metrics_table} VALUES",
            [{"StartTime": str(start_time),"EndTime": str(end_time), "UniqueIps": str(len(unique_ips)), "TotalPackets": str(next(counter))}])

        if input("Enter 1 to finish..\n") == "1":
            break

    