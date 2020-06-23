import scapy.all
from clickhouse_driver import Client
from scapy2dict import to_dict
import itertools

def startup():
    client = Client(host='localhost')
    #create structure
    client.execute("CREATE DATABASE IF NOT EXISTS test")
    client.execute("""CREATE TABLE IF NOT EXISTS test.mytable
    (
        InterfaceLayer String,
        InternetLayer String,
        TransportLayer String,
        ApplicationLayer String
    ) ENGINE = Memory
    """)
    #TinyLog engine for not testing, right now data is in RAM
    #print(client.execute('SHOW TABLES FROM test'))
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
    client.execute(f'INSERT INTO test.mytable VALUES',
             [data] )

    print(f"Unique IP addresses: {len(unique_ips)}, packets: {next(counter)}", end='\r')
    return None

if __name__ == "__main__":
    client = startup()
    counter = itertools.count()
    next(counter)
    unique_ips=[]

    print("Db is set up, waiting for packets to arrive....\n")
    #filter incoming traffic maybe
    # Setup sniff, filtering for incoming trafic
    scapy.all.sniff(filter=f"dst {scapy.all.get_if_addr(conf.iface)}", prn=custom_action, count=100000)
	