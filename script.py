import scapy.all
from clickhouse_driver import Client

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x


#Called each time a packet is caught
def custom_action(packet):
    data = {'InterfaceLayer': None, 'InternetLayer': None, 'TransportLayer': None, 'ApplicationLayer': None}
    plist = list(expand(packet))
    plist.reverse()
    for k, v in data.items():
        if not plist:
            break
        layer = plist.pop()
        field_names = [field.name for field in layer.fields_desc]
        #remove raw data
        if layer.name == "Raw":
            data[k] = layer.name
        else:
            data[k] = layer.name + str({field_name: getattr(packet, field_name) for field_name in field_names})
    print(data)
    if data["ApplicationLayer"]:
        print(client.execute(f'INSERT INTO test.mytable VALUES',
            [data] ))
    input()
    return None

## Setup sniff, filtering for IP traffic

client = Client(host='localhost', password='admin')
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
#TinyLog engine for not testing
#client.execute('INSERT INTO test VALUES (%(a)s), (%(b)s)',{'a': 1, 'b': 2})

print(client.execute('SHOW TABLES FROM test'))
print(client.execute('SELECT * FROM test.mytable'))

print("Db is set up, waiting for packets to arrive....\nPress q+Enter to exit\n")
#filter incoming traffic maybe
scapy.all.sniff(prn=custom_action, count=100000)