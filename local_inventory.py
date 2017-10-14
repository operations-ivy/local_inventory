import nmap
import pandas as pd

nm = nmap.PortScanner()

bad_cols = ["command_line", "scaninfo", "scanstats"]
good_cols = ["ip_address", "hostname", "os"]
host_dict = nm.scan('192.168.1.*', '22')

df = pd.DataFrame(host_dict)

df.drop("nmap", axis=1, inplace=True)
df.drop(bad_cols, axis=0, inplace=True)

inventory = pd.DataFrame(columns=good_cols)
inventory["ip_address"] = df.index
inventory.index.rename("index", inplace=True)

df.reset_index(drop=True, inplace=True)

for i, row in inventory.iterrows():
    inventory.iloc[i, inventory.columns.get_loc("hostname")] = df.scan[i].hostname()

for i, row in inventory.iterrows():
    inventory.iloc[i, inventory.columns.get_loc("os")] = df.scan[i]["tcp"][22]["cpe"]

for k, v in inventory.iterrows():
    if v.os == '':
        v["os"] = "other"
    else:
        continue

inventory.to_csv("/tmp/inventory", encoding="utf-8")
