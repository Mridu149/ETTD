import pandas as pd
df = pd.read_json("captures/benign_01.jsonl", lines=True)
t = df[df.tls.notna()].copy()
t["sni"] = t.tls.map(lambda x: x["sni"])
t["ja3"] = t.tls.map(lambda x: x["ja3"])
print(t.groupby(["sni", "ja3"]).size())
