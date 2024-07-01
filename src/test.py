import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

df = pd.read_csv("src/packet_log.csv")

df.columns = df.columns.str.strip()

df["Delay"].plot(kind="hist", bins = 10, edgecolor="k", alpha=0.8)
plt.title("Distribution")
plt.xlabel("Delay")
plt.ylabel("Frequency")

plt.show()