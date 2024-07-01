import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import norm

df = pd.read_csv("src/packet_log.csv")
df.columns = df.columns.str.strip()

print(df["Delay"].mean())

plt.figure(figsize=(10,6))
n, bins, patches = plt.hist(df["Delay"], bins = 10, density=True, edgecolor ="k", alpha=0.8, label="Actual data")

x = np.linspace(300, 700, 1000)
mean = 500
std_dev = 50
y = norm.pdf(x ,mean, std_dev)

plt.plot(x, y, "r-", linewidth=2, label="Gaussian (500, 50)")

plt.title("Distribution of delay")
plt.xlabel("Delay")
plt.ylabel("Density")

plt.legend()
plt.grid(True, alpha=0.3)

plt.ylim(0, max(max(n), max(y)) *1.1)

ax2 = plt.twiny()
ax2.set_xlim(400, 600)
ax2.set_label("Theoretical Gaussian")

plt.tight_layout()
plt.show()