import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import norm

# Read the data
df = pd.read_csv("src/packet_log.csv")
df.columns = df.columns.str.strip()

# Create the plot with two y-axes
fig, ax1 = plt.subplots(figsize=(12, 6))
ax2 = ax1.twinx()

# Plot the histogram of actual data on the first y-axis
n, bins, patches = ax1.hist(df["Delay"], bins=20, edgecolor="k", alpha=0.8, label='Actual Data', color='b')
ax1.set_xlabel("Delay")
ax1.set_ylabel("Frequency", color='b')
ax1.tick_params(axis='y', labelcolor='b')

# Generate points for the Gaussian curve
x = np.linspace(df["Delay"].min(), df["Delay"].max(), 1000)  # Adjusted to use actual data range
mean = df["Delay"].mean()
std_dev = df["Delay"].std()
y = norm.pdf(x, mean, std_dev)

# Plot the Gaussian curve on the second y-axis
ax2.plot(x, y, 'r-', linewidth=2, label=f'Gaussian (μ={mean:.2f}, σ={std_dev:.2f})')
ax2.set_ylabel("Probability Density", color='r')
ax2.tick_params(axis='y', labelcolor='r')

plt.title("Distribution of Delay")

# Add legends
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

# Print some statistics about the actual data
print(f"Actual data - Min: {df['Delay'].min()}, Max: {df['Delay'].max()}, Mean: {mean:.2f}, Std Dev: {std_dev:.2f}")
