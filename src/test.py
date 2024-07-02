import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from scipy.stats import norm

# Read data from csv
df = pd.read_csv("src/packet_log.csv")
df.columns = df.columns.str.strip() # Clean up columns

# Create two y-axes for the plot
fig, ax1 = plt.subplots(figsize=(10,6))
ax2 = ax1.twinx()

# Plot the measured data on ax1
n, bins, patchet = ax1.hist(df['Delay'], bins=10, edgecolor="k", alpha=0.8, label='Measured data', color='b')
ax1.set_xlabel("Measured delay")
ax1.set_ylabel("Number of occurences")
ax1.tick_params(axis='y', color='b')

# Plot theoretical gaussian curve
x = np.linspace(df['Delay'].min(), df['Delay'].max(), 1000) # Adjusted to use the actual data range
mean = df['Delay'].mean()
std_dev = df['Delay'].std()
y = norm.pdf(x, mean, std_dev)

ax2.plot(x, y, 'r-', linewidth=2, label=f'Gaussian (μ={mean:.2f}, σ={std_dev:.2f})')
ax2.set_ylabel("Probability Density", color='r')
ax2.tick_params(axis='y', labelcolor='r')

plt.title("The distribution of measured delay compared to theoretical values.")

# Add legends
lines1, labels1 = ax1.get_legend_handles_labels()
lines2, labels2 = ax2.get_legend_handles_labels()
ax1.legend(lines1 + lines2, labels1 + labels2, loc='upper left')

plt.grid(True, alpha=0.3)
plt.tight_layout()
plt.show()

# Print some statistics about the actual data
print(f"Actual data - Min: {df['Delay'].min()}, Max: {df['Delay'].max()}, Mean: {mean:.2f}, Std Dev: {std_dev:.2f}")