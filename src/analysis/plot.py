import matplotlib.pyplot as plt

# Data based on the provided image
data = {
    "Delay (ms)": [0, 50, 100, 150, 200, 250, 300],
    "Occurence (%)": [0, 10, 10, 10, 10, 10, 10],
    "Mean (ms)": [90, 151, 242, 299, 371, 439, 540],
    "Stddev (ms)": [5, 25, 70, 91, 104, 130, 163]
}

# Extracting data for plotting
delay = data["Delay (ms)"]
mean = data["Mean (ms)"]
stddev = data["Stddev (ms)"]

# Plotting Mean as a function of Delay
plt.figure(figsize=(10, 6))
plt.errorbar(delay, mean, yerr=stddev, fmt='o', capsize=5, label='Mean ± Stddev')
plt.plot(delay, mean, marker='o')

# Adding titles and labels
plt.title("Mean (ms) as a function of Delay (ms)")
plt.xlabel("Delay (ms)")
plt.ylabel("Mean (ms)")
plt.legend()
plt.grid(True)

# Show plot
plt.show()
