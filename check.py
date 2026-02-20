import pandas as pd

df = pd.read_csv("nsl_kdd_test.csv", header=None)

print("Shape:", df.shape)
print(df.head())
print(df.tail())
