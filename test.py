import pandas as pd

df = pd.read_csv(
    "data/raw/PhiUSIIL_Phishing_URL_Dataset.csv",
    encoding="utf-8-sig"
)

print("Dataset Shape:")
print(df.shape)

print("\nFirst 5 Rows:")
print(df.head())

print("\nColumns:")
print(df.columns)