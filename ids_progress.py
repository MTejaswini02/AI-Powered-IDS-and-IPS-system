import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

print("✅ Loading dataset...")

df = pd.read_csv("nsl_kdd_test.csv")  # Your dataset file

print("✅ Dataset loaded successfully!")

# Split into Features & Label
X = df.drop("Label", axis=1)
y = df["Label"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scaling features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("✅ Training RandomForest model...")

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train_scaled, y_train)

# Evaluation
y_pred = model.predict(X_test_scaled)
accuracy = accuracy_score(y_test, y_pred)

print(f"\n🎯 Model Training Completed!")
print(f"✅ Accuracy : {accuracy * 100:.2f}%")

# Save model and scaler
joblib.dump(model, "ids_model.pkl")
joblib.dump(scaler, "scaler.pkl")

print("\n💾 ids_model.pkl saved!")
print("💾 scaler.pkl saved!")
print("\n🚀 Training Phase completed successfully!")
