# ============================================================
# LEVEL 3 EV DATASET BENCHMARK
# Full dataset version: split into train/test inside the code
#
# Tasks:
#   1. Binary classification: binary_classification
#   2. Multiclass classification: multiclass_classification
#
# Models:
#   Classical: Random Forest, Extra Trees, Linear SVM
#   Deep: CNN, RNN, LSTM, KAN-style, Transformer
# ============================================================

import time
import warnings
import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

from sklearn.model_selection import train_test_split
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler, LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    matthews_corrcoef,
    classification_report,
    confusion_matrix
)
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.svm import LinearSVC

import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader


# ============================================================
# 1. Configuration
# ============================================================

FULL_DATASET_PATH = "C:/Users/Abdo/Downloads/ev_ids_sentinel_dashboard/DS/DS_EV.csv"

BINARY_LABEL = "binary_classification"
MULTICLASS_LABEL = "multiclass_classification"

TEST_SIZE = 0.20
RANDOM_STATE = 42

BATCH_SIZE = 256
EPOCHS = 20
LEARNING_RATE = 1e-3

DEVICE = "cuda" if torch.cuda.is_available() else "cpu"
print("Using device:", DEVICE)


# ============================================================
# 2. Level 3 feature removal
# ============================================================

DROP_LEVEL_3 = [
    # IDs / metadata
    "flow_id",
    "src_ip",
    "dst_ip",
    "flow_start_ts",
    "flow_end_ts",

    # labels
    "binary_classification",
    "multiclass_classification",

    # direct or near-direct leakage
    "heuristic_label",
    "heuristic_score",
    "heuristic_reasons",
    "flow_summary",
    "llm_context",

    # dataset-quality / generated scoring fields
    "feature_completeness_score",
    "capture_confidence_score",
    "stability_score",
    "timeliness_score",
    "robustness_score",
    "live_readiness_score",

    # strong attack-rule shortcut features
    "dst_port",
    "src_port",
    "protocol",
    "export_reason",
    "snapshot_kind",

    # scan / DoS shortcut features
    "failed_connections_1m",
    "scan_rate_1m",
    "fan_out_ratio_1m",
    "failed_ratio_1m",
    "unique_dst_count_1m",
    "new_port_count_1m",
    "unique_peer_ips_1m",
    "service_diversity_1m",

    # highly predictive traffic-volume features
    "total_fwd_bytes",
    "total_bwd_bytes",
    "fwd_pkt_len_mean",
    "fwd_pkt_len_max",
    "bwd_pkt_len_mean",
    "bwd_pkt_len_max",
    "flow_bytes_per_sec",
    "flow_packets_per_sec",

    # timing shortcut features
    "flow_duration",
    "flow_iat_mean",
    "flow_iat_max",
    "active_mean",

    # TCP flag / behaviour shortcuts
    "syn_count",
    "ack_count",
    "rst_count",
    "psh_count",
    "window_size_mean",
    "ttl_mean",

    # DNS shortcut features
    "dns_query_count",
    "dns_unique_qnames",
    "dns_qname_avg_len",
    "dns_qname_entropy",

    # partial-capture shortcut
    "packets_seen_at_export"
]


# ============================================================
# 3. Load and clean full dataset
# ============================================================

def clean_dataframe(df):
    df = df.copy()

    df.columns = df.columns.astype(str).str.strip()

    df = df.dropna(axis=0, how="all")
    df = df.dropna(axis=1, how="all")
    df = df.drop_duplicates()
    df = df.replace([np.inf, -np.inf], np.nan)

    object_cols = df.select_dtypes(include=["object"]).columns
    for col in object_cols:
        df[col] = df[col].astype(str).str.strip()

    return df


df = pd.read_csv(FULL_DATASET_PATH)

print("Original dataset shape:", df.shape)

df = clean_dataframe(df)

print("Cleaned dataset shape:", df.shape)

for label_col in [BINARY_LABEL, MULTICLASS_LABEL]:
    if label_col not in df.columns:
        raise ValueError(f"Missing label column: {label_col}")


# ============================================================
# 4. Split full dataset into train/test
# ============================================================
# Stratify using multiclass label because it is more detailed.
# This also usually preserves the binary distribution.

train_df, test_df = train_test_split(
    df,
    test_size=TEST_SIZE,
    random_state=RANDOM_STATE,
    stratify=df[MULTICLASS_LABEL]
)

train_df = train_df.reset_index(drop=True)
test_df = test_df.reset_index(drop=True)

print("\nTrain shape:", train_df.shape)
print("Test shape:", test_df.shape)

print("\nBinary train distribution:")
print(train_df[BINARY_LABEL].value_counts())

print("\nBinary test distribution:")
print(test_df[BINARY_LABEL].value_counts())

print("\nMulticlass train distribution:")
print(train_df[MULTICLASS_LABEL].value_counts())

print("\nMulticlass test distribution:")
print(test_df[MULTICLASS_LABEL].value_counts())

# Save split files
train_df.to_csv("train_split_level3.csv", index=False)
test_df.to_csv("test_split_level3.csv", index=False)


# ============================================================
# 5. Build Level 3 feature matrix
# ============================================================

feature_columns = [
    col for col in train_df.columns
    if col not in DROP_LEVEL_3
]

X_train_raw = train_df[feature_columns].copy()
X_test_raw = test_df[feature_columns].copy()

# Remove constant columns using train only
constant_columns = [
    col for col in X_train_raw.columns
    if X_train_raw[col].nunique(dropna=False) <= 1
]

X_train_raw = X_train_raw.drop(columns=constant_columns)
X_test_raw = X_test_raw.drop(columns=constant_columns, errors="ignore")

print("\nLevel 3 feature count:", X_train_raw.shape[1])
print("Level 3 features used:")
print(list(X_train_raw.columns))

print("\nRemoved constant columns:")
print(constant_columns)


# ============================================================
# 6. Preprocessing
# ============================================================

numeric_features = X_train_raw.select_dtypes(
    include=["int64", "int32", "float64", "float32"]
).columns.tolist()

categorical_features = X_train_raw.select_dtypes(
    exclude=["int64", "int32", "float64", "float32"]
).columns.tolist()

try:
    onehot = OneHotEncoder(handle_unknown="ignore", sparse_output=False)
except TypeError:
    onehot = OneHotEncoder(handle_unknown="ignore", sparse=False)

preprocessor = ColumnTransformer(
    transformers=[
        ("num", Pipeline([
            ("imputer", SimpleImputer(strategy="median")),
            ("scaler", StandardScaler())
        ]), numeric_features),

        ("cat", Pipeline([
            ("imputer", SimpleImputer(strategy="most_frequent")),
            ("onehot", onehot)
        ]), categorical_features)
    ]
)

print("\nNumeric features:", len(numeric_features))
print("Categorical features:", len(categorical_features))


# ============================================================
# 7. Metrics
# ============================================================

def compute_metrics(y_true, y_pred):
    return {
        "Accuracy": accuracy_score(y_true, y_pred),
        "Precision_macro": precision_score(y_true, y_pred, average="macro", zero_division=0),
        "Recall_macro": recall_score(y_true, y_pred, average="macro", zero_division=0),
        "F1_macro": f1_score(y_true, y_pred, average="macro", zero_division=0),
        "F1_weighted": f1_score(y_true, y_pred, average="weighted", zero_division=0),
        "MCC": matthews_corrcoef(y_true, y_pred)
    }


def print_report(task_name, model_name, y_true, y_pred, class_names):
    print("\n" + "=" * 90)
    print(f"{task_name.upper()} | {model_name}")
    print("=" * 90)

    print(classification_report(
        y_true,
        y_pred,
        target_names=class_names,
        zero_division=0
    ))

    print("Confusion matrix:")
    print(confusion_matrix(y_true, y_pred))


# ============================================================
# 8. Label preparation
# ============================================================

def prepare_labels(label_column):
    y_train_raw = train_df[label_column].astype(str)
    y_test_raw = test_df[label_column].astype(str)

    encoder = LabelEncoder()
    y_train = encoder.fit_transform(y_train_raw)
    y_test = encoder.transform(y_test_raw)

    return y_train, y_test, encoder


# ============================================================
# 9. Classical models
# ============================================================

classical_models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1
    ),

    "Extra Trees": ExtraTreesClassifier(
        n_estimators=300,
        class_weight="balanced",
        random_state=RANDOM_STATE,
        n_jobs=-1
    ),

    "Linear SVM": LinearSVC(
        class_weight="balanced",
        random_state=RANDOM_STATE,
        max_iter=5000
    )
}


def run_classical_benchmark(task_name, label_column):
    print("\n" + "#" * 90)
    print(f"CLASSICAL MODELS | {task_name.upper()} | LEVEL 3 FEATURES")
    print("#" * 90)

    y_train, y_test, encoder = prepare_labels(label_column)
    class_names = encoder.classes_

    results = []

    for model_name, model in classical_models.items():
        pipeline = Pipeline([
            ("preprocess", preprocessor),
            ("model", model)
        ])

        start_train = time.time()
        pipeline.fit(X_train_raw, y_train)
        train_time = time.time() - start_train

        start_test = time.time()
        y_pred = pipeline.predict(X_test_raw)
        test_time = time.time() - start_test

        metrics = compute_metrics(y_test, y_pred)
        metrics.update({
            "Task": task_name,
            "Feature_Set": "Level_3",
            "Model": model_name,
            "Model_Type": "Classical",
            "Train_time_sec": train_time,
            "Test_time_sec": test_time
        })

        results.append(metrics)

        print_report(task_name, model_name, y_test, y_pred, class_names)

    return pd.DataFrame(results)


# ============================================================
# 10. PyTorch dataset
# ============================================================

class TabularDataset(Dataset):
    def __init__(self, X, y):
        self.X = torch.tensor(X, dtype=torch.float32)
        self.y = torch.tensor(y, dtype=torch.long)

    def __len__(self):
        return len(self.y)

    def __getitem__(self, idx):
        return self.X[idx], self.y[idx]


def get_class_weights(y, num_classes):
    counts = np.bincount(y, minlength=num_classes)
    counts = np.maximum(counts, 1)
    weights = len(y) / (num_classes * counts)
    return torch.tensor(weights, dtype=torch.float32).to(DEVICE)


# ============================================================
# 11. Deep learning models
# ============================================================

class CNN1DClassifier(nn.Module):
    def __init__(self, input_dim, num_classes):
        super().__init__()

        self.net = nn.Sequential(
            nn.Conv1d(1, 32, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.BatchNorm1d(32),

            nn.Conv1d(32, 64, kernel_size=3, padding=1),
            nn.ReLU(),
            nn.BatchNorm1d(64),

            nn.AdaptiveAvgPool1d(1),
            nn.Flatten(),
            nn.Linear(64, num_classes)
        )

    def forward(self, x):
        x = x.unsqueeze(1)
        return self.net(x)


class RNNClassifier(nn.Module):
    def __init__(self, input_dim, num_classes, hidden_dim=64):
        super().__init__()

        self.rnn = nn.RNN(
            input_size=1,
            hidden_size=hidden_dim,
            batch_first=True,
            nonlinearity="tanh"
        )

        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        x = x.unsqueeze(-1)
        _, h = self.rnn(x)
        return self.fc(h[-1])


class LSTMClassifier(nn.Module):
    def __init__(self, input_dim, num_classes, hidden_dim=64):
        super().__init__()

        self.lstm = nn.LSTM(
            input_size=1,
            hidden_size=hidden_dim,
            batch_first=True
        )

        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        x = x.unsqueeze(-1)
        _, (h, _) = self.lstm(x)
        return self.fc(h[-1])


class KANLikeClassifier(nn.Module):
    """
    Lightweight KAN-inspired model using radial basis expansion.
    This avoids external pykan dependency.
    """
    def __init__(self, input_dim, num_classes, grid_size=8, hidden_dim=128):
        super().__init__()

        centers = torch.linspace(-2.5, 2.5, grid_size)
        self.register_buffer("centers", centers)

        self.fc1 = nn.Linear(input_dim * grid_size, hidden_dim)
        self.act = nn.SiLU()
        self.fc2 = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        x_expanded = x.unsqueeze(-1)
        basis = torch.exp(-((x_expanded - self.centers) ** 2))
        basis = basis.reshape(x.shape[0], -1)

        out = self.fc1(basis)
        out = self.act(out)
        out = self.fc2(out)

        return out


class TransformerClassifier(nn.Module):
    def __init__(self, input_dim, num_classes, d_model=64, nhead=4, num_layers=2):
        super().__init__()

        self.embedding = nn.Linear(1, d_model)

        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=128,
            dropout=0.1,
            batch_first=True
        )

        self.transformer = nn.TransformerEncoder(
            encoder_layer,
            num_layers=num_layers
        )

        self.fc = nn.Linear(d_model, num_classes)

    def forward(self, x):
        x = x.unsqueeze(-1)
        x = self.embedding(x)
        x = self.transformer(x)
        x = x.mean(dim=1)
        return self.fc(x)


# ============================================================
# 12. Deep learning training loop
# ============================================================

def train_deep_model(
    model,
    train_loader,
    test_loader,
    y_train,
    y_test,
    class_names,
    task_name,
    model_name,
    num_classes
):
    model = model.to(DEVICE)

    class_weights = get_class_weights(y_train, num_classes)
    criterion = nn.CrossEntropyLoss(weight=class_weights)

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=LEARNING_RATE,
        weight_decay=1e-4
    )

    start_train = time.time()

    for epoch in range(EPOCHS):
        model.train()
        total_loss = 0.0

        for X_batch, y_batch in train_loader:
            X_batch = X_batch.to(DEVICE)
            y_batch = y_batch.to(DEVICE)

            optimizer.zero_grad()
            logits = model(X_batch)
            loss = criterion(logits, y_batch)
            loss.backward()
            optimizer.step()

            total_loss += loss.item()

        avg_loss = total_loss / max(len(train_loader), 1)
        print(f"{task_name} | {model_name} | Epoch {epoch + 1}/{EPOCHS} | Loss: {avg_loss:.4f}")

    train_time = time.time() - start_train

    model.eval()
    predictions = []

    start_test = time.time()

    with torch.no_grad():
        for X_batch, _ in test_loader:
            X_batch = X_batch.to(DEVICE)
            logits = model(X_batch)
            y_pred = torch.argmax(logits, dim=1)
            predictions.extend(y_pred.cpu().numpy())

    test_time = time.time() - start_test

    y_pred = np.array(predictions)

    print_report(task_name, model_name, y_test, y_pred, class_names)

    metrics = compute_metrics(y_test, y_pred)
    metrics.update({
        "Task": task_name,
        "Feature_Set": "Level_3",
        "Model": model_name,
        "Model_Type": "Deep Learning",
        "Train_time_sec": train_time,
        "Test_time_sec": test_time
    })

    return metrics


def run_deep_benchmark(task_name, label_column):
    print("\n" + "#" * 90)
    print(f"DEEP MODELS | {task_name.upper()} | LEVEL 3 FEATURES")
    print("#" * 90)

    y_train, y_test, encoder = prepare_labels(label_column)
    class_names = encoder.classes_
    num_classes = len(class_names)

    # Fit preprocessing only on train
    X_train = preprocessor.fit_transform(X_train_raw)
    X_test = preprocessor.transform(X_test_raw)

    X_train = np.asarray(X_train, dtype=np.float32)
    X_test = np.asarray(X_test, dtype=np.float32)

    input_dim = X_train.shape[1]

    train_dataset = TabularDataset(X_train, y_train)
    test_dataset = TabularDataset(X_test, y_test)

    train_loader = DataLoader(
        train_dataset,
        batch_size=BATCH_SIZE,
        shuffle=True
    )

    test_loader = DataLoader(
        test_dataset,
        batch_size=BATCH_SIZE,
        shuffle=False
    )

    deep_models = {
        "CNN": CNN1DClassifier(input_dim, num_classes),
        "RNN": RNNClassifier(input_dim, num_classes),
        "LSTM": LSTMClassifier(input_dim, num_classes),
        "KAN": KANLikeClassifier(input_dim, num_classes),
        "Transformer": TransformerClassifier(input_dim, num_classes)
    }

    results = []

    for model_name, model in deep_models.items():
        metrics = train_deep_model(
            model=model,
            train_loader=train_loader,
            test_loader=test_loader,
            y_train=y_train,
            y_test=y_test,
            class_names=class_names,
            task_name=task_name,
            model_name=model_name,
            num_classes=num_classes
        )

        results.append(metrics)

    return pd.DataFrame(results)


# ============================================================
# 13. Run binary and multiclass benchmarks
# ============================================================

all_results = []

tasks = {
    "binary": BINARY_LABEL,
    "multiclass": MULTICLASS_LABEL
}

for task_name, label_column in tasks.items():
    classical_results = run_classical_benchmark(task_name, label_column)
    deep_results = run_deep_benchmark(task_name, label_column)

    task_results = pd.concat(
        [classical_results, deep_results],
        axis=0,
        ignore_index=True
    )

    task_results = task_results.sort_values(
        by="F1_macro",
        ascending=False
    )

    task_results.to_csv(
        f"{task_name}_level3_benchmark_results.csv",
        index=False
    )

    all_results.append(task_results)

final_results = pd.concat(all_results, axis=0, ignore_index=True)

final_results = final_results.sort_values(
    by=["Task", "F1_macro"],
    ascending=[True, False]
)

final_results.to_csv("all_level3_benchmark_results.csv", index=False)

print("\nFinal Level 3 benchmark results:")
print(final_results)

print("\nSaved files:")
print("- train_split_level3.csv")
print("- test_split_level3.csv")
print("- binary_level3_benchmark_results.csv")
print("- multiclass_level3_benchmark_results.csv")
print("- all_level3_benchmark_results.csv")