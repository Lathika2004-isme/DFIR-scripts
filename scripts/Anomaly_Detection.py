import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.svm import OneClassSVM
from sklearn.metrics import classification_report
import seaborn as sns

def main():
    csv=input("enter the csv file's full path :")
    df=pd.read_csv(csv)
    df.head(3)

    df = df.sort_values(by="timestamp")  # Ensure timestamps are in order

    df.head(3)

    from datetime import datetime
    df['timestamp']=pd.to_datetime(df['timestamp'],errors='coerce')
    print(df['timestamp'].isna().sum())

    df['time_last_event']=df['timestamp'].diff().dt.total_seconds().interpolate(method='linear')

    df['time_last_event'].value_counts()

    df['rolling_average']=df['time_last_event'].rolling(window=10).mean()
    df['rolling_average']=df['time_last_event'].fillna(df['rolling_average'].mean())
    df['rolling_average'].value_counts()

    df['rolling_std'] = df['time_last_event'].rolling(window=10).std()
    df['rolling_std'] = df['time_last_event'].fillna(df['rolling_std'].std())

    df['rolling_std'].value_counts()

    df['rolling_max']= df['time_last_event'].rolling(window=10).max()
    df['rolling_min'] = df['time_last_event'].rolling(window=10).min()

    df['rolling_max'].value_counts()

    df['rolling_min'].value_counts()

    df['rolling_min'].isnull().sum()

    df['rolling_max'].isnull().sum()

    df['rolling_min'].fillna(df['rolling_min'].median(), inplace=True)
    df['rolling_max'].fillna(df['rolling_max'].median(), inplace=True)

    df.drop(columns=['time_last_event'],inplace=True)
    df.drop(columns=['timestamp'],inplace=True)

    from sklearn.preprocessing import LabelEncoder
    le=LabelEncoder()
    df['protocol']=le.fit_transform(df['protocol'])
    dict(zip(le.classes_,le.transform(le.classes_)))

    import ipaddress
    df['ip_src_subnet'] = df['ip_src'].apply(lambda x: int(ipaddress.ip_network(x+'/24', strict=False).network_address))
    df['ip_dst_subnet'] = df['ip_dst'].apply(lambda x: int(ipaddress.ip_network(x+'/24', strict=False).network_address))

    df['ip_src_subnet'].value_counts()

    df['ip_dst_subnet'].value_counts()

    print(len(df['ip_src_subnet'].unique()))

    print(len(df['ip_dst_subnet'].unique()))

    df['well_known_src_port'] = df['src_port'].apply(lambda x: 1 if x <= 1023 else 0)
    df['registered_src_port'] = df['src_port'].apply(lambda x: 1 if 1024 <= x <= 49151 else 0)
    df['dynamic_src_port'] = df['src_port'].apply(lambda x: 1 if 49152 <= x <= 65535 else 0)

    df['well_known_src_port'].value_counts()

    df['registered_src_port'].value_counts()

    df['dynamic_src_port'].value_counts()

    df['well_known_dst_port'] = df['dst_port'].apply(lambda x: 1 if x <= 1023 else 0)
    df['registered_dst_port'] = df['dst_port'].apply(lambda x: 1 if 1024 <= x <= 49151 else 0)
    df['dynamic_dst_port'] = df['dst_port'].apply(lambda x: 1 if 49152 <= x <= 65535 else 0)

    df['well_known_dst_port'].value_counts()

    df['registered_dst_port'].value_counts()

    df['dynamic_dst_port'].value_counts()

    df.columns

    df.drop(columns=['ip_src','ip_dst','src_port','dst_port'],inplace=True)

    df.drop(columns=['well_known_src_port'],inplace=True)

    import pandas as pd
    from sklearn.preprocessing import  StandardScaler
    scaler=StandardScaler()
    d=pd.DataFrame(scaler.fit_transform(df),columns=df.columns)

    corr_matrix=d.corr()
    # Create heatmap
    plt.figure(figsize=(10, 8))
    sns.heatmap(corr_matrix, annot=True, cmap="coolwarm", fmt=".2f", linewidths=0.5)

    # Show plot
    plt.title("Correlation Matrix Heatmap")
    plt.show()

    d.drop(columns=['rolling_std','dynamic_dst_port','dynamic_src_port'],inplace=True)

    d.columns

    d_sample = d.sample(frac=0.4,random_state=42)

    print(d_sample.isnull().sum())

    import numpy as np
    from sklearn.svm import OneClassSVM
    from sklearn.model_selection import GridSearchCV,RandomizedSearchCV
    from sklearn.metrics import make_scorer,roc_auc_score

    def find_optimal_ocsvm_hyperparams(X, cv=3, scoring=roc_auc_score):
        """
        Finds optimal hyperparameters for One-Class SVM (OCSVM) using GridSearchCV for unsupervised learning.

        Args:
            X (array-like): The input data.
            cv (int, optional): Number of folds for cross-validation. Defaults to 5.
            scoring (str or callable, optional): Scoring metric for hyperparameter tuning.
                                                If None, it uses the default scoring method of the estimator.
                                                Defaults to None.

        Returns:
            tuple: (best_ocsvm, best_params) - The best trained OCSVM model and its best parameters.
        """

        param_grid = {
            'nu': [0.01,0.05, 0.1, 0.2, 0.5],  # Explore different values of nu
            'gamma': ['scale', 'auto', 1e-3, 1e-2, 1e-1, 1, 10],  # Explore different gamma values
            'kernel': ['rbf', 'sigmoid']  # Explore different kernels
        }

        ocsvm = OneClassSVM()

        if scoring:
            scorer = make_scorer(scoring)
            search = RandomizedSearchCV(ocsvm, param_grid, n_iter=15, cv=cv, scoring=scorer, n_jobs=-1,random_state=42)
        search.fit(X)

        best_ocsvm = search.best_estimator_
        best_params = search.best_params_

        return best_ocsvm, best_params

    best_ocsvm, best_params = find_optimal_ocsvm_hyperparams(d_sample)
    print("Best parameters found: ", best_params)
    print("Best OCSVM model: ", best_ocsvm)

    ocsvm = OneClassSVM(nu=0.1, kernel='rbf',gamma=0.001)  # Reduce nu since no anomalies
    ocsvm.fit(d)

    scores = ocsvm.decision_function(d)  # Get anomaly scores instead of just labels
    d['anomaly_score'] = scores  # Higher = more normal, lower = more anomalous

    # Set a dynamic threshold (e.g., 1st percentile of scores)
    threshold = d['anomaly_score'].quantile(0.05)
    d['is_anomaly'] = d['anomaly_score'] < threshold

    print(d['is_anomaly'].value_counts())  # Check how many anomalies were detected

    plt.figure(figsize=(8, 5))
    sns.boxplot(x=d['anomaly_score'])
    plt.title("Box Plot of Anomaly Scores")
    plt.show()

    plt.hist(d['anomaly_score'], bins=50, color='blue', edgecolor='black', alpha=0.7)
    plt.axvline(threshold, color='red', linestyle='dashed', label="Anomaly Threshold")
    plt.title("Anomaly Score Distribution")
    plt.xlabel("Anomaly Score")
    plt.ylabel("Frequency")
    plt.legend()
    plt.show()