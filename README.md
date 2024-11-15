Static Rule Based approaches :
------------------------------

1. High Transaction Amounts
Rule: Flag transactions exceeding a predefined threshold (e.g., $4,000). This threshold can be determined by rule/decision engineering based on historical patterns.
Why: High-value transactions are less common and may indicate fraud (e.g., stolen card usage or unauthorized purchases). 

2. Multiple Transactions in a Short Time Frame
Rule: Flag users who make more than a certain number of transactions (e.g., 5) within a short time window (e.g., 1 minute).
Why: Fraudsters often exploit stolen cards or compromised accounts to make as many transactions as possible before detection, especially with small amounts to avoid triggering alerts.

3. Unusual Merchant Interactions
Rule: Flag transactions where a user interacts with a merchant for the first time, combined with additional checks (e.g., high transaction amount).
Why:  Fraudulent behavior often involves purchases from unfamiliar or high-risk merchants. Combine with conditions like:
a. High transaction amount.
b. Minimum user transaction history to reduce false positives. 

4. Repeated Transactions of the Same Amount
Rule: Flag repeated identical transactions (same user, merchant, and amount) occurring more than a certain number of times within a specified time window.
Why: Fraudsters or errors in payment processing systems may cause repeated transactions/reties, leading to exploitation of system vulnerabilities.

5. Sudden Spending Pattern Changes
Rule: Flag transactions deviating significantly from a user’s historical spending pattern (e.g., more than 3 times the standard deviation).
Why: Detect anomalies in user behavior, such as unusually high-value transactions that deviate from the norm. This is advanced part of rule#1.


ML Algorithms Based approaches :
--------------------------------

1. Behavioral Profiling: Build user-specific models to predict "normal" behavior based on historical data. 
For example, train models for each user to predict: Typical spending amounts , Common merchants. Transaction frequencies , Flag deviations as anomalies.

2. Graph-Based Approaches: Model relationships between users, merchants, and transactions as a graph (using graph databases).
Use clustering algorithms to detect suspicious patterns (e.g., collusion between merchants and fraudulent users) Or Analyze connections (e.g., who transacts with whom) using 1-hop or 2-hop links to detect unusual activity nearby.

3. Risk Scoring: Assign a fraud risk score to each transaction using a logistic regression or gradient boosting model. Combine static rules with features like:
Historical spending patterns.
Geographical information.
Time-of-day activity.