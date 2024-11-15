import csv
from datetime import datetime, timedelta
from collections import defaultdict


class FraudDetection:
    def __init__(self, input_file):
        self.input_file = input_file
        self.transactions = []
        self.flagged_transactions = []

    def load_transactions(self):
        """Load transactions from a CSV file."""
        with open(self.input_file, 'r') as file:
            reader = csv.DictReader(file)
            for row in reader:
                self.transactions.append({
                    "user_id": row["user_id"],
                    "timestamp": datetime.strptime(row["timestamp"], '%Y-%m-%d %H:%M:%S'),
                    "merchant_name": row["merchant_name"],
                    "amount": float(row["amount"])
                })

    def detect_high_transaction_amount(self,
                                       threshold=4500):  ## thres can be determinded by rule engine/decision teams based on prior experience.
        """
        RULE 1: Flag transactions exceeding the threshold.
        """
        for transaction in self.transactions:
            if transaction["amount"] > threshold:
                self.flagged_transactions.append({**transaction, "rule": "High Amount"})

    def detect_multiple_transactions_in_short_time(self, time_window=60, max_transactions=5):
        """RULE 2: Flag users making more than 'max_transactions' in 'time_window' (seconds)."""
        user_transactions = defaultdict(list)
        for transaction in self.transactions:
            user_transactions[transaction["user_id"]].append(transaction["timestamp"])

        for user, timestamps in user_transactions.items():  # Looping through users and their transactions
            timestamps.sort()
            for i in range(len(timestamps) - max_transactions + 1):  # slidig windw to check burst
                if (timestamps[i + max_transactions - 1] - timestamps[i]).total_seconds() <= time_window:
                    for t in self.transactions:  # flag txn from original list
                        if t["user_id"] == user and t["timestamp"] in timestamps[i:i + max_transactions]:
                            self.flagged_transactions.append({**t, "rule": "Multiple Transactions in Short Time"})

    def detect_repeated_transactions(self, time_window=600, min_repeated=3):
        """
        RULE 3: Flag repeated identical transactions within 'time_window' (seconds) and if there are more than 'min_repeated' such transactions.
        """
        transaction_map = defaultdict(list)

        # Group timestamps by (user_id, merchant_name, amount)
        for transaction in self.transactions:
            key = (
            transaction["user_id"], transaction["merchant_name"], transaction["amount"])  # Same user, merchant, amount
            transaction_map[key].append(transaction["timestamp"])

        for key, timestamps in transaction_map.items():
            timestamps.sort()  # Sort timestamps for checking
            start = 0
            # sliding window approach to check for repeated transactions
            for end in range(len(timestamps)):
                while (timestamps[end] - timestamps[start]).total_seconds() > time_window:
                    start += 1
                # If the number of transactions in the window exceeds min_repeated, then flag all those txns.
                if end - start + 1 >= min_repeated:
                    for t in self.transactions:
                        if (t["user_id"], t["merchant_name"], t["amount"]) == key and t["timestamp"] in timestamps[
                                                                                                        start:end + 1]:
                            self.flagged_transactions.append({**t, "rule": "Repeated Transactions"})
                    break

    def detect_unusual_merchants(self, amount_threshold=2000, min_transaction_history=5):
        """
        RULE 4: Flag users interacting with a new merchant under specific conditions:
        1. The transaction amount exceeds 'amount_threshold'.
        2. The user has more than 'min_transaction_history' previous transactions.
        """
        # Track user-merchant interaction history
        merchant_history = defaultdict(set)
        user_transaction_counts = defaultdict(int)

        for transaction in self.transactions:
            user_id = transaction["user_id"]
            merchant_name = transaction["merchant_name"]
            amount = transaction["amount"]

            # Increment user's transaction count
            user_transaction_counts[user_id] += 1

            # Check if the merchant is new and the conditions are met
            if (merchant_name not in merchant_history[user_id] and
                    amount > amount_threshold and
                    user_transaction_counts[user_id] > min_transaction_history):
                # Flag the transaction
                self.flagged_transactions.append({**transaction, "rule": "Unusual Merchant"})

            merchant_history[user_id].add(merchant_name)

    def detect_sudden_spending_pattern_changes(self, deviation_threshold=3, min_transactions=5):
        """
        RULE 5: Flag transactions deviating significantly from historical spending.
        Flags only if the user has at least 'min_transactions' in their history.
        """
        user_spending = defaultdict(list)

        # Collect all transaction amounts for each user
        for transaction in self.transactions:
            user_spending[transaction["user_id"]].append(transaction["amount"])

        # Compute average spending and variance for each user
        user_stats = {}
        for user, amounts in user_spending.items():
            if len(amounts) >= min_transactions:
                avg = sum(amounts) / len(amounts)
                variance = sum((x - avg) ** 2 for x in amounts) / len(amounts)
                std_dev = variance ** 0.5
                user_stats[user] = {"average": avg, "std_dev": std_dev}

        # Flag transactions that deviate significantly
        for transaction in self.transactions:
            user_id, amount = transaction["user_id"], transaction["amount"]
            if user_id in user_stats:
                avg = user_stats[user_id]["average"]
                std_dev = user_stats[user_id]["std_dev"]
                if amount > avg + deviation_threshold * std_dev:
                    self.flagged_transactions.append({**transaction, "rule": "Sudden Spending Pattern Change"})

    def save_flagged_transactions(self, output_file):
        """Save flagged transactions to a CSV file."""
        if self.flagged_transactions:
            fieldnames = ["user_id", "timestamp", "merchant_name", "amount", "rule"]
            with open(output_file, 'w', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(self.flagged_transactions)
            print(f"Flagged transactions saved to {output_file}")
        else:
            print("No flagged transactions to save.")

    def run_rules(self):
        """Run all fraud detection rules."""
        self.detect_high_transaction_amount()
        self.detect_multiple_transactions_in_short_time()
        self.detect_unusual_merchants()
        self.detect_repeated_transactions()
        self.detect_sudden_spending_pattern_changes()


# Usage
if __name__ == "__main__":
    input_file = "fraud_detection_test_data.csv"
    output_file = "fraud_detection_test_data_results.csv"
    fraud_detection = FraudDetection(input_file)
    fraud_detection.load_transactions()
    fraud_detection.run_rules()
    fraud_detection.save_flagged_transactions(output_file)