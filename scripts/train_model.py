from wids.training import train

if __name__ == "__main__":
    print(train("data/processed/windows.csv")["metrics"])
