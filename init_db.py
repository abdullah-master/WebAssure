from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
import json
import time
import sys

def init_database():
    max_retries = 3
    retry_delay = 2  # seconds

    for attempt in range(max_retries):
        try:
            # Load MongoDB configuration
            with open('mongo_config.json') as f:
                config = json.load(f)
            
            # Connect to MongoDB with short timeout
            client = MongoClient(config['mongo_uri'], serverSelectionTimeoutMS=5000)
            
            # Test connection
            client.admin.command('ping')
            
            db = client[config['database']]
            collection = db[config['collection']]
            
            # Create collection if it doesn't exist
            if config['collection'] not in db.list_collection_names():
                db.create_collection(config['collection'])
                print(f"Collection {config['collection']} created successfully")
            
            # Create indexes for better query performance
            collection.create_index('timestamp')
            collection.create_index('target_url')
            collection.create_index([
                ('scan_metrics.zap.high_risks', 1),
                ('scan_metrics.zap.medium_risks', 1),
                ('scan_metrics.zap.low_risks', 1)
            ])
            
            print("Database initialized successfully with required indexes")
            return True
            
        except ConnectionFailure:
            if attempt < max_retries - 1:
                print(f"Connection attempt {attempt + 1} failed. Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print("Error: Could not connect to MongoDB.")
                print("Please ensure MongoDB is installed and running.")
                print("On Windows, you can start MongoDB with: net start MongoDB")
                return False
                
        except Exception as e:
            print(f"Error initializing database: {e}")
            return False

if __name__ == "__main__":
    success = init_database()
    sys.exit(0 if success else 1)
