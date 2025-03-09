#!/usr/bin/env python
# reset_db_direct.py - Truncate all tables in the database without running migrations
# WARNING: This script will DELETE ALL DATA from your database!

import os
import sys
from pathlib import Path

# Add the backend directory to the Python path
backend_dir = Path(__file__).parent.parent / "backend"
sys.path.append(str(backend_dir))

# Import SQLAlchemy directly without triggering migrations
from sqlalchemy import create_engine, text
from open_webui.env import DATABASE_URL, DATABASE_SCHEMA

# Check if this is a production database
if "prod" in DATABASE_URL.lower():
    print("\n" + "=" * 80)
    print(f"ERROR: This appears to be a PRODUCTION database: {DATABASE_URL}")
    print("For safety reasons, this script will not reset production databases.")
    print("=" * 80 + "\n")
    sys.exit(1)

# Ask for confirmation before proceeding
print("\n" + "=" * 80)
print(f"WARNING: You are about to reset the database at: {DATABASE_URL}")
print("This will DELETE ALL DATA from your database!")
print("=" * 80 + "\n")

confirm = input("Are you sure you want to proceed? This cannot be undone! (yes/no): ")
if confirm.lower() != "yes":
    print("Operation cancelled. No changes were made.")
    sys.exit(0)

print(f"Resetting database at: {DATABASE_URL}")

try:
    # Create a direct connection to the database without using the shared engine
    engine = create_engine(DATABASE_URL)
    
    with engine.connect() as connection:
        # Start a transaction
        with connection.begin():
            # Get all table names
            if "postgresql" in DATABASE_URL:
                schema = DATABASE_SCHEMA or "public"
                print(f"Using schema: {schema}")
                
                result = connection.execute(text(
                    f"SELECT tablename FROM pg_tables WHERE schemaname = '{schema}'"
                ))
                tables = [row[0] for row in result]
                
                if not tables:
                    print(f"No tables found in schema '{schema}'. Nothing to truncate.")
                    sys.exit(0)
                    
                print(f"Found {len(tables)} tables to truncate.")
                
                # Try to truncate each table individually with CASCADE option
                # This approach doesn't require superuser privileges
                for table in tables:
                    try:
                        print(f"Truncating table: {table}")
                        connection.execute(text(f'TRUNCATE TABLE "{schema}"."{table}" CASCADE;'))
                    except Exception as e:
                        print(f"Warning: Could not truncate {table} with CASCADE: {e}")
                        try:
                            # Try simple DELETE as fallback
                            print(f"Trying DELETE FROM {table} instead...")
                            connection.execute(text(f'DELETE FROM "{schema}"."{table}";'))
                        except Exception as e2:
                            print(f"Error truncating {table}: {e2}")
                            print(f"Skipping table {table}")
                
                print("Table truncation completed.")
                
            elif "sqlite" in DATABASE_URL:
                # For SQLite, we need a different approach
                result = connection.execute(text(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE 'alembic_%'"
                ))
                tables = [row[0] for row in result]
                
                if not tables:
                    print("No tables found. Nothing to truncate.")
                    sys.exit(0)
                    
                print(f"Found {len(tables)} tables to truncate.")
                
                # Disable foreign keys temporarily
                connection.execute(text("PRAGMA foreign_keys = OFF;"))
                
                # Truncate all tables
                for table in tables:
                    print(f"Truncating table: {table}")
                    connection.execute(text(f'DELETE FROM "{table}";'))
                
                # Re-enable foreign keys
                connection.execute(text("PRAGMA foreign_keys = ON;"))
                
                print("All tables truncated successfully.")
            else:
                print(f"Unsupported database type: {DATABASE_URL}")
                sys.exit(1)

    print("Database reset complete!")
    
except Exception as e:
    print(f"Error resetting database: {e}")
    sys.exit(1)
