from sqlmodel import SQLModel, Field, create_engine, Session, select, or_
import os
DATABASE_FILE = "test.db"
DATABASE_URL = f"sqlite:///{DATABASE_FILE}"
engine = create_engine(DATABASE_URL, echo=True, connect_args={"check_same_thread": False})
# Create Tables if They Don't Exist
def create_db_and_tables():
    if not os.path.exists(DATABASE_FILE):  # Only create tables if DB doesn't exist
        print("Database file not found. Creating a new one...")
        SQLModel.metadata.create_all(engine)
    else:
        print("Using existing database.")

# Dependency to Get Database Session
def get_db():
    with Session(engine) as session:
        yield session