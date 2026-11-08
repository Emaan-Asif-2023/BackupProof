from app import create_app, db

app = create_app()

with app.app_context():
    db.init_db()
    print("Database initialized successfully!")

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )
