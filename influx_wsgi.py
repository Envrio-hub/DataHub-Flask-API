from flask_influx import app

if __name__ == "__main__":
    app.run(host='localhost', port=5050, debug=True)
