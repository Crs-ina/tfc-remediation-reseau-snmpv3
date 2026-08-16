from app import create_app


app = create_app()


if __name__ == "__main__":
    app.run(
        host=app.config["WEBHOOK_BIND_HOST"],
        port=app.config["WEBHOOK_BIND_PORT"],
        debug=False,
    )

