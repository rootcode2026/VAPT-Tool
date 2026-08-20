import docker


def test_docker_connection():
    client = docker.from_env()

    info = client.info()

    print("Docker connection successful")
    print(f"Docker server version: {info.get('ServerVersion')}")


if __name__ == "__main__":
    test_docker_connection()