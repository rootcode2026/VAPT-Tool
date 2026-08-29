from app.scanner.profiles import get_scanners_for_profile


def main():

    profiles = [
        "quick",
        "web",
        "full",
    ]

    for profile in profiles:

        scanners = get_scanners_for_profile(profile)

        print(
            f"{profile}: {scanners}"
        )

    print("\nTesting invalid profile:")

    try:
        get_scanners_for_profile("invalid")
    except ValueError as exc:
        print(f"Correctly rejected: {exc}")


if __name__ == "__main__":
    main()