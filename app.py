from services.alert_service import analyze_latest_alert
from parser.alert_parser import display


def main():
    result = analyze_latest_alert()

    if result is None:
        print("No alerts found.")
        return

    display(
        result["alert"],
        result["risk"],
        result["iocs"],
        result["intel"],
        result["mitre"],
        result["report"],
    )


if __name__ == "__main__":
    main()
