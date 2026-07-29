def calculate_risk(alert):
    rule = alert.get("rule", {})
    level = int(rule.get("level", 0))

    if level >= 12:
        return "🔴 Critical"

    elif level >= 8:
        return "🟠 High"

    elif level >= 5:
        return "🟡 Medium"

    else:
        return "🟢 Low"
