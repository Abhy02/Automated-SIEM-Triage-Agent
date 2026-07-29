MITRE_MAPPING = {

    # SSH Authentication
    5715: {
        "technique": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion"
    },

    # PAM Login
    5501: {
        "technique": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion"
    },

    5502: {
        "technique": "T1078",
        "name": "Valid Accounts",
        "tactic": "Defense Evasion"
    },

    # Netstat
    533: {
        "technique": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery"
    }
}

def get_mitre(rule_id):

    return MITRE_MAPPING.get(
        rule_id,
        {
            "technique": "Unknown",
            "name": "Unknown",
            "tactic": "Unknown"
        }
    )
