from typing import Dict, Any, Optional


class Workflow:
    """Manages workflow configurations for different processing types."""

    workflows = {
        "quarantine": {
            "expect": True,
            "extra_subject": "Quarantined",
            "extra_body": None,
            "folder": False,
            "headers": False,
        },
        "promotion": {
            "expect": True,
            "extra_subject": None,
            "extra_body": None,
            "folder": "PromotionsAutomation",
            "headers": False,
        },
        "Spam": {
            "expect": True,
            "extra_subject": "Spam",
            "extra_body": None,
            "folder": False,
            "headers": False,
        },
        "junk": {
            "expect": True,
            "extra_subject": None,
            "extra_body": None,
            "folder": "Junk Email",
            "headers": False,
        },
        "header": {
            "expect": True,
            "extra_subject": None,
            "extra_body": None,
            "folder": False,
            "headers": {"header key": "header value"},
        },
        "admin": {
            "expect": False,
            "extra_subject": None,
            "extra_body": None,
            "folder": False,
            "headers": False,
        },
        "alert": {
            "expect": True,
            "extra_subject": "Phishing Alert!",
            "extra_body": ["Warning", "<strong>"],
            "folder": False,
            "headers": False,
        },
        "None": {"expect": False}
    }

    def retrieve_workflow(self, workflow_type: str) -> Dict[str, Any]:
        """
        Retrieve workflow configuration by type.

        Args:
            workflow_type: Type of workflow to retrieve

        Returns:
            Workflow configuration dictionary
        """
        return self.workflows.get(workflow_type, {
            "expect": True,
            "extra_subject": None,
            "extra_body": None,
            "folder": False,
            "headers": False,
        })
