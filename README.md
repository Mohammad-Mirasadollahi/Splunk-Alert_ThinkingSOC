# ThinkingSOC Alert Action for Splunk

## Overview

This Splunk Alert Action integrates your Splunk alerts with the [ThinkingSOC API Server](https://github.com/Mohammad-Mirasadollahi/ThinkingSOC). When a Splunk alert triggers, this action formats the alert metadata and results, and sends them via an HTTP POST request (webhook) to your configured ThinkingSOC API endpoint for further analysis using Ollama LLMs.

This allows you to leverage the analytical capabilities of ThinkingSOC directly from your Splunk alert workflow.

## Prerequisites

*   **Splunk Enterprise:** Version 9.x recommended.
*   **ThinkingSOC API Server:** A running and network-accessible instance of the ThinkingSOC API server. You will need its webhook URL.

## Installation

1.  **Download/Clone:** Obtain the Alert Action files.
2.  **Install like other apps:** Download the app package, navigate to the Splunk web interface, go to the "Apps" section, click "Install app from file," select the package, and restart Splunk if necessary.
3.  **Restart Splunk:** Restart your Splunk Search Head(s) for the new Alert Action to be recognized.

## Configuration (Per Alert)

Once installed, you can configure this action when setting up or editing a specific Splunk alert. After adding "ThinkingSOC" as a Trigger Action for your alert, you will see the following configuration fields:

---

1.  **URL**
    *   **Label:** `URL`
    *   **Description:** This is the **most important** field. Enter the complete URL of your ThinkingSOC API server's webhook endpoint.
    *   **Required:** Yes
    *   **Format:** `http://<thinkingsoc_ip_or_hostname>:<port>/api/v1/webhook`
    *   **Example:** `http://192.168.1.200:8001/api/v1/webhook`
    *   **Note:** Ensure this URL is reachable from your Splunk Search Head.

2.  **Username**
    *   **Label:** `Username`
    *   **Description:** Enter the username for Basic Authentication **if** your ThinkingSOC API server requires it. Leave blank if no authentication is needed.
    *   **Required:** No (Optional)
    *   **Example:** `splunk_user`

3.  **Password**
    *   **Label:** `Password`
    *   **Description:** Enter the password for Basic Authentication **if** your ThinkingSOC API server requires it. Leave blank if no authentication is needed. This will be stored as part of the Splunk alert configuration (Splunk typically masks/encrypts saved credentials).
    *   **Required:** No (Optional)

4.  **Description**
    *   **Label:** `Description`
    *   **Description:** Provide a static, short description for the alert itself. This description will be included in the payload sent to ThinkingSOC.
    *   **Required:** No (Optional)
    *   **Example:** `High severity firewall block detected`

5.  **Severity**
    *   **Label:** `Severity`
    *   **Description:** Select a static severity level to associate with alerts triggered by this specific Splunk search. This helps categorize the alert within ThinkingSOC.
    *   **Required:** No (Optional - defaults to None/Empty)
    *   **Options:** `(None)`, `Info`, `Low`, `Medium`, `High`, `Critical`
    *   **Example:** Select `High` from the dropdown.

6.  **MITRE Tactics**
    *   **Label:** `MITRE Tactics`
    *   **Description:** Optionally associate one or more static MITRE ATT&CK Tactic IDs with this alert. Use commas to separate multiple tactics.
    *   **Required:** No (Optional)
    *   **Example:** `TA0002, TA0003` (for Execution, Persistence)

7.  **MITRE Techniques**
    *   **Label:** `MITRE Techniques`
    *   **Description:** Optionally associate one or more static MITRE ATT&CK Technique IDs (and sub-technique IDs) with this alert. Use commas to separate multiple techniques.
    *   **Required:** No (Optional)
    *   **Example:** `T1059.001, T1547.001` (for PowerShell, Boot or Logon Autostart Execution: Registry Run Keys)

---

## Usage

1.  Create or edit a Saved Search/Alert in Splunk.
2.  Define your search query and trigger conditions as usual.
3.  Under the "Trigger Actions" section, click "Add Actions" and select "ThinkingSOC".
4.  Fill in the configuration fields described above (URL, Description, Severity, etc.) specific to this alert's context.
5.  Save the alert.
