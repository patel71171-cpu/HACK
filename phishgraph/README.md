# 🛡️ PhishGraph — Explainable Phishing Risk Detector

PhishGraph is a **Snowflake-powered cybersecurity prototype** that analyzes an email/message and produces an explainable phishing-risk score.

It is designed for a short hackathon/demo rather than production antivirus use.

## Architecture

```text
User
  │
  ▼
Streamlit UI
  │
  ▼
Python + Snowflake Connector
  │
  ▼
Snowflake
  ├── MESSAGES
  ├── MESSAGE_FEATURES
  └── RISK_RESULTS
  │
  ├── SQL feature engineering
  ├── Cortex AI → urgency/manipulation/threat analysis
  └── Transparent weighted risk calculation
  │
  ▼
Streamlit result
  ├── Risk score
  ├── Risk level
  ├── Score breakdown
  ├── Suspicious indicators
  └── Short explanation
```

## Risk formula

```text
risk_score =
    30% suspicious keywords
  + 25% unknown sender
  + 20% risky links
  + 15% urgency language
  + 10% domain risk
```

The final score is deliberately transparent. Cortex does **not** replace the scoring formula; it supplies natural-language signals such as urgency and manipulation and a short explanation.

## Features

- Paste an email/message.
- Store the analyzed message in Snowflake.
- Detect suspicious keywords.
- Count links.
- Account for known/unknown sender status.
- Use a demo domain-risk value.
- Use Snowflake Cortex `AI_COMPLETE` for natural-language analysis.
- Fall back to local rules if Cortex is unavailable.
- Calculate a 0–100 explainable risk score.
- Show the contribution of every scoring signal.
- Store analysis results in Snowflake.
- Include a synthetic CSV demonstration dataset.

## Project structure

```text
phishgraph/
├── app.py
├── setup.sql
├── load_demo_data.py
├── requirements.txt
├── .env.example
├── .gitignore
├── README.md
└── data/
    └── phishing_messages.csv
```

## 1. Create the Snowflake objects

Open Snowflake Snowsight and run:

```sql
-- Copy the complete setup.sql file into a worksheet.
```

The script creates:

```text
PHISHGRAPH_DB
└── PUBLIC
    ├── MESSAGES
    ├── MESSAGE_FEATURES
    └── RISK_RESULTS
```

The application can also create these objects automatically when it connects.

## 2. Check Cortex model availability

Run:

```sql
SHOW CORTEX BASE MODELS;
```

The repository defaults to:

```text
snowflake-arctic
```

If your account does not have that model available, change `CORTEX_MODEL` in `.env` to a model available to your account.

For example, current Snowflake documentation lists multiple text models for `AI_COMPLETE`, but model availability can vary by account/region/lifecycle.

## 3. Create the Python environment

### Windows PowerShell

```powershell
cd path\to\phishgraph

py -m venv .venv
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

If PowerShell blocks activation, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

### macOS/Linux

```bash
cd path/to/phishgraph

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

## 4. Configure Snowflake

Copy:

```text
.env.example
```

to:

```text
.env
```

Then edit:

```env
SNOWFLAKE_ACCOUNT=your_account_identifier
SNOWFLAKE_USER=your_username
SNOWFLAKE_PASSWORD=your_password
SNOWFLAKE_WAREHOUSE=COMPUTE_WH
SNOWFLAKE_DATABASE=PHISHGRAPH_DB
SNOWFLAKE_SCHEMA=PUBLIC
SNOWFLAKE_ROLE=
CORTEX_MODEL=snowflake-arctic
```

### Important

Do **not** commit `.env` to GitHub.

It is already included in `.gitignore`.

The Snowflake account value should be the account identifier, not the full `snowflakecomputing.com` URL.

## 5. Test Snowflake connection

Run:

```powershell
python -c "from dotenv import load_dotenv; load_dotenv(); import snowflake.connector, os; c=snowflake.connector.connect(account=os.environ['SNOWFLAKE_ACCOUNT'], user=os.environ['SNOWFLAKE_USER'], password=os.environ['SNOWFLAKE_PASSWORD']); print(c.cursor().execute('SELECT CURRENT_ACCOUNT(), CURRENT_USER()').fetchone()); c.close()"
```

You should see your Snowflake account and username.

## 6. Load the synthetic dataset

Run:

```powershell
python load_demo_data.py
```

Expected:

```text
Loaded 8 synthetic messages into DEMO_MESSAGES.
```

The CSV contains deliberately synthetic phishing/non-phishing examples.

## 7. Start the application

```powershell
streamlit run app.py
```

Open the URL Streamlit prints, normally:

```text
http://localhost:8501
```

## 8. Test the demo

Click:

```text
Load demo phishing message
```

It loads:

```text
URGENT: Your account will be deleted today.
Click here immediately to verify.
```

Then click:

```text
Analyze Message
```

You should see signals such as:

- suspicious keywords
- a detected link if one is present
- unknown sender
- urgency language
- domain risk
- risk score
- short explanation

## Cortex fallback

The app attempts Snowflake Cortex first.

If Cortex fails because of:

- model availability
- privileges
- region availability
- network/authentication problems
- account configuration

the app automatically uses local deterministic rules for urgency/manipulation so the demo can continue.

The UI tells you whether the analysis came from:

```text
snowflake_cortex
```

or:

```text
local_fallback
```

## Snowflake tables

### MESSAGES

Raw message information:

```text
MESSAGE_ID
SENDER_DOMAIN
SUBJECT
MESSAGE_TEXT
NUM_LINKS
SUSPICIOUS_KEYWORDS
DOMAIN_RISK
SENDER_KNOWN
CREATED_AT
```

### MESSAGE_FEATURES

Normalized features:

```text
KEYWORD_SCORE
UNKNOWN_SENDER_SCORE
LINK_SCORE
URGENCY_SCORE
DOMAIN_SCORE
CORTEX_RAW
```

### RISK_RESULTS

Explainable result:

```text
KEYWORD_POINTS
UNKNOWN_SENDER_POINTS
LINK_POINTS
URGENCY_POINTS
DOMAIN_POINTS
RISK_SCORE
RISK_LEVEL
EXPLANATION
```

## Example SQL to inspect results

```sql
SELECT *
FROM PHISHGRAPH_DB.PUBLIC.RISK_RESULTS
ORDER BY CREATED_AT DESC;
```

To inspect stored messages:

```sql
SELECT *
FROM PHISHGRAPH_DB.PUBLIC.MESSAGES
ORDER BY CREATED_AT DESC;
```

## Security / scope note

This is a **demonstration cybersecurity application**.

The domain-risk values in the included dataset are synthetic. They are not live threat-intelligence/reputation results.

The application should not be presented as a production antivirus, mail gateway, or definitive phishing classifier.

A risk score means that the message contains signals associated with phishing; it does not prove that a message is malicious.

## Suggested hackathon explanation

> PhishGraph uses Snowflake as the central data and analytics layer. A message is stored with metadata, converted into normalized risk features, analyzed with Snowflake Cortex for natural-language signals such as urgency and manipulation, and scored using a transparent weighted SQL formula. The UI exposes the individual contributions instead of hiding the decision behind a black-box prediction.

## Future improvements

For a larger version, add:

- real domain-age API
- real domain reputation feed
- URL reputation service
- SPF/DKIM/DMARC metadata
- attachment analysis
- historical sender behavior
- ML classifier trained on a labeled dataset
- Snowflake tasks/streams for batch processing
- authentication and user accounts
- audit logging
- dashboard of historical risk results

---

## License

Use this repository for educational, hackathon, and prototype purposes.
