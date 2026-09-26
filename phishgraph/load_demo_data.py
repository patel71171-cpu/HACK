import os
from pathlib import Path

import pandas as pd
from dotenv import load_dotenv
import snowflake.connector

load_dotenv()

DB = os.getenv("SNOWFLAKE_DATABASE", "PHISHGRAPH_DB")
SCHEMA = os.getenv("SNOWFLAKE_SCHEMA", "PUBLIC")
WAREHOUSE = os.getenv("SNOWFLAKE_WAREHOUSE", "")
ROLE = os.getenv("SNOWFLAKE_ROLE", "")


def connect():
    kwargs = {
        "account": os.environ["SNOWFLAKE_ACCOUNT"],
        "user": os.environ["SNOWFLAKE_USER"],
        "password": os.environ["SNOWFLAKE_PASSWORD"],
        "database": DB,
        "schema": SCHEMA,
    }
    if WAREHOUSE:
        kwargs["warehouse"] = WAREHOUSE
    if ROLE:
        kwargs["role"] = ROLE
    return snowflake.connector.connect(**kwargs)


def main():
    csv_path = Path(__file__).parent / "data" / "phishing_messages.csv"
    df = pd.read_csv(csv_path)

    conn = connect()
    cur = conn.cursor()
    try:
        cur.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {DB}.{SCHEMA}.DEMO_MESSAGES (
                MESSAGE_ID VARCHAR,
                SENDER_DOMAIN VARCHAR,
                SUBJECT VARCHAR,
                MESSAGE_TEXT VARCHAR,
                NUM_LINKS INTEGER,
                SUSPICIOUS_KEYWORDS INTEGER,
                DOMAIN_RISK FLOAT,
                SENDER_KNOWN BOOLEAN
            )
            """
        )
        cur.execute(f"TRUNCATE TABLE {DB}.{SCHEMA}.DEMO_MESSAGES")

        sql = f"""
        INSERT INTO {DB}.{SCHEMA}.DEMO_MESSAGES
        (MESSAGE_ID, SENDER_DOMAIN, SUBJECT, MESSAGE_TEXT,
         NUM_LINKS, SUSPICIOUS_KEYWORDS, DOMAIN_RISK, SENDER_KNOWN)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
        """

        rows = [
            (
                str(r.message_id),
                str(r.sender_domain),
                str(r.subject),
                str(r.message_text),
                int(r.num_links),
                int(r.suspicious_keywords),
                float(r.domain_risk),
                str(r.sender_known).lower() == "true",
            )
            for r in df.itertuples(index=False)
        ]
        cur.executemany(sql, rows)
        conn.commit()
        print(f"Loaded {len(rows)} synthetic messages into DEMO_MESSAGES.")
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    main()
