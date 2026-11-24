"""Measure compressed ALB log volume without reading or changing S3 objects."""

import argparse
from datetime import date, timedelta
import json
import subprocess
import sys


def measure_day(args, prefix):
    command = [
        "aws", "s3api", "list-objects-v2",
        "--bucket", args.bucket,
        "--expected-bucket-owner", args.account_id,
        "--region", args.region,
        "--prefix", prefix,
        "--no-paginate",
        "--no-cli-pager",
        "--output", "json",
    ]
    object_count = 0
    compressed_bytes = 0
    token = None
    while True:
        pagination = ["--continuation-token", token] if token else []
        response = subprocess.run(command + pagination, capture_output=True, text=True, check=True)
        page = json.loads(response.stdout)
        for item in page.get("Contents", []):
            filename = item["Key"].rsplit("/", 1)[-1]
            if "_app." in filename and filename.endswith(".log.gz"):
                object_count += 1
                compressed_bytes += item["Size"]
        token = page.get("NextContinuationToken")
        if not token:
            return {"objects": object_count, "compressed_bytes": compressed_bytes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bucket", required=True)
    parser.add_argument("--account-id", required=True)
    parser.add_argument("--region", required=True)
    parser.add_argument("--prefix", default="alb-access")
    parser.add_argument("--start", required=True, type=date.fromisoformat, help="First UTC delivery date (YYYY-MM-DD)")
    parser.add_argument("--end", required=True, type=date.fromisoformat, help="Last UTC delivery date (inclusive)")
    args = parser.parse_args()
    if args.start > args.end:
        parser.error("--end must be on or after --start")
    if not (args.account_id.isascii() and args.account_id.isdigit() and len(args.account_id) == 12):
        parser.error("--account-id must contain 12 digits")

    root = f"AWSLogs/{args.account_id}/elasticloadbalancing/{args.region}"
    if args.prefix.strip("/"):
        root = f"{args.prefix.strip('/')}/{root}"
    days = []
    try:
        for offset in range((args.end - args.start).days + 1):
            day = args.start + timedelta(days=offset)
            counts = measure_day(args, f"{root}/{day:%Y/%m/%d}/")
            days.append({"delivery_date_utc": day.isoformat(), **counts})
    except subprocess.CalledProcessError as error:
        print(error.stderr.strip(), file=sys.stderr)
        return 1
    except FileNotFoundError:
        print("Install the AWS CLI and make sure aws is on PATH.", file=sys.stderr)
        return 1

    print(json.dumps({
        "days": days,
        "objects": sum(day["objects"] for day in days),
        "compressed_bytes": sum(day["compressed_bytes"] for day in days),
    }, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
