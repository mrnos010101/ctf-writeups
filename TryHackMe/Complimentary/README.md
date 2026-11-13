Overview

A serverless wellness application hosted entirely on AWS (S3 static site + Cognito Identity Pool + DynamoDB). The app has no backend server — the browser talks directly to AWS services using temporary credentials issued silently by Cognito. The vulnerability is a misconfigured IAM policy on the unauthenticated role that allows a full table scan instead of restricting access to the caller's own records.
