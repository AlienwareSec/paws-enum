# paws-enum - AWS Enumeration Script

## Overview

This script performs AWS enumeration for IAM, S3, and EC2 resources using a specified AWS CLI profile. It retrieves detailed information about IAM users, groups, policies, S3 buckets, and EC2 instances, saving the output to a timestamped file.

[Watch Demo Video](https://github.com/AlienwareSec/paws-enum/blob/main/paws-enum.mp4)

## Features

- **IAM Enumeration:**
  - Account summary
  - List groups for a user
  - List and detail attached and inline policies for groups
  - List attached and inline user policies
  - List roles available to assume

- **S3 Enumeration:**
  - List all S3 buckets
  - Check and display S3 bucket policies
  - Check and display S3 bucket ACLs

- **EC2 Enumeration:**
  - Describe EC2 instances
  - Retrieve detailed information including instance name, security groups, instance ID, availability zone, state,

## Usage

### Prerequisites
- AWS CLI must be installed and configured on your machine.
- jq command-line JSON processor must be installed.

### Profile Setup
1. **Install AWS CLI:** Follow the instructions [here](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html) to install AWS CLI.
2. **Configure AWS CLI:** Set up your AWS CLI profile by running:
    ```bash
    aws configure --profile <profile_name>
    ```
    Replace `<profile_name>` with your desired profile name and enter your AWS credentials.

3. **Install jq:** Follow the instructions [here](https://stedolan.github.io/jq/download/) to install jq.

### Running the Script
1. **Save the Script:**
   Save the script to a file, e.g., `aws_enum.sh`.
2. **Make the Script Executable:**
   ```bash
   chmod +x pawsenum.sh
   ```
3. **Run the Script:**
   ```bash
   ./pawsenum.sh <profile_name>
   ```
   Replace `<profile_name>` with the AWS CLI profile name you set up.

### Output File
  -  The script saves the output in a file named in the format: ```<profile_name>_enum_<YYYY-MM-DD_HH-MM-SS>.txt```
