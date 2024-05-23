#!/bin/bash

# Check if profile name is provided as command-line argument
if [ $# -ne 1 ]; then
    echo -e "\033[0;31mUsage: $0 <profile_name>\033[0m"
    exit 1
fi

# Define colors
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

profile_name="$1"
current_time=$(date +"%Y-%m-%d_%H-%M-%S")
output_file="${profile_name}_enum_${current_time}.txt"

# Function to perform IAM enumerations

iam_enumeration() {
    echo -e "${YELLOW}IAM Enumeration:${NC}"

    # Get account summary
    echo -e "${YELLOW}[!] Checking Account Summary:${NC}"
    account_summary=$(aws iam get-account-summary --profile "$profile_name" 2>&1)
    if echo "$account_summary" | grep -q "AccessDenied"; then
        echo -e "${RED}[-] Access Denied${NC}\n"
    else
        echo -e "${GREEN}[+] Account Summary:${NC}" | tee -a "$output_file"
        echo "$account_summary" | jq -r '.SummaryMap | 
            "Policies: \(.Policies)\nInstanceProfiles: \(.InstanceProfiles)\nUsers: \(.Users)\nAccountMFAEnabled: \(.AccountMFAEnabled)\nAccessKeysPerUserQuota: \(.AccessKeysPerUserQuota)\nGroups: \(.Groups)\nMFADevices: \(.MFADevices)\nRoles: \(.Roles)\n"' | tee -a "$output_file"
    fi

    echo -e "${YELLOW}[!] Listing Groups for User:${NC}"
    groups=$(aws iam list-groups-for-user --profile "$profile_name" --user-name "$1" 2>&1)
    if echo "$groups" | grep -q "AccessDenied"; then
        echo -e "${RED}[-] Access Denied${NC}\n"
    else
        group_names=$(echo "$groups" | jq -r '.Groups[].GroupName')
        if [ -z "$group_names" ]; then
            echo -e "${RED}[-] No groups found${NC}\n"
        else
            echo -e "${GREEN}[+] Groups found:${NC}" | tee -a "$output_file"
            echo "$group_names" | tee -a "$output_file"
            echo "" | tee -a "$output_file"

            # Iterate over each group to list attached policies
            for group in $group_names; do
                echo -e "    ${YELLOW}[!] Listing policies for group: $group${NC}"
                group_policies=$(aws iam list-attached-group-policies --profile "$profile_name" --group-name "$group" 2>&1)
                if echo "$group_policies" | grep -q "AccessDenied"; then
                    echo -e "    ${RED}[-] Access Denied${NC}\n"
                else
                    attached_policies=$(echo "$group_policies" | jq -r '.AttachedPolicies[].PolicyArn')
                    if [ -z "$attached_policies" ]; then
                        echo -e "    ${RED}[-] No attached policies found for group: $group${NC}\n"
                    else
                        echo -e "    ${GREEN}[+] Attached Policies for group $group:${NC}" | tee -a "$output_file"
                        echo "$attached_policies" | sed 's/^/        /' | tee -a "$output_file"
                        echo "" | tee -a "$output_file"

                        # Iterate over each attached policy to get its details
                        for policy_arn in $attached_policies; do
                            echo -e "        ${YELLOW}[!] Getting policy details for: $policy_arn${NC}"
                            policy_version=$(aws iam get-policy --profile "$profile_name" --policy-arn "$policy_arn" --query 'Policy.DefaultVersionId' --output text)
                            policy_document=$(aws iam get-policy-version --profile "$profile_name" --policy-arn "$policy_arn" --version-id "$policy_version" --query 'PolicyVersion.Document' --output json)
                            if echo "$policy_document" | grep -q "AccessDenied"; then
                                echo -e "        ${RED}[-] Access Denied${NC}\n"
                            else
                                echo -e "        ${GREEN}[+] Policy document for $policy_arn:${NC}" | tee -a "$output_file"
                                echo "$policy_document" | jq -r '.Statement[] | 
                                    "            Effect: \(.Effect)\n            Principal: \(.Principal // "N/A")\n            Action: \(.Action)\n            Resource: \(.Resource)\n"' | tee -a "$output_file"
                            fi
                        done
                    fi
                fi

                # List inline policies for the group
                echo -e "    ${YELLOW}[!] Listing inline policies for group: $group${NC}"
                inline_policies=$(aws iam list-group-policies --profile "$profile_name" --group-name "$group" --query 'PolicyNames' --output text)
                if [ -z "$inline_policies" ]; then
                    echo -e "    ${RED}[-] No inline policies found for group: $group${NC}\n"
                else
                    echo -e "    ${GREEN}[+] Inline Policies for group $group:${NC}" | tee -a "$output_file"
                    echo "$inline_policies" | sed 's/^/        /' | tee -a "$output_file"
                    echo "" | tee -a "$output_file"

                    # Iterate over each inline policy to get its details
                    for inline_policy in $inline_policies; do
                        echo -e "        ${YELLOW}[!] Getting inline policy details for: $inline_policy${NC}"
                        policy_document=$(aws iam get-group-policy --profile "$profile_name" --group-name "$group" --policy-name "$inline_policy" --query 'PolicyDocument' --output json)
                        if echo "$policy_document" | grep -q "AccessDenied"; then
                            echo -e "        ${RED}[-] Access Denied${NC}\n"
                        else
                            echo -e "        ${GREEN}[+] Inline Policy document for $inline_policy in group $group:${NC}" | tee -a "$output_file"
                            echo "$policy_document" | jq -r '.Statement[] | 
                                "            Effect: \(.Effect)\n            Principal: \(.Principal // "N/A")\n            Action: \(.Action)\n            Resource: \(.Resource)\n"' | tee -a "$output_file"
                        fi
                    done
                fi
            done
        fi
    fi

    echo -e "${YELLOW}[!] List Attached User Policies:${NC}"
    attached_policies=$(aws iam list-attached-user-policies --profile "$profile_name" --user-name "$1" --query 'AttachedPolicies[].PolicyName' --output text 2>&1)
    if echo "$attached_policies" | grep -q "AccessDenied"; then
        echo -e "${RED}[-] Access Denied${NC}\n"
    else
        if [ -z "$attached_policies" ]; then
            echo -e "${RED}[-] No attached policies found.${NC}\n" 
        else
            echo -e "${GREEN}[+] Attached User Policies found:${NC}" | tee -a "$output_file"
            echo "$attached_policies" | tr '\t' '\n' | tee -a "$output_file"
            echo "" | tee -a "$output_file"


        fi
    fi

    echo -e "${YELLOW}[!] List User Policies:${NC}"
    policies=$(aws iam list-user-policies --profile "$profile_name" --user-name "$1" --query 'PolicyNames[]' --output text 2>&1)
    if [[ "$policies" == *"AccessDenied"* ]]; then
        echo -e "${RED}[-] Access Denied${NC}\n"
    elif [ -n "$policies" ]; then
        echo -e "${GREEN}[+] User Policies found:${NC}" | tee -a "$output_file"
        echo "$policies" | tr '\t' '\n' | tee -a "$output_file"
        echo "" | tee -a "$output_file"

        # Iterate through each policy and get its details
        for policy in $policies; do
            echo -e "\t${YELLOW}[!] Getting details for policy: $policy${NC}"
            policy_details=$(aws iam get-user-policy --profile "$profile_name" --user-name "$1" --policy-name "$policy" --query 'PolicyDocument' --output json 2>&1)
            
            if [[ "$policy_details" == *"AccessDenied"* ]]; then
                echo -e "\t${RED}[-] Access Denied for policy: $policy${NC}\n"
            else
                echo -e "\t${GREEN}[+] Policy Details for $policy:${NC}" | tee -a "$output_file"
                echo "$policy_details" | jq -r '
                    .Statement[] | 
                    "\tEffect: \(.Effect)\n\tAction: \(.Action | if type=="array" then join(", ") else . end)\n\tResource: \(.Resource | if type=="array" then join(", ") else . end)\n"
                ' | tee -a "$output_file"
            fi
        done
    else
        echo -e "${RED}[-] No user policies found.${NC}\n"
    fi

    # Function to list roles available to assume
    echo -e "${YELLOW}[!] Roles available to assume:${NC}"
    roles=$(aws iam list-roles --profile "$profile_name" --query 'Roles[].RoleName' --output json 2>&1)
    if echo "$roles" | grep -q "AccessDenied"; then
        echo -e "${RED}[-] Access Denied${NC}\n" 
    else
        role_names=$(echo "$roles" | jq -r '.[]' | tr '\n' ' ')
        if [ -z "$role_names" ]; then
            echo -e "${RED}[-] No roles available to assume${NC}\n" 
        else
            echo -e "${GREEN}[+] Roles found:${NC}"| tee -a "$output_file"
            echo "$role_names" | tr ' ' '\n' | tee -a "$output_file"   
        fi
    fi
}


# Function to perform S3 enumerations
s3_enumeration() {
    echo -e "${YELLOW}S3 Enumeration:${NC}"
    echo -e "${YELLOW}[!] List S3 Buckets:${NC}"
    list_buckets_output=$(aws s3 ls --profile "$profile_name" 2>&1)
    if [ -z "$list_buckets_output" ]; then
        echo -e "${RED}[-] No buckets found${NC}"
        echo -e "${RED}[-] Skipping S3 Enumeration${NC}\n"
        return
    elif echo "$list_buckets_output" | grep -q "AccessDenied"; then
        echo -e "${RED}[-] Access Denied${NC}"
        echo -e "${RED}[-] Skipping S3 Enumeration${NC}\n"
        return
    else
        echo -e "${GREEN}[+] Buckets found:${NC}" | tee -a "$output_file"
        echo "$list_buckets_output" | tee -a "$output_file"
        echo "" | tee -a "$output_file"
    fi

    buckets=$(aws s3api list-buckets --profile "$profile_name" --query 'Buckets[].Name' --output text 2>&1)
    if [[ "$buckets" == *"AccessDenied"* ]]; then
        echo -e "${RED}[-] Access Denied while listing buckets${NC}\n"
        return
    fi

    for bucket in $buckets; do
        echo -e "${YELLOW}\t[!] Checking S3 Bucket Policy for bucket: $bucket${NC}"

        # Get bucket policy
        bucket_policy=$(aws s3api get-bucket-policy --profile "$profile_name" --bucket "$bucket" 2>&1)

        if echo "$bucket_policy" | grep -q "AccessDenied"; then
            echo -e "${RED}\t[-] Access Denied${NC}\n"
        elif echo "$bucket_policy" | grep -q "NoSuchBucketPolicy"; then
            echo -e "${RED}\t[-] The bucket policy for bucket: $bucket - does not exist${NC}\n"
        else
            echo -e "${GREEN}\t[+] Bucket Policy found for bucket: $bucket${NC}" | tee -a "$output_file"
            echo "$bucket_policy" | jq -r '.Policy | fromjson | .Statement[] | 
                "\tEffect: \(.Effect)\n\tPrincipal: \(.Principal | if type=="object" then (. | to_entries[] | "\t\(.key): \(.value | if type == "array" then join(", ") else . end)") else . end)\n\tAction: \(.Action | if type=="array" then join(", ") else . end)\n\tResource: \(.Resource | if type=="array" then join(", ") else . end)\n"' | tee -a "$output_file"
        fi
    done

    for bucket in $buckets; do
        echo -e "${YELLOW}[!] Checking Bucket ACLs for bucket: $bucket${NC}"
        acl_output=$(aws s3api get-bucket-acl --profile "$profile_name" --bucket "$bucket" 2>&1)
        if echo "$acl_output" | grep -q "AccessDenied"; then
            echo -e "${RED}[-] Access Denied${NC}\n"
        else
            echo -e "${GREEN}[+] ACL found for bucket: $bucket${NC}" | tee -a "$output_file"
            echo "$acl_output" | jq -r '.Grants[] | 
                "ID: \(.Grantee.ID // "N/A")\nPermission: \(.Permission)"' | tee -a "$output_file"
            echo "" | tee -a "$output_file" 
        fi
    done
}


# Function to perform EC2 enumerations
ec2_enumeration() {
    echo -e "${YELLOW}EC2 Enumeration:${NC}"
    echo -e "${YELLOW}[!] Describe EC2 Instances:${NC}"

    ec2_output=$(aws ec2 describe-instances --profile "$profile_name" 2>&1)

    # Check if the ec2_output is empty or contains an error
    if [ -z "$ec2_output" ]; then
        echo -e "${RED}[-] No EC2 instances found${NC}\n" 
        return
    elif echo "$ec2_output" | grep -q "UnauthorizedOperation"; then
        echo -e "${RED}[-] UnauthorizedOperation${NC}\n" 
        exit 1
    fi

    # Parse the required information using jq
    instance_info=$(echo "$ec2_output" | jq -r '
    .Reservations[] | .Instances[] | {
        Name: (.Tags[]? | select(.Key == "Name") | .Value // "N/A"),
        Groups: (.SecurityGroups[]? | .GroupName),
        SecurityGroups: [.SecurityGroups[].GroupName],
        InstanceID: .InstanceId,
        AvailabilityZone: .Placement.AvailabilityZone,
        State: .State.Name,
        LaunchTime: .LaunchTime,
        PrivateIP: .PrivateIpAddress,
        VPCID: .VpcId,
        SUBNETID: .SubnetId,
        VOLUMEID: (.BlockDeviceMappings[]?.Ebs.VolumeId // "N/A"),
        OWNERID: (.NetworkInterfaces[0].OwnerId // "N/A")
    }' | jq -r '
        "Instance Name: \(.Name)",
        "Groups: \(.Groups // "N/A")",
        "Security Groups: \(.SecurityGroups | join(", "))",
        "Instance ID: \(.InstanceID)",
        "Availability Zone: \(.AvailabilityZone)",
        "State: \(.State)",
        "LaunchTime: \(.LaunchTime)",
        "PrivateIP: \(.PrivateIP)",
        "VPCID: \(.VPCID)",
        "SUBNETID: \(.SUBNETID)",
        "VOLUMEID: \(.VOLUMEID)",
        "OWNERID: \(.OWNERID)"
    ')

    # Number only the different EC2 instance names
    instance_info_with_numbers=$(echo "$instance_info" | awk '/Instance Name:/ {if (++count > 1) print ""; print count ". " $0; next} {print}')

    # Output the parsed information 
    if [ -z "$instance_info_with_numbers" ]; then
        echo -e "${RED}[-] No EC2 instances found${NC}\n"
    else
        echo -e "${GREEN}[+] EC2 Info found:${NC}" | tee -a "$output_file"
        echo -e "$instance_info_with_numbers" | tee -a "$output_file"
    fi

}

main() {
    # Get caller identity to extract username
    caller_identity=$(aws sts get-caller-identity --profile "$profile_name")
    username=$(echo "$caller_identity" | jq -r '.Arn' | awk -F '/' '{print $2}')
    echo -e "${GREEN}[+] Username: $username${NC}\n" | tee -a "$output_file"

    iam_enumeration "$username"
    s3_enumeration
    ec2_enumeration

}

main