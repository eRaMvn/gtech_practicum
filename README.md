# IAM Keeper

IAM Keeper is to revert the state of IAM User and Role to the baseline if non-designated credentials make changes

## S3 bucket structure

- role
  - role_name
    - inline_policies
      - policy_1.json
      - policy_2.json
    - managed_policies/list.json
    - state.txt

- user
  - user_name
    - inline_policies
      - policy_1.json
      - policy_2.json
    - managed_policies/list.json
    - state.txt

- managed_policies
  - policy_1.json
  - policy_2.json

## Update for the week

- Add log events
- Develop function
- Handle race condition
