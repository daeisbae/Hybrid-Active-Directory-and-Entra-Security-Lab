# README Tone and Structure Guide

This guide describes the writing style used in this repository's README. It should help future AI edits match the existing style without turning the README into a fixed template.

## Overall Shape

The README is written as a hands-on AWS IAM security lab. It teaches by setting up IAM concepts, showing vulnerable configurations, exploiting them, then showing detection and mitigation options.

The usual flow is:

1. Introduce the AWS concept or attack path.
2. Explain the lab scenario in plain language.
3. Show the relevant AWS console screenshot.
4. Describe what the screenshot means or what the reader should do next.
5. Add commands, policies, or scripts only when needed.
6. Show the result and explain what access or detection was achieved.

Do not force every section into this exact sequence. Some topics need more screenshots, some need commands, and some only need a short explanation. The goal is a reproducible lab path.

## Tone

Use a practical, direct, lab-guide tone. Write like someone walking through what they did in a real AWS account.

The README often uses:

- "we will" when introducing the next lab action
- "now we can see" when confirming a result
- "here" when pointing to a screenshot or setting
- occasional first person when describing a specific lab choice

Keep theory short. Give enough context for the reader to understand the risk, then move to the concrete AWS step.

Good style examples:

- "We will create a user called `hacker` with `ec2:RunInstances` and `iam:PassRole` permission."
- "Here, we assign the policy that allows the user to assume the admin role."
- "Now we can verify the identity with `aws sts get-caller-identity`."
- "This permission is dangerous because the user can create access keys for another account."

## Structure

Use numbered headings for major sections and subsections:

```md
## 2. Exploits

### 2.1 IAM Privilege Escalation - sts::AssumeRole
```

Use descriptive technical headings. Prefer AWS service names, IAM actions, and the exploit or mitigation name. Avoid vague headings.

Use the README's existing high-level order when adding related material:

1. Concepts and setup
2. Exploits
3. Mitigations and detection

When a later section depends on an earlier concept, link back to it instead of re-explaining everything.

## Screenshots

Screenshots are part of the main explanation, not decoration. Each screenshot should be followed or preceded by a short sentence explaining what the reader should notice or do.

Use plain alt text:

```md
![iam user assign permission](images/example.png)
```

Good screenshot captions explain the action or result:

- "We will assign the `IAM-Management` permission which we created earlier."
- "The compliance dashboard shows which IAM resources violate security best practices."
- "GuardDuty will alert you about the unusual API calls made from the compromised instance."

## Commands and Policies

Use fenced code blocks with language tags:

```bash
aws sts get-caller-identity --profile target
```

```json
{
 "Version": "2012-10-17",
 "Statement": [
  {
   "Effect": "Allow",
   "Action": "sts:AssumeRole",
   "Resource": "arn:aws:iam::{aws account id}:role/AdminAccess"
  }
 ]
}
```

Place commands close to the step where the reader needs them. Explain what the command does before or after the block, but avoid long command-by-command lectures.

## Warnings and Notes

Use GitHub admonitions for real requirements, gotchas, or dangerous assumptions:

```md
> [!IMPORTANT]
> You need to know the security group name that allows inbound traffic on port 80.
```

Do not overuse warning blocks. They should point out something that can break the lab, create risk, or change detection behavior.

## Language Preferences

Prefer simple, concrete language:

- use "use" instead of "utilize"
- use "get" or "gain" instead of inflated alternatives
- use "shows", "creates", "detects", "allows", and "assigns"
- name the exact AWS service, IAM action, user, role, policy, or command

Avoid marketing language, dramatic reframes, and ornate transitions. The README should feel like practical security notes, not a blog post.

## Editing Guidance

When adding new README content:

1. Match the existing lab-first flow.
2. Keep paragraphs short and action-oriented.
3. Add screenshots where the AWS console state matters.
4. Add commands only where the CLI is part of the lab.
5. Explain the security impact in plain language.
6. Link to earlier sections when reusing a concept.

The most important rule: write each section so a reader can reproduce the lab and understand why the permission, action, or detection matters.
