# Representative Terraform IAM sample for SafeAI v2.5 IaC evidence.
# Expected Grant triples (ground truth for the benchmark corpus):
#  1. principal=agent-s3-access action=s3:GetObject,s3:PutObject
#     resource=arn:aws:s3:::agent-bucket/* provenance=partially-resolved
#     (jsonencode payload) source=main.tf
#  2. principal=aws_iam_role.agent_role.name action=attached-policy
#     resource=attach provenance=repo-iac-observed source=main.tf

resource "aws_iam_role" "agent_role" {
  name = "agent-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
  })
}

resource "aws_iam_policy" "agent_s3" {
  name = "agent-s3-access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = ["arn:aws:s3:::agent-bucket/*"]
    }]
  })
}

resource "aws_iam_role_policy_attachment" "attach" {
  role       = aws_iam_role.agent_role.name
  policy_arn = aws_iam_policy.agent_s3.arn
}
