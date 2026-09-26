"""Tests for the Terraform brace-block scanner (v2.5 IaC evidence)."""

import os

from safeai.iac.terraform import parse_terraform_file

FIXTURE = os.path.join(
    os.path.dirname(__file__), "fixtures", "iac", "terraform",
    "representative", "main.tf")


def _read_fixture():
    with open(FIXTURE, encoding="utf-8") as handle:
        return handle.read()


def test_representative_fixture_yields_expected_grants():
    grants = parse_terraform_file("main.tf", _read_fixture())
    by_principal = {g["principal"]: g for g in grants}
    policy = by_principal["agent-s3-access"]
    assert policy["action"] == "s3:GetObject,s3:PutObject"
    assert policy["resource"] == "arn:aws:s3:::agent-bucket/*"
    assert policy["provenance"] == "partially-resolved"  # jsonencode()
    assert policy["family"] == "cloud"
    assert policy["source_file"] == "main.tf"
    assert policy["line"] >= 1
    attach = by_principal["aws_iam_role.agent_role.name"]
    assert attach["action"] == "attached-policy"
    assert attach["resource"] == "attach"
    assert attach["provenance"] == "repo-iac-observed"


def test_hcl_bare_keys_and_quoted_json_keys():
    text = '''
resource "aws_iam_policy" "a" {
  policy = "{\\"Statement\\": [{\\"Action\\": [\\"s3:GetObject\\"], \\"Resource\\": [\\"x\\"]}]}"
}
resource "aws_iam_policy" "b" {
  statement {
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }
}
'''
    grants = parse_terraform_file("a.tf", text)
    actions = sorted(g["action"] for g in grants)
    assert actions == ["ec2:DescribeInstances", "s3:GetObject"]


def test_interpolation_forces_partially_resolved():
    text = '''
resource "aws_iam_policy" "dyn" {
  name = "dyn-${var.env}"
  statement {
    actions   = ["s3:ListBucket"]
    resources = ["arn:aws:s3:::${var.bucket}/*"]
  }
}
'''
    (grant,) = parse_terraform_file("d.tf", text)
    assert grant["provenance"] == "partially-resolved"
    assert any("unresolved" in note for note in grant["fidelity_notes"])


def test_unattached_policy_flagged_not_dropped():
    text = '''
resource "aws_iam_policy_attachment" "loose" {
  policy_arn = aws_iam_policy.orphan.arn
}
'''
    (grant,) = parse_terraform_file("l.tf", text)
    assert grant["principal"] == "<unattached>"
    assert "unattached-policy" in grant["fidelity_notes"]
    assert grant["provenance"] == "partially-resolved"


def test_comments_do_not_create_phantom_blocks():
    text = '''
# resource "aws_iam_policy" "phantom" {
#   statement { actions = ["iam:*"] }
# }
resource "aws_iam_policy" "real" {
  statement {
    actions = ["s3:GetObject"]  # trailing comment
    resources = ["*"] // line comment
  }
}
'''
    grants = parse_terraform_file("c.tf", text)
    assert [g["principal"] for g in grants] == ["real"]


def test_unbalanced_tail_is_skipped_not_guessed():
    text = 'resource "aws_iam_policy" "broken" {\n  statement {\n    actions = ["s3:*"]\n'
    assert parse_terraform_file("broken.tf", text) == []


def test_non_iam_resources_ignored():
    text = '''
resource "aws_s3_bucket" "data" {
  bucket = "agent-bucket"
}
'''
    assert parse_terraform_file("s3.tf", text) == []


def test_never_raises_on_pathological_input():
    assert parse_terraform_file("x.tf", "\x00\x01\x02 {{{") == []
    assert parse_terraform_file("x.tf", "resource " * 10000) == []
    assert parse_terraform_file("x.tf", "") == []
