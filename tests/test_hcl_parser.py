"""Tests for the HCL parser — the foundation every Terraform rule stands on."""

from __future__ import annotations

import pytest

from cloudguard.scanners.hcl import HCLParseError, parse_expression, parse_hcl


def test_parses_blocks_labels_and_attributes():
    body = parse_hcl(
        """
        resource "aws_s3_bucket" "data" {
          bucket = "my-bucket"
          acl    = "private"
        }
        """
    )
    block = body.blocks[0]
    assert block.type == "resource"
    assert block.labels == ["aws_s3_bucket", "data"]
    assert block.address == "aws_s3_bucket.data"
    assert block.resource_type == "aws_s3_bucket"
    assert block.get_str("bucket") == "my-bucket"


def test_parses_nested_blocks():
    body = parse_hcl(
        """
        resource "aws_security_group" "web" {
          ingress {
            from_port   = 443
            to_port     = 443
            cidr_blocks = ["0.0.0.0/0"]
          }
          ingress {
            from_port = 80
            to_port   = 80
          }
          egress {
            from_port = 0
          }
        }
        """
    )
    group = body.blocks[0]
    assert len(group.get_blocks("ingress")) == 2
    assert len(group.get_blocks("egress")) == 1
    first = group.get_blocks("ingress")[0]
    assert first.get_int("from_port") == 443
    assert first.get("cidr_blocks").str_items() == ["0.0.0.0/0"]


def test_literal_types():
    body = parse_hcl(
        """
        locals {
          text     = "hello"
          number   = 42
          decimal  = 1.5
          yes      = true
          no       = false
          list     = ["a", "b"]
          mapping  = { key = "value", other = 3 }
          computed = var.something
          joined   = "prefix-${var.name}"
        }
        """
    )
    attrs = body.blocks[0].attributes
    assert attrs["text"].as_str() == "hello"
    assert attrs["number"].as_int() == 42
    assert attrs["decimal"].literal == 1.5
    assert attrs["yes"].as_bool() is True
    assert attrs["no"].as_bool() is False
    assert attrs["list"].str_items() == ["a", "b"]
    assert attrs["mapping"].as_object()["key"].as_str() == "value"
    assert attrs["mapping"].as_object()["other"].as_int() == 3
    # References and interpolations stay unresolved, but keep their source text.
    assert attrs["computed"].is_literal is False
    assert attrs["computed"].raw == "var.something"
    assert attrs["joined"].as_str() is None


def test_bool_is_not_reported_as_int():
    body = parse_hcl("locals { flag = true }")
    assert body.blocks[0].get_int("flag") is None
    assert body.blocks[0].get_bool("flag") is True


def test_comments_are_ignored():
    body = parse_hcl(
        """
        # a hash comment
        // a slash comment
        /* a block
           comment */
        resource "aws_instance" "app" {
          ami = "ami-123"  # trailing comment
          # commented_out = "value"
        }
        """
    )
    block = body.blocks[0]
    assert block.get_str("ami") == "ami-123"
    assert "commented_out" not in block.attributes


def test_heredoc_is_captured():
    body = parse_hcl(
        """
        resource "aws_instance" "app" {
          user_data = <<-EOT
            #!/bin/bash
            echo hello
          EOT
          ami = "ami-123"
        }
        """
    )
    block = body.blocks[0]
    assert "echo hello" in (block.get_str("user_data") or "")
    # Parsing resumes correctly after the heredoc.
    assert block.get_str("ami") == "ami-123"


def test_line_numbers_point_at_the_source():
    body = parse_hcl('\n\nresource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n')
    block = body.blocks[0]
    assert block.line == 3
    assert block.get("acl").line == 4


def test_jsonencode_is_unwrapped():
    body = parse_hcl(
        """
        resource "aws_iam_policy" "p" {
          policy = jsonencode({
            Version = "2012-10-17"
            Statement = [
              { Effect = "Allow", Action = "*", Resource = "*" }
            ]
          })
        }
        """
    )
    document = body.blocks[0].get("policy").unwrap_call("jsonencode")
    assert document is not None
    statements = document.as_object()["Statement"].as_list()
    assert statements[0].as_object()["Action"].as_str() == "*"


def test_string_with_escaped_quotes():
    body = parse_hcl('locals { text = "say \\"hi\\"" }')
    assert body.blocks[0].get_str("text") == 'say "hi"'


def test_expression_with_braces_is_not_a_block():
    body = parse_hcl(
        """
        resource "aws_instance" "app" {
          tags = { Name = "app" }
        }
        """
    )
    block = body.blocks[0]
    assert block.blocks == []
    assert block.get("tags").as_object()["Name"].as_str() == "app"


def test_walk_visits_every_descendant():
    body = parse_hcl(
        """
        resource "aws_security_group" "web" {
          ingress {
            from_port = 22
          }
        }
        """
    )
    types = [block.type for block in body.walk()]
    assert types == ["__root__", "resource", "ingress"]


def test_unterminated_block_raises():
    with pytest.raises(HCLParseError) as excinfo:
        parse_hcl('resource "aws_s3_bucket" "b" {\n  acl = "private"\n')
    assert excinfo.value.line >= 1


def test_parse_expression_standalone():
    value = parse_expression('["a", "b"]')
    assert value.str_items() == ["a", "b"]
