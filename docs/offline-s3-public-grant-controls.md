# Offline S3 Public Grant Controls

This R0 component supports a narrow part of `AOE-GC-D14-S11`. It projects caller-supplied existing public-read ACL and bucket-policy declarations through organization, account and bucket Block Public Access settings. It combines each setting with the most restrictive applicable value and keeps unknown values explicit. It also checks whether Bucket Owner Enforced disables the ACL path. No AWS API call, bucket read, policy parser, object read or reachability test occurs.

The distinction matters: `BlockPublicAcls` and `BlockPublicPolicy` reject certain future writes but do not remove existing grants. `IgnorePublicAcls` suppresses public ACL grants, and `RestrictPublicBuckets` restricts access derived from a public bucket policy. Bucket Owner Enforced disables ACL permissions. These behaviors are documented by [Amazon S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html) and [S3 Object Ownership](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-ownership-new-bucket.html).

The caller must supply the grant classifications, control values and context completeness. The component does not determine whether a policy is actually public, whether an action permits object reads, whether an explicit deny or KMS key blocks a request, or whether an access point changes the result. A candidate means a declared grant path merits review, not that an object is publicly reachable. The unsigned result needs original-model replay and grants no finding, qualification or positive-use authority.

Example: [`examples/offline-s3-public-grant-controls-component.json`](../examples/offline-s3-public-grant-controls-component.json).
