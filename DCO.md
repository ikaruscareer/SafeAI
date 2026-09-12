# Developer Certificate of Origin (DCO)

SafeAI uses the Developer Certificate of Origin instead of a Contributor
License Agreement. You keep ownership of your work; you only certify its
origin and license compatibility. This is not legal advice.

## What you certify

By adding a `Signed-off-by` trailer to your commits, you certify the
[Developer Certificate of Origin 1.1](https://developercertificate.org/)
(that text is normative; the summary here is not a substitute):

> The contribution was created in whole or in part by me and I have the
> right to submit it under the open source license indicated in the file;
> or it is based on previous work that, to the best of my knowledge, is
> covered under an appropriate open source license and I have the right
> under that license to submit that work with modifications; or it was
> provided directly to me by some other person who certified the above
> and I have not modified it. I understand the project and contribution
> are public and that a record of the contribution (including all personal
> information I submit with it) is maintained indefinitely and may be
> redistributed consistent with the project's Apache-2.0 license.

Scope: contribution origin and Apache-2.0 license certification only. No
ownership transfer, no patent grant beyond what Apache-2.0 already states.

## How to sign off

```bash
git commit -s -m "feat: add Docker capability detection"
```

Every commit in a pull request must carry a `Signed-off-by: Name <email>`
trailer matching the author. Pull requests verify this automatically
(see `.github/workflows/ci.yml`, job `dco`).

## Forgot the sign-off?

```bash
# Amend the last commit:
git commit --amend -s --no-edit
# Or sign off a whole branch (rebases; only for unmerged work):
git rebase --signoff main
```

## Local check

```bash
python scripts/check_dco.py --range main..HEAD
```
