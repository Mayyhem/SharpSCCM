# Contributing

Welcome! Thanks for taking the time to contribute to SharpSCCM!

The following is a set of guidelines for contributing to SharpSCCM, including submitting bug reports, submitting feature requests, reviewing new submissions, or contributing code that can be incorporated into the project. These are mostly guidelines, not rules. Use your best judgment and feel free to propose changes to this document in a pull request.

**Table of Contents:**

1. [Important Resources](#important-resources)
2. [Questions](#questions)
3. [Issues and Bug Reports](#issues-and-bug-reports)
4. [Security Vulnerabilities](#security-vulnerabilities)
5. [Development](#development)
6. [Pull Requests](#pull-requests)
7. [Feature Requests](#feature-requests)
8. [Code of Conduct](#code-of-conduct)

## Important Resources

If you have a question, please review the following resources before opening an issue to get the fastest results:

* [Wiki](https://github.com/Mayyhem/SharpSCCM/wiki)
* [Open Issues](https://github.com/Mayyhem/SharpSCCM/issues)

## Questions

Still have a question, but not an issue to report? Please reach out to Chris at @_Mayyhem on Twitter or @Mayyhem in the [BloodHoundGang Slack](https://bloodhoundhq.slack.com), or start a [Discussion](https://github.com/Mayyhem/SharpSCCM/discussions/categories/q-a).

## Issues and Bug Reports
If you find a bug in the source code, please help us by submitting an issue to our [GitHub issue tracker](https://github.com/Mayyhem/SharpSCCM/issues) or a pull request with a fix.

Before submitting an issue, please:

* check open and closed issues for any previous related discussion.
* check open pull requests for fixes.
* make sure you are using the latest release.
 
When submitting a new issue, please use the provided templates. Please fill out each section to ensure we have the basic information needed to begin reviewing the issue and reproducing it.

## Security Vulnerabilities
**If you find a security vulnerability, please do not open an issue and first privately contact Chris at @_Mayyhem on Twitter or @Mayyhem in the [BloodHoundGang Slack](https://bloodhoundhq.slack.com).**

Please include:

- a concise description of the vulnerability and its impact.
- step-by-step instructions to reproduce or observe the issue.
- relevant stack traces, screenshots, or other information.

The maintainer will respond as soon as possible. Depending on the impact and work required to resolve the issue, expect a patch within 14-30 days.

## Development

### Lab Environment
Microsoft’s [official lab kits](https://docs.microsoft.com/en-us/microsoft-365/enterprise/modern-desktop-deployment-and-management-lab?view=o365-worldwide) can automatically deploy a fully operational SCCM lab in Hyper-V running ConfigMgr. Using them is a great way to get started without taking a lot of time to manually deploy SCCM.

### GitHub Flow
SharpSCCM follows [GitHub flow](https://docs.github.com/en/get-started/quickstart/github-flow) to colloborate on development.

You will need to fork the main repository to work on your changes. Simply navigate to our GitHub page and click the "Fork" button at the top. Once you've forked the repository, you can clone your new repository and start making edits.

It is best to isolate each topic or feature into a “feature branch”. While individual commits allow you control over how small individual changes are made to the code, branches are a great way to group a set of commits all related to one feature together, or to isolate different efforts when you might be working on multiple topics at the same time. A feature branch should be limited in scope to a single issue.

```
# Checkout the main branch - you want your new branch to come from main
git checkout main

# Create a new branch named newfeature (give your branch its own simple informative name)
git branch newfeature

# Switch to your new branch
git checkout newfeature
```

## Pull Requests

When submitting a pull request, please follow all instructions in the [pull request template](https://github.com/Mayyhem/SharpSCCM/blob/main/PULL_REQUEST_TEMPLATE.md).

While the prerequisites above must be satisfied prior to having your pull request reviewed, the reviewer(s) may ask you to complete additional design work, tests, or other changes before your pull request can be ultimately accepted.

When you are ready to generate a pull request, either for preliminary review, or for consideration of merging into the project you must first push your local feature branch back up to GitHub:

```
git push origin newfeature
```

Once you've committed and pushed all of your changes to GitHub, go to the page for your fork on GitHub, select your feature branch, and click the pull request button. If you need to make any adjustments to your pull request, just push the updates to your branch. Your pull request will automatically track the changes on your development branch and update.

### Review Process
The maintainer looks at pull requests on a regular basis, typically within two weeks. After feedback has been given we expect responses within two weeks. After two weeks we may close the pull request if it isn't showing any activity.

### Addressing Feedback
Once a PR has been submitted, your changes will be reviewed and constructive feedback may be provided. Feedback isn't meant as an attack, but to help make sure the highest quality code makes it into our project. Changes will be approved once required feedback has been addressed.

If a maintainer asks you to "rebase" your PR, they're saying that a lot of code has changed, and that you need to update your fork so it's easier to merge.

To update your forked repository, follow these steps:

```
# Fetch upstream main and merge with your repo's main branch
git fetch upstream
git checkout main	
git merge upstream/main

# If there were any new commits, rebase your development branch
git checkout newfeature
git rebase main
```

If too much code has changed for git to automatically apply your branches changes to the new master, you will need to manually resolve the merge conflicts yourself.

Once your new branch has no conflicts and works correctly, you can override your old branch using this command:

```
git push -f
```
Note that this will overwrite the old branch on the server, so make sure you are happy with your changes first!

## Feature Requests

Before submitting a feature request, please:

* Check the current backlog under the _Projects_ tab
* Check the _Ideas_ section under the _Discussions_ tab

If your idea is already being tracked on the backlog or in the ideas discussion, please feel free to comment on it to add your support. Otherwise, please submit your new idea using the _Ideas_ section of the _Discussion_ tab using the [feature request template](https://github.com/Mayyhem/SharpSCCM/blob/main/.github/ISSUE_TEMPLATE/feature_request.md).

## Code of Conduct

By participating in this project, you agree to abide by our [Code of Conduct](https://github.com/Mayyhem/SharpSCCM/blob/main/CODE_OF_CONDUCT.md). We expect all contributors to follow the Code of Conduct and to treat fellow humans with respect. Please report unacceptable behavior to Chris at @_Mayyhem on Twitter or @Mayyhem in the [BloodHoundGang Slack](https://bloodhoundhq.slack.com). 
