# Contributing

Welcome! Thank you for your interest in contributing to Misconfiguration Manager!

## Adding a new technique
If creating a pull request for a new technique, please follow these steps:

1. Review open pull requests for technique numbering conflicts
2. Create a new directory under the relevant technique category (e.g., [CRED](./attack-techniques/CRED/)) in the format of `<CATEGORY>-n` where `n` is the highest number technique in the category +1
3. Create the primary markdown file in the format of `<category-#_description.md>`
4. Copy the relevant template ([attack](./attack-techniques/_attack-template.md) or [defense](./defense-techniques/_defense-techniques-list.md)) into the description markdown file
5. Fill out all sections of the template to the best of your ability
6. Include links to relevant offensive and defensive IDs
7. Review other techniques in the category for examples
8. Update other techniques if necessary using "Replace in Files" feature of VS Code
9. The submission does not have to be complete or perfect but please note what needs additional work


## Issues
If you find any incorrect or incomplete information, please open an issue. We encourage you to submit a pull request with your recommended changes. Be the change you want to see!

## Pull requests
Before creating a pull request, create a fork of the `main` branch and push your work to your fork. From there, you can open a pull request to the Misconfiguration Repository.

