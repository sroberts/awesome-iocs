# Contribution Guidelines

The goal of this project is to identify useful sources of indicators of compromise and bring them together to help people get started with detecting known threats. It focuses on indicators and detection signatures, plus a few IOC-specific tools and formats. This is a curation, not a collection: only add sources you can recommend.

If you're interested in adding to the Awesome IOCs list, submit a pull request using the [GitHub Flow](https://docs.github.com/en/get-started/using-github/github-flow).

## Adding an entry

- Use the format `- [owner/name](url) - Description ending in a period.` For sources not hosted on GitHub, use the source's name as the link text.
- Say what the source is and why it's useful, in one sentence. For example, what kind of indicators it has, where they come from, or what they help you do.
- Keep each section in byte (case-sensitive) order: digits, then uppercase, then lowercase. Don't append to the bottom. `./script/check-sort README.md archived.md` checks this, and CI runs it.
- Link to the current location. If a repository was renamed or transferred, use the new owner and name rather than relying on GitHub's redirect.
- Describe the source neutrally. Don't use claims such as "validated", "high-confidence" or "best" unless the source documents how they are met.
- If you work for or are affiliated with the source, say so in the pull request. Commercial or vendor-operated feeds are welcome, but the maintainer judges them on the quality of the data, and the description should make clear who operates them.

## Archived sources

- Sources that are archived, superseded, or no longer maintained go in [archived.md](archived.md), not the README. Note the reason in the description, for example `Archived.` or `Last updated 2017.`
- Please open a pull request to move a source to `archived.md` when it stops being maintained.

## Related lists

- Other Awesome lists that cover neighbouring topics go in the `Related Lists` section of the README, linked with `#readme`.
