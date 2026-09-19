# Release preparation

## Before publishing

- Run the [release checklist](RELEASE-CHECKLIST.md) against the intended commit.
- Check installation and the README instructions on a clean machine without personal API keys.
- Capture the main workflow and an unavailable-provider state from that build.
- Record the short walkthrough in [video/STORYBOARD.md](video/STORYBOARD.md).
  Keep the DEMO label visible when using synthetic data.
- Check the release download links, hashes and signature disclosures.
- Ask a few testers to install it and complete an investigation without assistance.
  Track anything that blocks them as an issue.

## Release notes

Include the version, supported platforms, changes, known issues and checks actually run.
Link to the download, source, privacy policy and screenshots. The release workflow adds
file hashes, source revision and signature information; avoid duplicating that section.

Describe Windows and Android separately. Android does not provide Windows-style socket
attribution, and its production APK publication is disabled by default. Note provider
outages or device-specific restrictions discovered during testing.

## Walkthrough and feedback

The developer's TikTok account is [szoboszlai2113](https://tiktok.com/szoboszlai2113).
A short recording can show installation, filtering a process and inspecting a connection.
Use an actual build and identify any synthetic data. Check the recording for private
addresses, paths, account names and keys before posting it.

Direct bugs and feature requests to GitHub issues. Private security reports can go to
[user2102392109@proton.me](mailto:user2102392109@proton.me); see [SECURITY.md](../SECURITY.md).

## After publishing

Prioritize installation failures, crashes and incorrect results. Group repeated reports
before expanding the feature set. Update the quick-start instructions when a step causes
confusion, and record fixes and remaining limitations in the next release notes.
