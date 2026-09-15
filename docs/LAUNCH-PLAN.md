# An honest launch plan

## Positioning

**One sentence:** A native Windows network investigation tool that brings process context,
destination lookups and explainable risk signals into one place.

Lead with that workflow, not a promise to detect every threat. Android is an experimental
companion with explicit platform limits. Local reports work without an AI subscription.

Suggested GitHub description:

> Windows network investigation with explainable risk signals. Experimental Android companion; explicit data and permission limits.

Suggested topics: `windows`, `network-monitoring`, `security-tools`, `cpp`, `win32`, `kotlin`,
`android`, `network-analysis`. Use relevant topics, not keyword stuffing.

## Before asking for attention

- Complete the release gates and make one tested download easy to find.
- Add two actual captures: the main workflow and an unavailable-provider state.
- Record a 30–45 second demo: launch → find process → inspect reason → export.
  Keep the synthetic DEMO marker visible if using demo data.
- Check the README and release ZIP on a clean machine with no personal API keys.
- Enable private vulnerability reporting and keep bug/feature templates available.
- Ask 3–5 testers to follow the quick start without help. Fix their first blocking issue
  before posting to a larger audience.

## Suggested first-release post

> I’m building NetLurker, an open-source Windows network investigation tool in C++/Win32.
> It connects process identity, observed sockets, IP lookups and rule explanations in one
> native UI. Local reports work without an AI API key.
>
> This is a pre-release, not an antivirus. Provider failures and missing measurements are
> shown explicitly. The Android companion has a smaller scope: no VPN/root capture and no
> live connection attribution for other apps.
>
> I’d especially appreciate feedback on false-positive rules, high-DPI layouts and the
> first-run experience. Here’s the tested download, source, privacy policy and short demo:
> [insert actual release URL and capture after release gates pass].

Publish only where project/self-promotion is permitted, disclose that you are the author,
and answer technical criticism with evidence. Do not buy stars, automate promotional
comments, create fake testimonials, or imply community adoption that has not happened.

## First two weeks

- Days 1–3: respond to installation and data-accuracy reports; publish a focused fix if needed.
- Days 4–7: document the most common investigation and the limitations users misunderstand.
- Days 8–14: prioritize repeated problems and useful contributions; avoid a feature spree.

Useful signals: successful first runs, reproducible bug reports, returning testers, and
merged contributions. Star growth may follow usefulness and trust, but no number is guaranteed.
