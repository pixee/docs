---
sidebar_position: 6
---

# User guide

## Continuous improvement

Once installed, Pixee will begin opening pull requests against your repositories immediately. There is no need to summon Pixee manually - all of your improvements will come automatically at a manageable weekly cadence.

## Summoning Pixee

If you have merged all your Pixee pull requests and you're eager to see more recommendations, you can summon Pixee manually. Simply reply to a pull request or open an issue with the following command:

`@pixeebot next`

This will let Pixee know it should immediately open a new pull request with additional improvements for this repository.

### Summon via an issue

GitHub users can also open an issue with the summon command in the issue body:

![Summon from issue](/img/summon1.png)

Within a couple of minutes, Pixee will open a new pull request with additional improvements for your repository:

![Summon from issue](/img/summon3.png)

## Pull request reminders

If a Pixee pull request remains open, two automatic reminders will occur over time in the form of comments on the pull request.

If the pull request is still not merged or closed after two weeks, Pixee will close it automatically with a final comment.

If a closed pull request indicates additional recommendations are available, Pixee can still be summoned after the pull request has been reopened.

## Pixee status

When a pull request is opened, Pixee will initiate its run, and you can monitor progress in the status checks section of your pull request.

If Pixee does not have any recommendations, it will mark the check as Successful. If recommendations are found, a separate pull request will be generated, and the check will be marked as Neutral. Review the check details to access the new pull request link and additional information regarding the recommendations. If you merge the new pull request, the original check will register this and be updated to Successful.

> Note: Pixee will only run when the pull request is first opened. If subsequent commits are introduced, Pixee will not initiate another run and the check will disappear, as progress is linked to the initial commit.

![checks in progress](/img/checks_in_progress.png)

## Pixee activity

The Activity dashboard exists as a GitHub Issue and offers a holistic perspective on Pixee's functionality within your repository. Through this interface, you can conveniently monitor your open pull requests, other available recommendations, and more. The dashboard is automatically enabled upon installation, provided that GitHub Issues are also enabled for your repository.

The issue can remain open, and the data will automatically refresh with each Pixee analysis that occurs. If the issue is closed, the feature will be disabled and the data will become stale. Reopening it will reactivate the dashboard, and resume auto-updates when Pixee runs.
