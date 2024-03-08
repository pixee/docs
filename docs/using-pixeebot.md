---
sidebar_position: 6
---

# User guide

## Continuous improvement

Once installed, Pixeebot will begin opening pull requests against your repositories immediately. There is no need to summon Pixeebot manually - all of your improvements will come automatically at a manageable weekly cadence.

## Summoning Pixeebot

If you have merged all your Pixeebot pull requests and you're eager to see more recommendations, you can summon Pixeebot manually. Simply reply to a pull request or open an issue with the following command:

`@pixeebot next`

This will let Pixeebot know it should immediately open a new pull request with additional improvements for this repository.

### Summon via an issue

You can also open an issue with the summon command in the issue body:

![Summon from issue](/img/summon1.png)

Within a couple of minutes, Pixeebot will open a new pull request with additional improvements for your repository:

![Summon from issue](/img/summon3.png)

## Pull request reminders

If a Pixeebot pull request remains open, two automatic reminders will occur over time in the form of comments on the pull request.

If the pull request is still not merged or closed after two weeks, Pixeebot will close it automatically with a final comment.

If a closed pull request indicates additional recommendations are available, Pixeebot can still be summoned after the pull request has been reopened.

## Pixeebot status

When a pull request is opened, Pixeebot will initiate its run, and you can monitor progress in the status checks section of your pull request.

If Pixeebot does not have any recommendations, it will mark the check as Successful. If recommendations are found, a separate pull request will be generated, and the check will be marked as Neutral. Review the check details to access the new pull request link and additional information regarding the recommendations. If you merge the new pull request, the original check will register this and be updated to Successful.

> Note: Pixeebot will only run when the pull request is first opened. If subsequent commits are introduced, Pixeebot will not initiate another run and the check will disappear, as progress is linked to the initial commit.

![checks in progress](/img/checks_in_progress.png)

## Pixeebot activity

The Activity dashboard exists as a GitHub Issue and offers a holistic perspective on Pixeebot's functionality within your repository. Through this interface, you can conveniently monitor your open pull requests, other available recommendations, and more. The dashboard is automatically enabled upon installation, provided that GitHub Issues are also enabled for your repository.

The issue can remain open, and the data will automatically refresh with each Pixeebot analysis that occurs. If the issue is closed, the feature will be disabled and the data will become stale. Reopening it will reactivate the dashboard, and resume auto-updates when Pixeebot runs.
