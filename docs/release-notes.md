---
sidebar_position: 8
---

# Release Notes

We're working hard to bring you new features, enhancements, and reliability to the Pixee Platform. We'd ❤️ to hear from you. Drop us a note at [hi@pixee.ai](mailto:hi@pixee.ai)!

## April 19, 2024

> ⚡️
> **Updated Pixeebot App Permissions**
>
> In order to propose changes to improve GitHub Actions workflows, we have requested additional GitHub application permissions. **This change increases Pixeebot's access to read and write access to Workflows.**
>
> Existing users must update their app permissions and have received an email prompting them to do so. Please reach out to us with any questions!

### Pixeebot App + Platform {#2024-04-19---pixeebot-app--platform}

#### 🚀 New Features & Enhancements {#2024-04-19---new-features-enhancements}

- Users that have configured the Pixeebot <> Sonar integration can now use `workflow_dispatch` as a workflow trigger. For more on using Pixeebot to fix Sonar findings, see documentation [here](https://docs.pixee.ai/code-scanning-tools/sonar)
- Refined data displayed on the Activity Dashboard. Additional information on the Pixeebot Activity Dashboard can be found [here](https://blog.pixee.ai/managing-pixeebot-activity-with-the-new-user-dashboard)

#### 🐛 Bug Fixes {#2024-03-29---bug-fixes}

- Fixed a bug preventing repo activation and scan status from displaying correctly on the user platform

### Codemodder {#2024-04-19---codemodder}

#### 🐍 Python {#2024-04-19---codemodder-python}

- Added detection and processing for external Semgrep SARIF files. This change enables Codemodder to detect Semgrep SARIF provided with the `--sarif` flag

#### ☕️ Java {#2024-04-19---codemodder-java}

- Updated `verbose-request-mapping` codemod to remove unused `RequestMapping` imports after replacing them with shortcut variants. See codemod documentation [here](https://docs.pixee.ai/codemods/java/pixee_java_verbose-request-mapping/)
- Updated codemod metadata to provide additional context on which findings are associated with which fixes, and reasoning behind any unfixed findings
- Made improvements to codemods that handle parameterization to prevent unused variables from being included in code fixes

## March 29, 2024

> 🔗
> **Pixee CLI Bitbucket Integration**
>
> You can now put Pixee to work on your Bitbucket repositories using the Pixee Bitbucket pipeline. This integration gives you access to Pixee’s automated code hardening on the Bitbucket platform. Support for GitLab coming soon!
>
> For more information, see documentation [here](https://docs.pixee.ai/open-pixee)

### Pixeebot App + Platform {#2024-03-29---pixeebot-app--platform}

#### 🚀 New Features & Enhancements {#2024-03-29---new-features-enhancements}

- Pixeebot now automatically fixes CodeQL and GitHub Advanced Security alerts. No setup required, Pixeebot will automatically work on findings after install. See documentation [here](https://docs.pixee.ai/code-scanning-tools/codeql), and a video walkthrough on our YouTube channel [here](https://youtu.be/DXs8VHsfiIQ)

#### 🐛 Bug Fixes {#2024-03-29---bug-fixes}

- Fixed a bug that prevented available codemods from loading in the the Available table on the User Dashboard
- Resolved an issue that slowed the loading of analyses counts in the User Dashboard

### Codemodder {#2024-03-29---codemodder}

#### 🐍 Python {#2024-03-29---codemodder-python}

- Updates to improve handling of `requirements.txt` files with `-r` flags
- Updated `enable-jinja2-autoescape` codemod to better handle cases where the contents of `**kwargs` is unknown. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_enable-jinja2-autoescape)

#### ☕️ Java {#2024-03-29---codemodder-java}

- Updated `sql-parameterizer codemod` to fix additional cases. See codemod documentation [here](https://docs.pixee.ai/codemods/java/pixee_java_sql-parameterizer)

## March 15, 2024

> 🛠️
> **Pixeebot Fixes Sonar Issues:**
>
> Pixeebot can now ingest your organization’s Sonar findings and automatically provide PRs to remediate some of them, giving you back development time.
>
> Installation is quick and easy. See documentation [here](https://docs.pixee.ai/code-scanning-tools/sonar)

### Pixeebot App + Platform {#2024-03-15---pixeebot-app--platform}

#### 🚀 New Features & Enhancements {#2024-03-15---new-features--enhancements}

- Made enhancements to the platform to speed up feedback delivery
- Rolled out a new and improved User Dashboard. The User Dashboard on pixee.ai has been updated for easier management of Pixeebot installations and issues across all repositories. Learn more in [this blog post](https://blog.pixee.ai/managing-pixeebot-activity-with-the-new-user-dashboard)

#### 🐛 Bug Fixes {#2024-03-15---bug-fixes}

- Various bug fixes

### Codemodder {#2024-03-15---codemodder}

#### 🐍 Python {#2024-03-15---codemodder-python}

- Updated `fix-deprecated-abstractproperty` codemod to account for `staticmethod` and `classmethod` deprecated properties. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_fix-deprecated-abstractproperty)
- Updated platform to handle the new CodeTF  `detectionTool` field to ensure consistent presentation for third party tool remediation results.

#### ☕️ Java {#2024-03-15---codemodder-java}

- Updated `switch-literal-first` codemod to account for previous null checks. See codemod documentation [here](https://docs.pixee.ai/codemods/java/pixee_java_switch-literal-first)
- Updated `harden-process-creation` codemod to ensure that it is not executed when the parameters received are only constant variables or hardcoded values. See codemod documentation [here](https://docs.pixee.ai/codemods/java/pixee_java_harden-process-creation)

## March 1, 2024

### Pixeebot App + Platform {#2024-03-01---pixeebot-app--platform}

#### 🚀 New Features & Enhancements {#2024-03-01---new-features--enhancements}

- Implemented changes to optimize codemod performance

#### 🐛 Bug Fixes {#2024-03-01---bug-fixes}

- Fixed an issue that caused Pixeebot to open multiple pull requests for a single issue

### Codemodder {#2024-03-01---codemodder}

#### 🐍 Python {#2024-03-01---codemodder-python}

- New codemod: `str-concat-in-sequence-literals` fixes cases of implicit string concatenation inside lists, sets, or tuples. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_str-concat-in-sequence-literals)
- New codemod: `fix-async-task-instantiation` replaces manual instantiation of a `Task` with a `create_task` call per the asyncio [documentation](https://docs.python.org/3/library/asyncio-task.html#asyncio.Task). See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_fix-async-task-instantiation)

#### ☕️ Java {#2024-03-01---codemodder-java}

- Fixed a hang issue that caused stalls in code analysis

## February 22, 2024

> 🔏
> **Now Supporting Signed Commits:**
>
> Commits containing Pixeebot's fixes are now [signed](https://docs.github.com/en/authentication/managing-commit-signature-verification/about-commit-signature-verification) for enhanced security, and compliance.
>
> All Pixeebot commits will show a green verified badge you can use to verify authenticity, and review detailed information on the verified signature.

### Pixeebot App + Platform {#2024-02-22---pixeebot-app--platform}

#### 🚀 New Features & Enhancements {#2024-02-22---new-features--enhancements}

- Implemented a change to the installation flow so that more repositories skip the waitlist
- Added a search and filter functionality to the installations page of the user platform, allowing users to search for specific Pixeebot installations and filter results

#### 🐛 Bug Fixes {#2024-02-22---bug-fixes}

- Fixed a bug affecting Java repositories that caused contextual comments included in Pixeebot fixes to contain incorrect line numbers

### Codemodder {#2024-02-22---codemodder}

#### 🐍 Python {#2024-02-22---codemodder-python}

- Updated `requests-verify` codemod to support the [httpx](https://www.python-httpx.org/) library. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_requests-verify)
- Updated `fix-file-resource-leak` codemod for better handling of indent blocks containing multiple open statements. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_fix-file-resource-leak)

#### ☕️ Java {#2024-02-22---codemodder-java}

- New codemod: `overrides-match-synchronization` adds missing synchronized keyword to methods that override a synchronized method in the parent class, ensuring [proper synchronization](https://wiki.sei.cmu.edu/confluence/display/java/TSM00-J.+Do+not+override+thread-safe+methods+with+methods+that+are+not+thread-safe). This improves code maintainability, and reduces the risk of issues like race conditions and data corruption. (for Sonar) See codemod documentation [here](https://docs.pixee.ai/codemods/java/sonar_java_overrides-match-synchronization-s3551)
- Updated `define-constant-for-duplicate-literal` codemod to inject new literals at the end of a file, rather than the beginning. This change improves the style of code generated by this codemod. See codemod documentation [here](https://docs.pixee.ai/codemods/java/sonar_java_define-constant-for-duplicate-literal-s1192)

## January 26, 2024

> 🌟
> **Introducing the Activity Dashboard:**
>
> This dashboard exists as a GitHub Issue, and is your source of truth for Pixeebot’s functionality within your repository. Use the Activity dashboard to:
>
> - Easily manage the open pull requests Pixeebot has created for you
> - Check for available fixes in the continuous improvement queue, and summon Pixeebot to create pull requests for them
> - Review the work that Pixeebot has already completed in your repository
>
> The dashboard is automatically enabled upon installation, provided that GitHub Issues are also enabled for your repository. See Activity dashboard documentation [here](https://docs.pixee.ai/using-pixeebot/#pixeebot-activity).

### Pixeebot App + Platform {#2024-01-26---pixeebot-app--platform}

#### 🚀 New Features & Enhancements {#2024-01-26---new-features--enhancements}

- Released performance improvement for navigating between pages on the user dashboard.

#### 🐛 Bug Fixes {#2024-01-26---bug-fixes}

- Resolved a bug that occurred when users requested a continuous improvement changes using `@pixeebot next`, Pixeebot would analyze the user’s repository twice and potentially send two PRs.

### Codemodder {#2024-01-26---codemodder}

#### 🐍 Python {#2024-01-26---codemodder-python}

- `security` package updates and release
- New codemod: `combine-startswith-endswith` Simplifies boolean expressions used with the `startswith` and `endswith` methods of `str` objects. A lot of code uses boolean expressions such as `x.startswith('foo')` or `x.startswith('bar')` , which is unnecessary since these objects can accept a tuple of strings to match. Where possible, this codemod replaces such boolean expressions with `x.startswith(('foo', 'bar))` for cleaner, more concise code. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_combine-startswith-endswith)
- New codemod: `fix-deprecated-logging-warn` Updates usage of the `warn` method from `logging` (which has been [deprecated](https://docs.python.org/3/library/logging.html#logging.Logger.warning) since Python 3.3) in favor of `warning`. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_fix-deprecated-logging-warn)
- New codemod: `flask-enable-csrf-protection` Introduces protections against cross-site forgery (CSRF) attacks by embedding an additional token into HTTP requests to identify requests from unauthorized locations. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_flask-enable-csrf-protection)
- New codemod: `remove-debug-breakpoint` removes any calls to `breakpoint()` or `pdb.set_trace()` which are generally only used for interactive debugging and should not be deployed in production. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_remove-debug-breakpoint).
- New codemod: `replace-flask-send-fil`e Introduces protections against path traversal attacks when using the `Flask` `send_file` function. This codemod uses Flasks’s `flask.send_from_directory` function for input path validation. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_replace-flask-send-file)
- New codemod: `use-set-literal` Converts Python set constructions using literal list arguments into more efficient and readable set literals. It simplifies expressions like `set([1, 2, 3])` to `{1, 2, 3}`, enhancing both performance and code clarity. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_use-set-literal#pixeepythonuse-set-literal)

#### ☕️ Java {#2024-01-26---codemodder-java}

- Added short-circuiting to improve performance of composed codemods
- New codemod: `sonar:java/remove-unused-private-method` removes unused `private` methods. These can increase both the mental load and maintenance burden of maintainers, as you have to keep compiling the unused code when making sweeping changes to the APIs used within the method. (for Sonar) See codemod documentation [here](https://docs.pixee.ai/codemods/java/sonar_java_remove-unused-private-method-s1144)
- New codemod: `sonar:java/declare-variable-on-separate-line` splits variable assignments onto their own lines. [Many](https://wiki.sei.cmu.edu/confluence/display/java/DCL52-J.+Do+not+declare+more+than+one+variable+per+declaration) [sources](https://rules.sonarsource.com/java/RSPEC-1659/) [believe](https://dart.dev/tools/linter-rules/avoid_multiple_declarations_per_line) it is easier to review code where the variables are separate statements on their own individual line. (for Sonar) See codemod documentation [here](https://docs.pixee.ai/codemods/java/sonar_java_declare-variable-on-separate-line-s1659)

## December 29, 2023

> 🎉
> **Introducing the Pixee CLI:**
>
> You can now access Pixee’s automated code hardening functionalities from the command line! The Pixee CLI gives you the ability to run Java and Python codemods and apply recommended code changes locally, in your own development environment.
>
> We built this to give developers the ability to see and apply the types of changes Pixee recommends, before installing Pixeebot on their GitHub repositories. **See Pixee CLI documentation [here](https://www.pixee.ai/cli)**

### Pixeebot App + Platform {#2023-12-29---pixeebot-app--platform}

#### 🚀 New Features & Enhancements {#2023-12-29---new-features--enhancements}

- Checks API Integration: We have integrated Pixeebot with the GitHub Checks API to enhance Pixeebot’s pull request hardening feature. This integration provides real-time status updates on Pixeebot’s analysis of your pull requests. See documentation [here](https://docs.pixee.ai/using-pixeebot/#pixeebot-status)
- Styling updates to the user platform, including skeleton tables for loading and improvements to color consistency
- Enhancement to improve load time performance on the installations page

#### 🐛 Bug Fixes {#2023-12-29---bug-fixes}

- Fixed bugs related to activation and commit status data to ensure both statuses are displayed correctly on the user platform
- Resolved a bug that caused duplicate pull requests to be opened for Pixeebot recommendations

### Codemodder {#2023-12-29---codemodder}

#### 🐍 Python {#2023-12-29---codemodder-python}

- New codemod: `add-requests-timeout` adds a timeout to requests made using the requests package. These requests do not timeout by default, which is potentially unsafe as it can cause an application to hang indefinitely. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_add-requests-timeouts)
- New codemod: `remove-future-imports` removes all `__future__` imports often found in older codebases for forward compatibility with features. While harmless, they are also unnecessary. And in most cases, you probably just forgot to remove them. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_remove-future-imports)
- New codemod: `flask-json-response-type` correctly sets content-type header for Flask JSON responses. This can prevent Cross-site-scripting (XSS) attacks) See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_flask-json-response-type/)
- New codemod: `exception-without-raise` fixes cases where an exception is referenced by itself in a statement without being raised. This most likely indicates a bug: you probably meant to actually raise the exception. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_exception-without-raise)
- Enhanced pull request descriptions for Python codemods that add new dependencies. When a codemod fails to add a dependency, these enhancements provide additional context as to why

#### ☕️ Java {#2023-12-29---codemodder-java}

- New codemod: `sonar:java/remove-commented-code` eliminates commented-out code that may impede readability and distract focus. (for Sonar) See codemod documentation [here](https://docs.pixee.ai/codemods/java/sonar_java_remove-commented-code-s125)
- New codemod: `sonar:java/replace-stream-collectors-to-list` modernizes a stream's `List` creation to be driven from the simple, and more readable [`Stream#toList()`](<https://docs.oracle.com/javase/16/docs/api/java.base/java/util/stream/Collectors.html#toList()>) method. (for Sonar) See codemod documentation [here](https://docs.pixee.ai/codemods/java/sonar_java_replace-stream-collectors-to-list-s6204)
- New codemod: `sonar:java/remove-useless-parentheses` removes redundant parentheses that make it harder to understand code. (for Sonar) See codemod documentation [here](https://docs.pixee.ai/codemods/java/sonar_java_remove-useless-parentheses-s1110)
- New codemod: `sonar:java/remove-unused-local-variable` removes unused variables that make code harder to read, leading to confusion and bugs. This codemod only removes variables that have no state-changing effects. (for Sonar) See codemod documentation [here](https://docs.pixee.ai/codemods/java/sonar_java_remove-unused-local-variable-s1481)

## December 12, 2023

This entry covers updates and enhancements implemented in October and November. These changes reflect our system's ongoing evolution, improvements, and new features.

> ⚡️
> **Updated Pixeebot app permissions:**
> To give users feedback in real time about Pixeebot Analysis, we have requested additional Github Application Permissions. **This change increases Pixeebot's access to Checks from read-only to read and write.** Existing users must update their app permissions and have received an email prompting them to do so. Please reach out to us with any questions!

### Pixeebot App + Platform {#2023-12-12---pixeebot-app--platform}

#### 🚀 New Features & Enhancements {#2023-12-12---new-features--enhancements}

- Enhanced first-time user modal and replaced with welcome toast
- Improved consistency in dashboard with styling updates and modifications
- Improved reliability of Codemod orchestration platform

#### 🐛 Bug Fixes {#2023-12-12---bug-fixes}

- Addressed intermittent issues with authentication tokens invalidating user sessions

### Codemodder {#2023-12-12---codemodder}

#### 🐍 Python {#2023-12-12---codemodder-python}

General support for Python is live! Some updates that made Python support possible:

- New codemod: `fix-file-resource-leak` auto closes file object to prevent resource leaks and possible Denial-of-Service (DoS) attacks. See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_fix-file-resource-leak)
- New codemod: `django-json-response-type` correctly sets content-type header for Django JSON responses. This can prevent Cross-site-scripting (XSS) attacks (a Flask equivalent is on the way!) See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_django-json-response-type)
- New codemod: `numpy-nan-equality` replaces erroneous equality check for numpy NaN (`a == numpy.nan`) with the correct check (`numpy.isnan(a)`) See codemod documentation [here](https://docs.pixee.ai/codemods/python/pixee_python_numpy-nan-equality)
- Codemod enhancement: support for f-strings in `sql-parameterization` codemod
- Codemod enhancement: added support for `aiohttp_jinja2` in `enable-jinja2-autoescape` codemod
- Streamlined dependency management by:
  - Introducing error handling to improve parsing reliability for `pyproject.toml`
  - Integrating a `setup.py` writer functionality
  - Enabling the Python repo manager with a basic heuristic for dependency location selection

#### ☕️ Java {#2023-12-12---codemodder-java}

- New codemod: used for setting a private constructor to hide implicit public constructor (for Sonar)
- New codemod: replaces `@Controller` with `@RestController` and removes `@ResponseBody` annotations (for Sonar)
- New codemod: removes redundant variable creation (for Sonar)
- New codemod: enforces the appropriate parsing technique for converting Strings to
  primitive types in the codebase (for Sonar)
- New codemod: substitutes `String#replaceAll()` for `String#replace()` where appropriate (for Sonar)

## October 13, 2023

#### 🚀 New Features & Enhancements {#2023-10-13---new-features--enhancements}

- More Python codemods are out! 15+ and counting...
- Python now supports PR Hardening mode

#### 🐛 Bug Fixes {#2023-10-13---bug-fixes}

- Temporary fix for repository enrollment issues

## October 6, 2023

#### 🚀 New Features & Enhancements {#2023-10-06---new-features--enhancements}

- 🐍Python Alpha: Python support is here! All repos will be waitlisted automatically, but if you’d like to give it a try, use a fork or clone of Pygoat
- Light Mode: We heard you. Introducing a sleek Light Mode
- Java Security Toolkit now supports Java modules

#### 🐛 Bug Fixes {#2023-10-06---bug-fixes}

- `pom.xml` Formatting: Fixed formatting issues
- `@pixeebot next` behavior: Fixed occurrences where this option was being shown erroneously or duplicating PRs

## September 29, 2023

#### 🚀 New Features & Enhancements {#2023-09-29---new-features--enhancements}

- ✨AI PR Comments are here: We're excited to announce that AI enrichment of Pixeebot PRs is now live! This powerful feature enhances your PRs with insights & comments that are specific to your code. Goodbye uninspiring comments
- Codemodder Orchestrator: We’re ready to scale! The underlying infrastructure has been completely revamped to improve scalability, performance, reliability, and security
- Java is Generally Available! Your Java repos will no longer be waitlisted

#### 🐛 Bug Fixes {#2023-09-29---bug-fixes}

- GitHub Comment Errors: We've resolved the issue where 422 errors were encountered while leaving comments on GitHub. You can now interact seamlessly without errors

## September 22, 2023

#### 🚀 New Features & Enhancements {#2023-09-22---new-features--enhancements}

- Added some examples to `codemodder-java` project for more examples of the types of codemods one can make
- We found a CVE in Node.js! Read about it here: https://blog.pixee.ai/breaking-down-the-nodejs-sandbox-bypass-cve-2023-30587

#### 🐛 Bug Fixes {#2023-09-22---bug-fixes}

- Various bug fixes

## September 15, 2023

#### 🚀 New Features & Enhancements {#2023-09-15---new-features--enhancements}

- Improved platform reliability with better reporting and cloud configuration
- Various performance improvements
- 🎤 Launched our blog at blog.pixee.ai

## September 8, 2023

#### 🚀 New Features & Enhancements {#2023-09-08---new-features--enhancements}

- Message Updates for Pixeebot: Smarter choices when there are no PR enhancements, plus clearer messaging. Enjoy
- Various performance improvements

#### 🐛 Bug Fixes {#2023-09-08---bug-fixes}

- Various stability improvements

## September 1, 2023

#### 🚀 New Features & Enhancements {#2023-09-01---new-features--enhancements}

- User Dashboard Upgrade: New look, feel, and onboarding experience for Pixeebot users
- Accelerated Waitlist: We’re letting more Java repositories in. If your Java repo is still waitlisted, please be patient; it’ll get in soon!
- Various performance improvements

#### 🐛 Bug Fixes {#2023-09-01---bug-fixes}

- Codemodder-java: A bug preventing files outside of src/main/java from being hardened has been resolved
- Docs page for SQL parameterization codemod has been updated to eliminate any confusion

## August 22, 2023 - Public Beta

Hello World! This is our first public release. We're ecstatic to announce that Pixeebot for Java on GitHub is here. This release includes:

- Continuous improvement that automatically runs a weekly analysis on your entire repo for any hardening opportunities
- Pull requests every time you submit code to provide automated hardening recommendations
- Personal user dashboard to provide a high level overview of all your repos and Pixeebot-generated PRs
- The ability to summon Pixeebot anytime with the `@pixeebot next` command in a GitHub comment
- Detailed storytelling to provide crystal clear explanations for recommended changes
- 35+ codemods and counting to provide critical hardening with high confidence
- Our published open source Codemodder framework - the foundation for the codemods
- An open source Java security toolkit library containing best practices for Java code security
- Configurability of basic settings, as requested by Alpha users
- Simple installation in just 2 steps via GitHub
