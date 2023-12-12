---
sidebar_position: 8
---

# Release Notes
We're working hard to bring you new features, enhancements and reliability to the Pixee Platform. We'd ❤️ to hear from you, drop us a note at [hi@pixee.ai](mailto:hi@pixee.ai)! 

## December 12, 2023
This entry covers updates and enhancements implemented in October and November. These changes reflect our system's ongoing evolution, improvements, and new features.

> ⚡️
> **Updated Pixeebot app permissions:** 
> To give users feedback in real time about Pixeebot Analysis, we have requested additional Github Application Permissions. **This change increases Pixeebot's access to Checks from read-only to read and write.** Existing users must update their app permissions and have received an email prompting them to do so.  Please reach out to us with any questions!




## Pixeebot App + Platform
### 🚀 New Features & Enhancements
* Enhanced first-time user modal and replaced with welcome toast
* Improved consistency in dashboard with styling updates and modifications
* Improved reliability of Codemod orchestration platform

### 🐛 Bug Fixes
* Addressed intermittent issues with authentication tokens invalidating user sessions

## Codemodder
### 🐍 Python
General support for Python is live! Some updates that made Python support possible:
* New codemod: `fix-file-resource-leak` auto closes file object to prevent resource leaks and possible Denial-of-Service (DoS) attacks
* New codemod: `django-json-response-type` correctly sets content-type header for Django JSON responses. This can prevent Cross-site-scripting (XSS) attacks (a Flask equivalent is on the way!)
* New codemod: `numpy-nan-equality` replaces erroneous equality check for numpy NaN (`a == numpy.nan`) with correct check (`numpy.isnan(a)`)
* Codemod enhancement: support for f-strings in `sql-parameterization` codemod
* Codemod enhancement: added support for `aiohttp_jinja2` in `enable-jinja2-autoescape` codemod
* Streamlined dependency management by:
  - Introducing error handling to improve parsing reliability for `pyproject.toml`
  - Integrating a `setup.py`  writer functionality
  - Enabling the Python repo manager with a basic heuristic for dependency location selection.


### ☕️ Java 
* New codemod: used for setting a private constructor to hide implicit public constructor (for Sonar)
* New codemod: replaces  `@Controller` with `@RestController` and removes `@ResponseBody` annotations (for Sonar)
* New codemod: removes redundant variable creation (for Sonar)
* New codemod: enforces the appropriate parsing technique for converting Strings to
primitive types in the codebase (for Sonar)
* New codemod: substitutes `String#replaceAll()` for `String#replace()` where appropriate (for Sonar)



## October 13, 2023
### 🚀 New Features & Enhancements
* More Python codemods are out! 15+ and counting...
* Python now supports PR Hardening mode
### 🐛 Bug Fixes
* Temporary fix for repository enrollment issues

## October 6, 2023
### 🚀 New Features & Enhancements
* 🐍Python Alpha: Python support is here! All repos will be waitlisted automatically, but if you’d like to give it a try use a fork or clone of Pygoat
* Light Mode: We heard you. Introducing a sleek Light Mode
* Java Security Toolkit now supports Java modules
### 🐛 Bug Fixes
* `pom.xml` Formatting: Fixed formatting issues
* `@pixeebot next` behavior: Fixed occurrences where this option was being shown erroneously or duplicating PRs

## September 29, 2023
### 🚀 New Features & Enhancements
* ✨AI PR Comments are here: We're excited to announce that AI enrichment of Pixeebot PRs is now live! This powerful feature enhances your PRs with insights & comments that are specific to your code. Goodbye uninspiring comments
* Codemodder Orchestrator: We’re ready to scale! The underlying infrastructure has been completely revamped to improve scalability, performance, reliability and security
* Java is Generally Available! Your Java repos will no longer be waitlisted
### 🐛 Bug Fixes
* GitHub Comment Errors: We've resolved the issue where 422 errors were encountered while leaving comments on GitHub. You can now interact seamlessly without errors

## September 22, 2023
### 🚀 New Features & Enhancements
* Added some examples to `codemodder-java` project for more examples of the types of codemods one can make
* We found a CVE in Node.js! Read about it here: https://blog.pixee.ai/breaking-down-the-nodejs-sandbox-bypass-cve-2023-30587
### 🐛 Bug Fixes
* Various bug fixes

## September 15, 2023
### 🚀 New Features & Enhancements
* Improved platform reliability with better reporting and cloud configuration
* Various performance improvements
* 🎤 Launched our blog at blog.pixee.ai

## September 8, 2023
### 🚀 New Features & Enhancements
* Message Updates for Pixeebot: Smarter choices when there are no PR enhancements, plus clearer messaging. Enjoy
* Various performance improvements
### 🐛 Bug Fixes
* Various stability improvements

## September 1, 2023
### 🚀 New Features & Enhancements
* User Dashboard Upgrade: New look, feel, and onboarding experience for Pixeebot users
* Accelerated Waitlist: We’re letting more Java repositories in. If your Java repo is still waitlisted, please be patient, it’ll get in soon!
* Various performance improvements
### 🐛 Bug Fixes
* Codemodder-java: A bug preventing files outside of src/main/java from being hardened has been resolved
* Docs page for SQL parameterization codemod has been updated to eliminate any confusion

## August 22, 2023 - Public Beta
Hello World! This is our first public release. We're ecstatic to announce that Pixeebot for Java on Github is here. This release includes:
* Continuous improvement that automatically runs a weekly analysis on your entire repo for any hardening opportunities
* Pull requests every time you submit code to provide automated hardening recommendations
* Personal user dashboard to provide a high level overview of all your repos and Pixeebot-generated PRs
* The ability to summon Pixeebot anytime with the `@pixeebot next` command in a GitHub comment
* Detailed storytelling to provide crystal clear explanations for recommended changes
* 35+ codemods and counting to provide critical hardening with high confidence
* Our published open source Codemodder framework - the foundation for the codemods
* An open source Java security toolkit library containing best practices for Java code security
* Configurability of basic settings, as requested by Alpha users
* Simple installation in just 2 steps via GitHub

 
