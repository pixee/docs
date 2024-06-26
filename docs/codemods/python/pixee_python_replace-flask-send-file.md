---
title: "Replace unsafe usage of `flask.send_file`"
sidebar_position: 1
---

## pixee:python/replace-flask-send-file

| Importance | Review Guidance      | Requires Scanning Tool |
| ---------- | -------------------- | ---------------------- |
| Medium     | Merge Without Review | No                     |

The `Flask` `send_file` function from Flask is susceptible to a path traversal attack if its input is not properly validated.
In a path traversal attack, the malicious agent can craft a path containing special paths like `./` or `../` to resolve a file outside of the expected directory path. This potentially allows the agent to overwrite, delete or read arbitrary files. In the case of `flask.send_file`, the result is that a malicious user could potentially download sensitive files that exist on the filesystem where the application is being hosted.
Flask offers a native solution with the `flask.send_from_directory` function that validates the given path.

Our changes look something like this:

```diff
-from flask import Flask, send_file
+from flask import Flask
+import flask
+from pathlib import Path

app = Flask(__name__)

@app.route("/uploads/<path:name>")
def download_file(name):
-    return send_file(f'path/to/{name}.txt')
+    return flask.send_from_directory((p := Path(f'path/to/{name}.txt')).parent, p.name)
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this change is safe and will not cause any issues.

## Codemod Settings

N/A

## References

- [https://flask.palletsprojects.com/en/3.0.x/api/#flask.send_from_directory](https://flask.palletsprojects.com/en/3.0.x/api/#flask.send_from_directory)
- [https://owasp.org/www-community/attacks/Path_Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
