---
title: "Ensure Django Model Classes Implement a `__str__` Method"
sidebar_position: 1
---

## pixee:python/django-model-without-dunder-str

| Importance | Review Guidance    | Requires Scanning Tool |
| ---------- | ------------------ | ---------------------- |
| Low        | Merge After Review | No                     |

If you've ever actively developed or debugged a Django application, you may have noticed that the string representations of Django models and their instances can sometimes be hard to read or to distinguish from one another. Loading models in the interactive Django console or viewing them in the admin interface can be puzzling. This is because the default string representation of Django models is fairly generic.

This codemod is intended to make the string representation of your model objects more human-readable. It will automatically detect all of your model's fields and display them as a descriptive string.

For example, the default string representation of the `Question` model from Django's popular Poll App tutorial looks like this:

```diff
from django.db import models

class Question(models.Model):
    question_text = models.CharField(max_length=200)
    pub_date = models.DateTimeField("date published")
+
+    def __str__(self):
+        model_name = self.__class__.__name__
+        fields_str = ", ".join((f"{field.name}={getattr(self, field.name)}" for field in self._meta.fields))
+        return f"{model_name}({fields_str})"
```

Without this change, the string representation of `Question` objects look like this in the interactive Django shell:

```
>>> Question.objects.all()
<QuerySet [<Question: Question object (1)>]>
```

With this codemod's addition of `__str__`, it now looks like:

```
>>> Question.objects.all()
<QuerySet [<Question: Question(id=1, question_text=What's new?, pub_date=2024-02-21 14:28:45.631782+00:00)>]>
```

You'll notice this change works great for models with only a handful of fields. We encourage you to use this codemod's change as a starting point for further customization.

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge After Review?

This codemod is a great starting point for models with few fields. We encourage you to write custom `__str__` methods that best suit your Django application.

## Codemod Settings

N/A

## References

- [https://docs.djangoproject.com/en/5.0/ref/models/instances/#django.db.models.Model.**str**](https://docs.djangoproject.com/en/5.0/ref/models/instances/#django.db.models.Model.__str__)
