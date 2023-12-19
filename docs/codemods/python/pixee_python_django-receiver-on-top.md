---
title: Ensure Django @receiver is the first decorator
sidebar_position: 1
---

## pixee:python/django-receiver-on-top

| Importance | Review Guidance      | Requires Scanning Tool |
|------------|----------------------|------------------------|
| Medium     | Merge Without Review | No                     |

Django uses signals to notify and handle actions that happens elsewhere in the application. You can define a response to a given signal by decorating a function with the `@receiver(signal)` decorator. The order in which the decorators are declared for this function is important. If the `@receiver` decorator is not on top, any decorators before it will be ignored. 
Our changes look something like this:

```diff
from django.dispatch import receiver
from django.views.decorators.csrf import csrf_exempt
from django.core.signals import request_finished

+@receiver(request_finished)
@csrf_exempt
-@receiver(request_finished)
def foo():
    pass
```

If you have feedback on this codemod, [please let us know](mailto:feedback@pixee.ai)!

## F.A.Q.

### Why is this codemod marked as Merge Without Review?

We believe this change leads to the intended behavior the application and is thus safe.

## Codemod Settings

N/A

## References

* [https://docs.djangoproject.com/en/4.1/topics/signals/](https://docs.djangoproject.com/en/4.1/topics/signals/)
