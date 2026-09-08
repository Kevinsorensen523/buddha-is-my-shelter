# Python Framework Compatibility Index

## Web frameworks

| Framework | Status | Integration |
|---|---|---|
| Flask | Actively maintained | [flask_example.py](flask_example.py) (dedicated) |
| Django | Actively maintained | [django_example.py](django_example.py) (dedicated — note: Django ships its own CSRF middleware already; don't run both on the same routes) |
| FastAPI | Actively maintained, very popular for APIs | [fastapi_example.py](fastapi_example.py) (dedicated, async) |
| Pyramid | Maintained | No dedicated example — wire into a "tween" (`config.add_tween(...)`), conceptually the same before-handler check as the Flask example, different registration API |
| Tornado | Maintained | No dedicated example — override `RequestHandler.prepare()` on a base handler class all your handlers extend; async, closer in shape to the FastAPI example than Flask's |
| Masonite | Maintained (Laravel-inspired) | No dedicated example — implements its own `Middleware` class with a `before()`/`after()` method; conceptually closest to the reasoning already written up for [../php/LaravelMiddlewareExample.php](../php/LaravelMiddlewareExample.php) (construct once, not per-request) |
| Bottle | Maintained (minimal, single-file) | No dedicated example — use `@app.hook('before_request')`; conceptually the same before-handler check as the Flask example |

## Not applicable

Everything below has no HTTP request/response pipeline to hook a
CSRF/rate-limit check into — the same reasoning as PHPUnit/Mockery in the
PHP index, or Hibernate/MyBatis in the Java index.

| Category | Examples | Why not applicable |
|---|---|---|
| ML/data science | PyTorch, TensorFlow, Scikit-learn, Keras, Hugging Face Transformers, JAX | Model training/inference libraries, not web servers |
| Desktop GUI | PyQt/PySide, Tkinter, Kivy, wxPython, CustomTkinter | Native desktop apps — no HTTP requests involved; if a desktop app talks to a backend API, secure that backend with one of the frameworks above instead |
| Testing | Pytest, Robot Framework, Behave | Test runners, not applications |
| Web automation/scraping | Scrapy, Selenium, Playwright | These make outbound requests (as a client), the reverse direction from everything in this library, which secures a server receiving requests |
| Data apps/dashboards | Streamlit, Dash, Panel | Different paradigm from request middleware — Streamlit re-runs a script top-to-bottom per interaction rather than routing discrete HTTP requests; Dash is built on Flask under the hood, so [flask_example.py](flask_example.py)'s pattern applies if you need it there specifically; Panel is built on Tornado, see that framework's note above |
