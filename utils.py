import time
from functools import wraps


def progress_decorator(total_steps):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            function_start_time = time.time()
            print_status = None

            def update_progress(current_step, obj=None):
                if obj is not None:
                    print_status = obj.print_status
                else:
                    print_status = None
                function_now_time = time.time()
                progress_percent = (current_step / total_steps) * 100
                if print_status:
                    print(
                        f"\r{func.__name__} Progress: {progress_percent:.2f}% ({function_now_time - function_start_time:.2f}s)",
                        end='', flush=True)

            kwargs['update_progress'] = update_progress
            result = func(*args, **kwargs)
            if print_status:
                print()  # Move to the next line after function completion
            return result

        return wrapper

    return decorator
