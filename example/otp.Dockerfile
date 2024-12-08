
FROM python:3.9
WORKDIR /code

RUN pip install --no-cache-dir --upgrade fastapi[standard]
RUN mkdir app
COPY otp.py /code/app/otp.py
CMD ["fastapi", "run", "app/otp.py", "--port", "8080"]
