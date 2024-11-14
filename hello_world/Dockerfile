FROM python:3.12-rc-slim

# Set work directory.
WORKDIR /usr/src/app

# Install system dependencies including curl to download poetry.
RUN apt-get update && apt-get install -y \
  curl \
  && rm -rf /var/lib/apt/lists/*

# Install Poetry
# Using pip to ensure compatibility and easier path management
RUN pip install poetry

# Set the configuration for Poetry: do not create virtual environments as we are in Docker
RUN poetry config virtualenvs.create false

# Ensure Python prints out everything in stdout/stderr immediately without buffering it
ENV PYTHONUNBUFFERED=1 \
  POETRY_NO_INTERACTION=1 \
  PYTHONDONTWRITEBYTECODE=1

# Copy just the pyproject.toml and poetry.lock to install dependencies,
# leveraging Docker cache to speed up builds unless dependencies change.
COPY ./hello_world/pyproject.toml ./hello_world/poetry.lock* ./

# Install project dependencies
RUN poetry install --no-root --no-dev

# Copy your application code.
COPY . .

# Command to run your application
CMD ["fastapi", "dev", "hello_world/hello_world/main.py"]