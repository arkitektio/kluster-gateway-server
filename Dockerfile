FROM python:3.10-bookworm

# Install dependencies
RUN pip install poetry rich
RUN poetry config virtualenvs.create false 
ENV PYTHONUNBUFFERED=1

# Debug mounts
RUN mkdir /workspaces


# Copy dependencies
COPY pyproject.toml /
COPY poetry.lock /
RUN poetry install


# Install App
RUN mkdir /workspace
ADD . /workspace
WORKDIR /workspace

CMD ["dask-gateway-server", "--config", "dask_gateway_config.py"]