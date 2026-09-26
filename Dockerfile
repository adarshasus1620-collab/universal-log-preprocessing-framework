# ULPF - Universal Log Pre-processing Framework
# Self-contained image: no internet access needed at runtime (air-gap ready)

FROM python:3.12-slim

WORKDIR /app

# Install only what the app needs
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the project
COPY . .

# Streamlit's default port
EXPOSE 8501

# Run the demo UI
CMD ["streamlit", "run", "app.py", "--server.address=0.0.0.0", "--server.port=8501"]