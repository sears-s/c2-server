FROM metasploitframework/metasploit-framework:latest

# Install packages
COPY apk_packages.txt /tmp
RUN apk add --no-cache $(cat /tmp/apk_packages.txt) \
    && rm /tmp/apk_packages.txt

# Install Python modules
COPY python_modules.txt /tmp
RUN python3 -m pip install --no-cache-dir --upgrade pip && \
    python3 -m pip install --no-cache-dir wheel && \
    python3 -m pip install --no-cache-dir -r /tmp/python_modules.txt \
    && rm /tmp/python_modules.txt
