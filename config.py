import os
from dotenv import load_dotenv

load_dotenv()

# Bot configuration
DISCORD_TOKEN = os.getenv("DISCORD_TOKEN")
CHANNEL_ID = int(os.getenv("CHANNEL_ID", 0))  # Discord channel ID for commands
ADMIN_ROLE_ID = int(os.getenv("ADMIN_ROLE_ID", 0))  # Admin role ID

# VPS configuration
ALLOWED_OS = ["ubuntu-22-04-with-tmate", "ubuntu-20-04", "debian-11", "centos-9"]
USER_MAX_RAM = 4  # GB
USER_MAX_CPU = 1  # Cores
SERVER_LIMIT = 1  # Max containers per user
HOSTNAME = "GalaxyOp"