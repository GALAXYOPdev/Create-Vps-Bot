import discord
from discord import app_commands
from discord.ext import commands
import asyncio
import subprocess
import uuid
import config
import database
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

# Initialize Discord bot
intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix="/", intents=intents)

# Initialize database
database.init_database()

# Generate SSH key pair
def generate_ssh_key(user_id):
    key = rsa.generate_private_key(backend=default_backend(), public_exponent=65537, key_size=2048)
    private_key = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )
    
    os.makedirs("ssh_keys", exist_ok=True)
    private_key_path = f"ssh_keys/{user_id}_{uuid.uuid4().hex}.pem"
    with open(private_key_path, "wb") as f:
        f.write(private_key)
    os.chmod(private_key_path, 0o600)
    
    return private_key_path, public_key.decode("utf-8")

# Capture SSH session line from tmate
async def capture_ssh_session_line(exec_cmd):
    async for line in exec_cmd.stdout:
        line = line.decode("utf-8").strip()
        if line.startswith("ssh "):
            return line
    return None

# Check if user is admin
def is_admin(member):
    return any(role.id == config.ADMIN_ROLE_ID for role in member.roles)

@bot.event
async def on_ready():
    print(f"Logged in as {bot.user}")
    try:
        synced = await bot.tree.sync()
        print(f"Synced {len(synced)} command(s)")
    except Exception as e:
        print(f"Error syncing commands: {e}")

@bot.tree.command(name="ping", description="Check bot latency")
async def ping(interaction: discord.Interaction):
    latency = round(bot.latency * 1000)
    embed = discord.Embed(
        title="🏓 Pong!",
        description=f"Bot latency: **{latency}ms**",
        color=discord.Color.green()
    )
    embed.set_footer(text="Bot created by GalaxyOP")
    await interaction.response.send_message(embed=embed)

@bot.tree.command(name="create-vps", description="Create a new VPS")
@app_commands.describe(
    ram="RAM in GB (e.g., 2, 4, 8)",
    cpu="CPU cores (e.g., 1, 2, 4)",
    os="OS (e.g., ubuntu-22-04-with-tmate, ubuntu-20-04)"
)
async def create_vps(interaction: discord.Interaction, ram: int, cpu: int, os: str):
    if interaction.channel_id != config.CHANNEL_ID:
        embed = discord.Embed(
            title="❌ Error",
            description="This command can only be used in the designated channel!",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return
    if isinstance(interaction.channel, discord.DMChannel):
        embed = discord.Embed(
            title="❌ Error",
            description="This command cannot be used in DMs!",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return
    if os not in config.ALLOWED_OS:
        embed = discord.Embed(
            title="❌ Invalid OS",
            description=f"Allowed OS: {', '.join(config.ALLOWED_OS)}",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return
    if not is_admin(interaction.user):
        if ram > config.USER_MAX_RAM or cpu > config.USER_MAX_CPU:
            embed = discord.Embed(
                title="❌ Permission Denied",
                description=f"Normal users are limited to {config.USER_MAX_RAM}GB RAM and {config.USER_MAX_CPU} core!",
                color=discord.Color.red()
            )
            await interaction.response.send_message(embed=embed, ephemeral=True)
            return

    await create_server_task(interaction, ram, cpu, os)

async def create_server_task(interaction: discord.Interaction, ram: int, cpu: int, os: str):
    await interaction.response.send_message(embed=discord.Embed(
        description="### Creating Instance, This takes a few seconds. Powered by GalaxyOP",
        color=0x00ff00
    ))
    userid = str(interaction.user.id)
    if database.count_user_servers(userid) >= config.SERVER_LIMIT:
        await interaction.followup.send(embed=discord.Embed(
            description="```Error: Instance Limit-reached```",
            color=0xff0000
        ))
        return

    image = os if os == "ubuntu-22-04-with-tmate" else "ubuntu-22.04"  # Map OS to Docker image
    token = str(uuid.uuid4())
    private_key_path, public_key = generate_ssh_key(userid)

    try:
        container_id = subprocess.check_output([
            "docker", "run", "-itd", "--privileged", "--hostname", config.HOSTNAME,
            "--cap-add=ALL", f"--memory={ram}g", f"--cpus={cpu}", image
        ]).strip().decode('utf-8')
    except subprocess.CalledProcessError as e:
        await interaction.followup.send(embed=discord.Embed(
            description=f"### Error creating Docker container: {e}",
            color=0xff0000
        ))
        return

    try:
        exec_cmd = await asyncio.create_subprocess_exec(
            "docker", "exec", container_id, "tmate", "-F",
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
        )
    except subprocess.CalledProcessError as e:
        await interaction.followup.send(embed=discord.Embed(
            description=f"### Error executing tmate in Docker container: {e}",
            color=0xff0000
        ))
        subprocess.run(["docker", "kill", container_id])
        subprocess.run(["docker", "rm", container_id])
        return

    ssh_session_line = await capture_ssh_session_line(exec_cmd)
    if ssh_session_line:
        dm_embed = discord.Embed(
            title="🚀 Your VPS Details",
            description="Here are the details for your new VPS:",
            color=discord.Color.purple()
        )
        dm_embed.add_field(name="💻 SSH Session Command", value=f"```{ssh_session_line}```", inline=False)
        dm_embed.add_field(name="💾 OS", value=os, inline=True)
        dm_embed.add_field(name="🧠 CPU", value=f"{cpu} core(s)", inline=True)
        dm_embed.add_field(name="🗄️ RAM", value=f"{ram}GB", inline=True)
        dm_embed.add_field(name="🔑 SSH Key", value="Download below", inline=False)
        dm_embed.add_field(name="🗝️ Token", value=token, inline=False)
        dm_embed.add_field(name="🔐 Password", value="root", inline=False)
        dm_embed.set_footer(text="Bot created by GalaxyOP | Keep your token safe!")
        
        await interaction.user.send(embed=dm_embed)
        await interaction.user.send(file=discord.File(private_key_path))
        
        database.add_to_database(userid, container_id, ssh_session_line, token, ram, cpu, os)
        await interaction.followup.send(embed=discord.Embed(
            description="### Instance created successfully. Check your DMs for details.",
            color=0x00ff00
        ))
    else:
        await interaction.followup.send(embed=discord.Embed(
            description="### Something went wrong or the Instance is taking longer than expected. If this problem continues, Contact GalaxyOP Support.",
            color=0xff0000
        ))
        subprocess.run(["docker", "kill", container_id])
        subprocess.run(["docker", "rm", container_id])

@bot.tree.command(name="delvps", description="Delete a VPS by token (Admin only)")
@app_commands.describe(token="VPS token")
async def delvps(interaction: discord.Interaction, token: str):
    if not is_admin(interaction.user):
        embed = discord.Embed(
            title="❌ Permission Denied",
            description="This command is for admins only!",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return
    if interaction.channel_id != config.CHANNEL_ID:
        embed = discord.Embed(
            title="❌ Error",
            description="This command can only be used in the designated channel!",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    container = database.get_container_by_token(token)
    if not container:
        embed = discord.Embed(
            title="❌ Invalid Token",
            description="No VPS found with this token.",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    user_id, container_id = container
    try:
        subprocess.run(["docker", "kill", container_id])
        subprocess.run(["docker", "rm", container_id])
        database.delete_container(user_id, container_id)
        embed = discord.Embed(
            title="🗑️ VPS Deleted",
            description=f"VPS with token `{token}` has been deleted.",
            color=discord.Color.green()
        )
        await interaction.response.send_message(embed=embed)
    except subprocess.CalledProcessError as e:
        embed = discord.Embed(
            title="❌ Error",
            description=f"Failed to delete VPS: {e}",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="tokencheck", description="Check VPS tokens for a user (Admin only)")
@app_commands.describe(userid="User ID")
async def tokencheck(interaction: discord.Interaction, userid: str):
    if not is_admin(interaction.user):
        embed = discord.Embed(
            title="❌ Permission Denied",
            description="This command is for admins only!",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return
    if interaction.channel_id != config.CHANNEL_ID:
        embed = discord.Embed(
            title="❌ Error",
            description="This command can only be used in the designated channel!",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    containers = database.get_user_containers(userid)
    if not containers:
        embed = discord.Embed(
            title="📋 No VPS Found",
            description="This user has no active VPS instances.",
            color=discord.Color.orange()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    embed = discord.Embed(
        title="🔍 VPS Tokens",
        description=f"VPS tokens for user ID `{userid}`:",
        color=discord.Color.blue()
    )
    for i, (container_id, ssh_session, token, ram, cpu, os) in enumerate(containers, 1):
        embed.add_field(
            name=f"VPS {i}",
            value=f"Container ID: `{container_id}`\nToken: `{token}`\nOS: `{os}`\nRAM: `{ram}GB`\nCPU: `{cpu} cores`",
            inline=False
        )
    embed.set_footer(text="Bot created by GalaxyOP")
    await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="regenvps", description="Regenerate SSH key for a VPS")
async def regenvps(interaction: discord.Interaction):
    if interaction.channel_id != config.CHANNEL_ID:
        embed = discord.Embed(
            title="❌ Error",
            description="This command can only be used in the designated channel!",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    containers = database.get_user_containers(str(interaction.user.id))
    if not containers:
        embed = discord.Embed(
            title="❌ No VPS Found",
            description="You have no active VPS instances.",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    # Regenerate SSH key for the last VPS
    container_id, ssh_session, token, ram, cpu, os = containers[-1]
    private_key_path, public_key = generate_ssh_key(str(interaction.user.id))

    # Simplified: In production, update the container's SSH configuration
    embed = discord.Embed(
        title="🔑 SSH Key Regenerated",
        description="New SSH key generated. Check your DMs for the new key.",
        color=discord.Color.green()
    )
    await interaction.response.send_message(embed=embed)
    await interaction.user.send(file=discord.File(private_key_path))

@bot.tree.command(name="deletevpsall", description="Delete all VPS instances (Admin only)")
async def deletevpsall(interaction: discord.Interaction):
    if not is_admin(interaction.user):
        embed = discord.Embed(
            title="❌ Permission Denied",
            description="This command is for admins only!",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return
    if interaction.channel_id != config.CHANNEL_ID:
        embed = discord.Embed(
            title="❌ Error",
            description="This command can only be used in the designated channel!",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    try:
        containers = subprocess.check_output(["docker", "ps", "-a", "-q"]).decode("utf-8").splitlines()
        for container_id in containers:
            subprocess.run(["docker", "kill", container_id])
            subprocess.run(["docker", "rm", container_id])
        database.delete_all_containers()
        embed = discord.Embed(
            title="🗑️ All VPS Deleted",
            description="All VPS instances have been deleted.",
            color=discord.Color.green()
        )
        await interaction.response.send_message(embed=embed)
    except subprocess.CalledProcessError as e:
        embed = discord.Embed(
            title="❌ Error",
            description=f"Failed to delete VPS: {e}",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

@bot.tree.command(name="node_status", description="Check Docker node status")
async def node_status(interaction: discord.Interaction):
    if interaction.channel_id != config.CHANNEL_ID:
        embed = discord.Embed(
            title="❌ Error",
            description="This command can only be used in the designated channel!",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)
        return

    try:
        containers = subprocess.check_output(["docker", "ps", "-a", "--format", "{{.ID}} {{.Image}} {{.Status}}"]).decode("utf-8").splitlines()
        embed = discord.Embed(
            title="🖥️ Node Status",
            description="Current Docker node status:",
            color=discord.Color.blue()
        )
        if not containers:
            embed.add_field(name="Status", value="No active nodes.", inline=False)
        for container in containers:
            container_id, image, status = container.split(maxsplit=2)
            embed.add_field(
                name=f"Container {container_id[:12]}",
                value=f"Image: {image}\nStatus: {status}",
                inline=False
            )
        embed.set_footer(text="Bot created by GalaxyOP")
        await interaction.response.send_message(embed=embed)
    except subprocess.CalledProcessError as e:
        embed = discord.Embed(
            title="❌ Error",
            description=f"Failed to fetch node status: {e}",
            color=discord.Color.red()
        )
        await interaction.response.send_message(embed=embed, ephemeral=True)

bot.run(config.DISCORD_TOKEN)