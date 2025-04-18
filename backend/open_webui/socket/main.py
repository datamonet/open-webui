import asyncio
import socketio
import logging
import sys
import time
from redis import asyncio as aioredis

from open_webui.models.users import Users, UserNameResponse
from open_webui.models.channels import Channels
from open_webui.models.chats import Chats
from open_webui.utils.redis import (
    parse_redis_sentinel_url,
    get_sentinels_from_env,
    AsyncRedisSentinelManager,
)

from open_webui.env import (
    ENABLE_WEBSOCKET_SUPPORT,
    WEBSOCKET_MANAGER,
    WEBSOCKET_REDIS_URL,
    WEBSOCKET_REDIS_LOCK_TIMEOUT,
    WEBSOCKET_SENTINEL_PORT,
    WEBSOCKET_SENTINEL_HOSTS,
)
from open_webui.utils.auth import decode_token
from open_webui.socket.utils import RedisDict, RedisLock

from open_webui.env import (
    GLOBAL_LOG_LEVEL,
    SRC_LOG_LEVELS,
)


logging.basicConfig(stream=sys.stdout, level=GLOBAL_LOG_LEVEL)
log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["SOCKET"])


if WEBSOCKET_MANAGER == "redis":
    if WEBSOCKET_SENTINEL_HOSTS:
        redis_config = parse_redis_sentinel_url(WEBSOCKET_REDIS_URL)
        mgr = AsyncRedisSentinelManager(
            WEBSOCKET_SENTINEL_HOSTS.split(","),
            sentinel_port=int(WEBSOCKET_SENTINEL_PORT),
            redis_port=redis_config["port"],
            service=redis_config["service"],
            db=redis_config["db"],
            username=redis_config["username"],
            password=redis_config["password"],
        )
    else:
        mgr = socketio.AsyncRedisManager(
                WEBSOCKET_REDIS_URL,
                # Add connection pool configuration
                redis_options={
                    "socket_timeout": 60, # 60s
                    "socket_connect_timeout": 30, # 30s
                    "health_check_interval": 60, # 60s
                    "retry_on_timeout": True,
                    # Use a connection pool with a reasonable max_connections limit
                    "max_connections": 10000  # Adjust based on your needs
                }
            )
    sio = socketio.AsyncServer(
        cors_allowed_origins=[],
        async_mode="asgi",
        transports=(["websocket"] if ENABLE_WEBSOCKET_SUPPORT else ["polling"]),
        allow_upgrades=ENABLE_WEBSOCKET_SUPPORT,
        always_connect=True,
        client_manager=mgr,
    )
else:
    sio = socketio.AsyncServer(
        cors_allowed_origins=[],
        async_mode="asgi",
        transports=(["websocket"] if ENABLE_WEBSOCKET_SUPPORT else ["polling"]),
        allow_upgrades=ENABLE_WEBSOCKET_SUPPORT,
        always_connect=True,
    )


# Timeout duration in seconds
TIMEOUT_DURATION = 3

# Dictionary to maintain the user pool

if WEBSOCKET_MANAGER == "redis":
    log.debug("Using Redis to manage websockets.")
    redis_sentinels = get_sentinels_from_env(
        WEBSOCKET_SENTINEL_HOSTS, WEBSOCKET_SENTINEL_PORT
    )
    SESSION_POOL = RedisDict(
        "open-webui:session_pool",
        redis_url=WEBSOCKET_REDIS_URL,
        redis_sentinels=redis_sentinels,
    )
    USER_POOL = RedisDict(
        "open-webui:user_pool",
        redis_url=WEBSOCKET_REDIS_URL,
        redis_sentinels=redis_sentinels,
    )
    USAGE_POOL = RedisDict(
        "open-webui:usage_pool",
        redis_url=WEBSOCKET_REDIS_URL,
        redis_sentinels=redis_sentinels,
    )

    clean_up_lock = RedisLock(
        redis_url=WEBSOCKET_REDIS_URL,
        lock_name="usage_cleanup_lock",
        timeout_secs=WEBSOCKET_REDIS_LOCK_TIMEOUT,
        redis_sentinels=redis_sentinels,
    )
    aquire_func = clean_up_lock.aquire_lock
    renew_func = clean_up_lock.renew_lock
    release_func = clean_up_lock.release_lock
else:
    SESSION_POOL = {}
    USER_POOL = {}
    USAGE_POOL = {}
    aquire_func = release_func = renew_func = lambda: True


async def periodic_redis_cleanup():
    """takin code: Clean up idle Redis connections
    - Runs cleanup every hour
    - Only cleans up normal connections (preserves subscription connections)
    - Cleans up connections that have been idle for more than 1 hour
    """
    CLEANUP_INTERVAL = 10 * 60  # 10 minutes
    IDLE_TIMEOUT = 20 * 60  # 20 minutes
    while True:
        redis = None
        try:
            if WEBSOCKET_MANAGER == "redis":
                log.info("Starting Redis idle connection cleanup...")
                
                # Record initial connection count
                redis = await aioredis.from_url(WEBSOCKET_REDIS_URL)
                initial_clients = await redis.client_list()
                initial_count = len(initial_clients)
                log.info(f"Total current connections: {initial_count}")
                
                killed = 0
                for client in initial_clients:
                    # Skip special connections
                    flags = client.get('flags', '')
                    if any(flag in flags for flag in ['S', 'M', 'x']):  # S=subscription, M=master, x=multiplex
                        continue
                            
                    # Check idle time
                    idle_seconds = int(client.get('idle', 0))
                    if idle_seconds >= IDLE_TIMEOUT: 
                        addr = client.get('addr')
                        name = client.get('name', 'unnamed')
                        try:
                            await redis.client_kill(addr)
                            killed += 1
                            log.debug(f"Cleaned up connection: {name} ({addr}), idle time: {idle_seconds}s")
                        except Exception as e:
                            log.warning(f"Failed to clean up connection {addr}: {str(e)}")
                
                # Check status after cleanup
                final_clients = await redis.client_list()
                final_count = len(final_clients)
                log.info(
                    f"Redis idle connection cleanup completed:\n"
                    f"- Initial connections: {initial_count}\n"
                    f"- Connections cleaned: {killed}\n"
                    f"- Current connections: {final_count}"
                )
                
        except Exception as e:
            log.error(f"Redis cleanup task failed: {str(e)}")
        finally:
            if redis:
                try:
                    await redis.close()
                except Exception as e:
                    log.error(f"Failed to close Redis connection: {str(e)}")
        
        # Run every CLEANUP_INTERVAL
        await asyncio.sleep(CLEANUP_INTERVAL)


async def periodic_usage_pool_cleanup():
    if not aquire_func():
        log.debug("Usage pool cleanup lock already exists. Not running it.")
        return
    log.debug("Running periodic_usage_pool_cleanup")
    try:
        while True:
            if not renew_func():
                log.error(f"Unable to renew cleanup lock. Exiting usage pool cleanup.")
                raise Exception("Unable to renew usage pool cleanup lock.")

            now = int(time.time())
            send_usage = False
            for model_id, connections in list(USAGE_POOL.items()):
                # Creating a list of sids to remove if they have timed out
                expired_sids = [
                    sid
                    for sid, details in connections.items()
                    if now - details["updated_at"] > TIMEOUT_DURATION
                ]

                for sid in expired_sids:
                    del connections[sid]

                if not connections:
                    log.debug(f"Cleaning up model {model_id} from usage pool")
                    del USAGE_POOL[model_id]
                else:
                    USAGE_POOL[model_id] = connections

                send_usage = True

            if send_usage:
                # Emit updated usage information after cleaning
                await sio.emit("usage", {"models": get_models_in_use()})

            await asyncio.sleep(TIMEOUT_DURATION)
    finally:
        release_func()


app = socketio.ASGIApp(
    sio,
    socketio_path="/ws/socket.io",
)

__all__ = ['app', 'periodic_usage_pool_cleanup', 'periodic_redis_cleanup']


def get_models_in_use():
    # List models that are currently in use
    models_in_use = list(USAGE_POOL.keys())
    return models_in_use


@sio.on("usage")
async def usage(sid, data):
    model_id = data["model"]
    # Record the timestamp for the last update
    current_time = int(time.time())

    # Store the new usage data and task
    USAGE_POOL[model_id] = {
        **(USAGE_POOL[model_id] if model_id in USAGE_POOL else {}),
        sid: {"updated_at": current_time},
    }

    # Broadcast the usage data to all clients
    await sio.emit("usage", {"models": get_models_in_use()})


@sio.event
async def connect(sid, environ, auth):
    user = None
    if auth and "token" in auth:
        data = decode_token(auth["token"])

        if data is not None and "id" in data:
            user = Users.get_user_by_id(data["id"])

        if user:
            SESSION_POOL[sid] = user.model_dump()
            if user.id in USER_POOL:
                USER_POOL[user.id] = USER_POOL[user.id] + [sid]
            else:
                USER_POOL[user.id] = [sid]

            # print(f"user {user.name}({user.id}) connected with session ID {sid}")
            await sio.emit("user-list", {"user_ids": list(USER_POOL.keys())})
            await sio.emit("usage", {"models": get_models_in_use()})


@sio.on("user-join")
async def user_join(sid, data):

    auth = data["auth"] if "auth" in data else None
    if not auth or "token" not in auth:
        return

    data = decode_token(auth["token"])
    if data is None or "id" not in data:
        return

    user = Users.get_user_by_id(data["id"])
    if not user:
        return

    SESSION_POOL[sid] = user.model_dump()
    if user.id in USER_POOL:
        USER_POOL[user.id] = USER_POOL[user.id] + [sid]
    else:
        USER_POOL[user.id] = [sid]

    # Join all the channels
    channels = Channels.get_channels_by_user_id(user.id)
    log.debug(f"{channels=}")
    for channel in channels:
        await sio.enter_room(sid, f"channel:{channel.id}")

    # print(f"user {user.name}({user.id}) connected with session ID {sid}")

    await sio.emit("user-list", {"user_ids": list(USER_POOL.keys())})
    return {"id": user.id, "name": user.name}


@sio.on("join-channels")
async def join_channel(sid, data):
    auth = data["auth"] if "auth" in data else None
    if not auth or "token" not in auth:
        return

    data = decode_token(auth["token"])
    if data is None or "id" not in data:
        return

    user = Users.get_user_by_id(data["id"])
    if not user:
        return

    # Join all the channels
    channels = Channels.get_channels_by_user_id(user.id)
    log.debug(f"{channels=}")
    for channel in channels:
        await sio.enter_room(sid, f"channel:{channel.id}")


@sio.on("channel-events")
async def channel_events(sid, data):
    room = f"channel:{data['channel_id']}"
    participants = sio.manager.get_participants(
        namespace="/",
        room=room,
    )

    sids = [sid for sid, _ in participants]
    if sid not in sids:
        return

    event_data = data["data"]
    event_type = event_data["type"]

    if event_type == "typing":
        await sio.emit(
            "channel-events",
            {
                "channel_id": data["channel_id"],
                "message_id": data.get("message_id", None),
                "data": event_data,
                "user": UserNameResponse(**SESSION_POOL[sid]).model_dump(),
            },
            room=room,
        )


@sio.on("user-list")
async def user_list(sid):
    await sio.emit("user-list", {"user_ids": list(USER_POOL.keys())})


@sio.event
async def disconnect(sid):
    if sid in SESSION_POOL:
        user = SESSION_POOL[sid]
        del SESSION_POOL[sid]

        user_id = user["id"]
        USER_POOL[user_id] = [_sid for _sid in USER_POOL[user_id] if _sid != sid]

        if len(USER_POOL[user_id]) == 0:
            del USER_POOL[user_id]

        await sio.emit("user-list", {"user_ids": list(USER_POOL.keys())})
    else:
        pass
        # print(f"Unknown session ID {sid} disconnected")


async def update_database(event_data, request_info):
    """takin code: 异步处理数据库更新操作，与消息发送解耦。

    Args:
        event_data (dict): 事件数据，包含消息类型和内容
        request_info (dict): 请求信息，包含chat_id和message_id
    """
    try:
        # 验证事件类型是否存在
        if "type" not in event_data:
            return

        # 验证必要的请求参数
        if not all(k in request_info for k in ["chat_id", "message_id"]):
            log.error(f"Missing required fields in request_info: {request_info}")
            return

        # 处理状态更新事件
        if event_data["type"] == "status":
            # 异步更新消息状态
            await Chats.add_message_status_to_chat_by_id_and_message_id(
                request_info["chat_id"],
                request_info["message_id"],
                event_data.get("data", {}),  # 使用空字典作为默认值
            )
        # 处理消息内容更新事件
        elif event_data["type"] == "message":
            try:
                # 获取现有消息内容
                message = await Chats.get_message_by_id_and_message_id(
                    request_info["chat_id"],
                    request_info["message_id"],
                )
                # 如果消息存在则获取内容，否则使用空字符串
                content = message.get("content", "") if message else ""
                # 追加新的消息内容
                content += event_data.get("data", {}).get("content", "")
                # 异步更新消息内容
                await Chats.upsert_message_to_chat_by_id_and_message_id(
                    request_info["chat_id"],
                    request_info["message_id"],
                    {"content": content},
                )
            except Exception as e:
                log.error(f"Error processing message update: {e}")
                # 如果获取消息失败，仍然尝试保存新内容
                content = event_data.get("data", {}).get("content", "")
                await Chats.upsert_message_to_chat_by_id_and_message_id(
                    request_info["chat_id"],
                    request_info["message_id"],
                    {"content": content},
                )
        elif event_data["type"] == "replace":
            content = event_data.get("data", {}).get("content", "")
            await Chats.upsert_message_to_chat_by_id_and_message_id(
                request_info["chat_id"],
                request_info["message_id"],
                {"content": content},
            )
    except Exception as e:
        log.error(f"Database update failed: {e}")
        # 这里可以选择重试或者通知前端

def get_event_emitter(request_info, update_db=True):
    async def __event_emitter__(event_data):
        user_id = request_info["user_id"]
        
        # 1. 获取所有需要发送消息的session
        session_ids = list(
            set(
                USER_POOL.get(user_id, [])
                + (
                    [request_info.get("session_id")]
                    if request_info.get("session_id")
                    else []
                )
            )
        )

        # 2. 创建所有消息发送任务
        emit_tasks = []
        for session_id in session_ids:
            task = sio.emit(
                "chat-events",
                {
                    "chat_id": request_info.get("chat_id", None),
                    "message_id": request_info.get("message_id", None),
                    "data": event_data,
                },
                to=session_id,
            )
            emit_tasks.append(task)
        
        # 3. takin code: 并行处理所有消息发送
        if emit_tasks:
            await asyncio.gather(*emit_tasks)
        
        # 4. takin code: 异步处理数据库写入
        if update_db:
            asyncio.create_task(update_database(event_data, request_info))

    return __event_emitter__


def get_event_call(request_info):
    async def __event_caller__(event_data):
        response = await sio.call(
            "chat-events",
            {
                "chat_id": request_info.get("chat_id", None),
                "message_id": request_info.get("message_id", None),
                "data": event_data,
            },
            to=request_info["session_id"],
        )
        return response

    return __event_caller__


get_event_caller = get_event_call


def get_user_id_from_session_pool(sid):
    user = SESSION_POOL.get(sid)
    if user:
        return user["id"]
    return None


def get_user_ids_from_room(room):
    active_session_ids = sio.manager.get_participants(
        namespace="/",
        room=room,
    )

    active_user_ids = list(
        set(
            [SESSION_POOL.get(session_id[0])["id"] for session_id in active_session_ids]
        )
    )
    return active_user_ids


def get_active_status_by_user_id(user_id):
    if user_id in USER_POOL:
        return True
    return False
