# Open WebUI 与 Takin 集成文档

## 认证流程

### Token 类型

1. **Takin Token**
   - 存储位置：`__Secure-authjs.session-token` 或 `authjs.session-token` cookie
   - 包含字段：
     - email：Takin 用户邮箱
     - name：Takin 用户名
     - sub：Takin 数据库中的用户 ID
     - 其他 Takin 用户信息

2. **WebUI Token**
   - 存储位置：Authorization Bearer token
   - 包含字段：
     - id：WebUI 数据库中的用户 ID

### 认证装饰器

`get_current_user` 装饰器处理两种认证场景：

1. **Auth API 路由**
   - 可以直接获取 Takin token
   - 处理用户登录、注册等操作

2. **其他 API 路由**
   - 仅能获取 WebUI token
   - 从 Authorization header 中获取用户 ID

### 登录流程

1. 用户通过 Takin 登录页面进行认证
2. 登录成功后获取 Takin token
3. 前端存储 token 并初始化 WebSocket 连接
4. 每次请求都会验证用户权限

### 退出流程

1. 调用 `/api/v1/auths/signout` 接口
2. 删除所有相关 cookie
3. 重定向到 Takin 登录页面

## 主要修改

1. **auth.py**
   - 添加 Takin token 处理
   - 增强 token 验证逻辑
   - 添加 cookie 管理函数

2. **auths.py**
   - 修改用户添加接口
   - 增强退出逻辑

3. **+layout.svelte**
   - 集成 Takin 登录流程
   - 处理 WebSocket 认证

## 注意事项

1. 用户必须在 Takin 数据库中存在才能登录
2. 所有 API 请求都需要进行认证
3. 安全 cookie 配置依赖于环境变量

环境变量
```
# 关闭注册
WEBUI_AUTH=false
# 公开 Takin API URL
PUBLIC_TAKIN_API_URL=http://localhost:3000
# 数据库连接字符串
DATABASE_URL=postgresql://postgres:@localhost:5432/open-webui
# WebUI 密钥,，保持和takin-test一致
WEBUI_SECRET_KEY=Puaexx
```