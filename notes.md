# SRC漏洞挖掘Agent 搭建笔记v2
---

## 目录

1. [先搞清楚：什么是 Agent](#1-什么是agent)
2. [我们走过的弯路：v1 固定流水线为什么失败](#2-弯路)
3. [v2 的核心思想：让 LLM 当驾驶员](#3-核心思想)
4. [Function Calling：LLM 怎么"动手"](#4-function-calling)
5. [七个工具：Agent 的"工具箱"](#5-工具箱)
6. [会话本：Agent 的"记忆"](#6-会话本)
7. [护栏：约束与安全](#7-护栏)
8. [规则引擎的新角色：从裁判到助手](#8-规则引擎)
9. [证据分级：说了不算，测了才算](#9-证据分级)
10. [完整的一次任务长什么样](#10-一次任务)
11. [关键概念速查](#11-概念速查)
12. [干中学：你可以怎么上手](#12-干中学)

---

## 1. 什么是 Agent？

### 1.1 从"问 AI"到"让 AI 干活"

你可能用过 ChatGPT 这类对话 AI——打开网页，输入问题，它给你回答。这叫**对话式 AI**。

**Agent（智能体）不一样**。它不是一个问答机器，而是一个能自主完成任务的系统。

打个比方：
- **对话式 AI** = 一个知识渊博的朋友，你问什么他答什么，但他只能动嘴
- **Agent** = 一个实习生，你交代一个任务，他自己去查资料、做实验、写报告，最后交给你完整成果

关键区别就一个字：**手**。Agent 有工具可以调用——能发 HTTP 请求、能执行代码、能读文件、能记录结果。没有工具的 AI 只能"说"，有工具的 AI 才能"做"。

### 1.2 安全场景为什么需要 Agent？

漏洞挖掘不是"问一句答一句"的活，它是一个**探索过程**：

```
访问网站 → 发现登录页 → 试着输入非法字符 → 发现报错 → 怀疑SQL注入
→ 构造payload → 验证成功 → 记录证据 → 继续找下一个
```

每一步都依赖上一步的结果。对话式 AI 做不到"记住 20 步之前的上下文并持续行动"，Agent 可以。

---

## 2. 弯路：v1 固定流水线为什么失败

### 2.1 v1 的设计

我们第一版（v1）用的是教科书式的**固定流水线（Pipeline）**：6 个模块排好队，数据依次流过：

```
任务解析 → 信息采集 → 规则引擎扫描 → 过滤研判 → 验证执行 → 报告
```

规则引擎用正则表达式匹配危险代码模式（比如 `execute("SELECT...")`），匹配置信度高的标记"疑似漏洞"，再交给验证模块测试。

### 2.2 翻车现场

**演示直接卡死**。为什么？复盘后发现三个致命问题：

**问题一：规则引擎不会"理解"，只会"匹配"。**

真实的漏洞代码长这样：
```python
query = f"SELECT * FROM users WHERE username = '{username}'"
cursor.execute(query)        # ← username 是用户输入，拼进 SQL 了
```
但正则规则只匹配 `execute("SELECT...` 这种**字面量直接写死在括号里**的写法。`execute(query)` 这种变量传参，规则引擎认不出来。

更糟的是，参数化查询（**安全**的写法）反而被规则命中：
```python
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # 这是安全的！
```

**规则引擎把安全代码报成漏洞，把真漏洞漏掉**——正好反了。

**问题二：置信度打分是拍脑袋定的，没人真正去验证。**

规则给了 0.55 分，过滤模块阈值定在 0.70，于是全部落进"不确定"区间。验证模块只接收"确认"的发现——结果收到 **0 个**，一个都没验证，整条流水线空转。

**问题三：HTTP 请求的重试逻辑把靶场搞挂了。**

每个请求配置了"失败重试 3 次、超时 30 秒"。路径遍历的 payload 让单线程 Flask 靶场 hang 住之后，后续每个请求都傻等 2 分钟。几十个请求排队 = 看起来"死循环"。

### 2.3 教训

**安全漏洞挖掘需要"语义理解"，纯规则阈值扛不住。** 规则引擎能告诉你"这里有个危险函数调用"，但它分不清"危险调用+用户输入=漏洞"还是"危险调用+参数化=安全"。这个判断需要真正的理解力——这正是 LLM 擅长的。

**于是有了 v2：把方向盘交给 LLM。**

---

## 3. 核心思想：让 LLM 当驾驶员

### 3.1 架构翻转

v1 是"规则引擎干活，LLM 打下手"。v2 反过来了：

```
┌───────────────────────────────────────┐
│           LLM（驾驶员）                 │
│   每轮自主决策：下一步做什么？           │
└──────────┬────────────────────────────┘
           │ Function Calling（伸手调工具）
           ▼
┌───────────────────────────────────────┐
│            工具层（双手）               │
│  http_request  发HTTP请求（10秒超时）   │
│  python_exec   执行Python（审计）       │
│  rule_scan     规则扫描（参考用）       │
│  add_finding   记录漏洞                 │
│  mark_verified 标记验证通过             │
│  switch_phase  切换工作阶段             │
│  read_source   读源码                   │
│  session_status 查看进度                │
└──────────┬────────────────────────────┘
           │
           ▼
┌───────────────────────────────────────┐
│         会话本（JSON持久化）            │
│  每个发现、每个步骤、每个事实都存档      │
└───────────────────────────────────────┘
```

### 3.2 "轮次循环"——Agent 的心跳

Agent 的工作方式是一个循环，每轮四步：

```
第1轮: LLM思考"先看看任务状态" → 调 session_status 工具 → 得到任务信息
第2轮: LLM思考"探测首页" → 调 http_request 工具 → 得到页面HTML
第3轮: LLM思考"页面有登录表单，看看源码" → 调 rule_scan 工具 → 得到规则命中
第4轮: LLM思考"源码里用户名直接拼SQL，测试一下" → 调 http_request 工具 → 返回"登录成功！"
第5轮: LLM思考"确认了" → 调 add_finding + mark_verified → 漏洞入库
...
```

这个循环叫 **ReAct 模式**（Reasoning + Acting，边想边做），是当前 Agent 架构的主流范式。对比 v1 的固定流水线：v2 里**顺序不是写死的，是 LLM 每轮现场决定的**。

### 3.3 为什么这次不卡死了

因为纪律变了：

| | v1 | v2 |
|---|---|---|
| HTTP 重试 | 3次×30秒 | **0次×10秒** |
| 验证顺序 | 固定模块流程 | LLM 自己判断"值不值得测" |
| 危险类型（路径遍历/命令注入）| 硬测 → 靶场挂掉 | **提示词里明确禁止实测** |
| 目标失联 | 继续傻等 | LLM 看到超时就转报告阶段 |

看到没——**卡死问题不是用更复杂的代码解决的，是用"更聪明的决策者"解决的**。工程上这叫"把不确定性交给最擅长处理不确定性的组件"。

---

## 4. Function Calling：LLM 怎么"动手"

### 4.1 概念

普通对话：你发文字 → LLM 回文字。
Function Calling：你告诉 LLM"你有这些函数可用"→ LLM 回复"我要调用 http_request 函数，参数是 xxx" → 你的程序**代替 LLM 执行**这个函数 → 把结果回给 LLM → 它根据结果继续决策。

关键理解：**LLM 不执行任何代码，它只是"点菜"，你的程序是"厨师"。**

### 4.2 工具是怎么定义的

我们给 LLM 的"菜单"长这样（简化版）：

```json
{
  "name": "http_request",
  "description": "发送HTTP请求到目标，返回状态码、响应头和正文。超时10秒不重试。",
  "parameters": {
    "method": {"enum": ["GET", "POST", "HEAD"]},
    "url": "完整URL",
    "params": "查询参数或表单数据"
  }
}
```

LLM 看完菜单，自主决定什么时候点哪道菜。注意 `description` 的重要性——**LLM 靠这段文字理解工具的用途和限制**。写工具描述就是给实习生写操作手册：说清楚"能干什么、有什么限制、什么时候用"。

### 4.3 提示词 = 实习生守则

`core/orchestrator.py` 里的系统提示词就是"实习生守则"，约定了：

```
1. 按阶段推进：任务解析→信息采集→分析→验证→报告
2. HTTP请求要克制：每个端点探测1-2次就够
3. 验证payload必须非破坏性
4. 证据不足就标不确定，不要强行确认
5. 禁止实测路径遍历和命令注入（会搞挂靶场）
6. 源码可用时优先白盒分析
```

**提示词工程的核心**：不是写得越长越好，而是把"边界条件"讲清楚——什么能做、什么不能做、什么情况下收手。

### 4.4 推理模型的一个坑

我们用的模型是"先思考再回答"型（推理模型）：它先输出思考过程（reasoning），再输出正式回复（content）。如果 `max_tokens` 设太小，token 全花在思考上，正式回复是空的。

解决办法：token 预算给足（8192），并且代码里做了降级处理——如果 content 为空但 reasoning 有内容，就用 reasoning 的结尾当回复。**这就是为什么很多"AI 不回复"的 bug，其实是 token 预算被思考吃光了。**

---

## 5. 工具箱：七个工具逐一拆解

### 5.1 http_request —— Agent 的手

```
输入: method="POST", url="http://target/login", params={"username": "' OR '1'='1"}
输出: {status: 200, body: "Login successful! Welcome, alice_demo"}
```

设计要点：
- **10 秒硬超时、零重试**——这是 v1 血泪教训换来的纪律
- 响应体截断 3000 字符——防止大页面撑爆 LLM 上下文
- 每次请求前做**主机白名单校验**——超出授权范围直接拒绝

### 5.2 python_exec —— Agent 的计算器

有些活 LLM 干不了：下载 zip、解压、解析 HTML、构造复杂 payload。这时候 LLM 写一段 Python 交给这个工具执行。

```python
# LLM 可能写这样的代码：
import requests, zipfile, io
r = requests.get("http://target/www.zip")
z = zipfile.ZipFile(io.BytesIO(r.content))
print(z.namelist())
```

安全性怎么保证？
- **审计日志**：每次执行记录到 `output/python_execute_audit.jsonl`（代码片段、目的、结果）
- **破坏性操作黑名单**：代码里出现 DROP、DELETE、rm -rf 等关键词直接拒绝
- **输出截断**：防止海量输出冲爆上下文

### 5.3 rule_scan —— 从裁判降级为助手

v1 里规则引擎是裁判（它打分决定一切）。v2 里它是**参考资料**：LLM 调用它拿到一份"可疑点清单"，然后自己判断哪些值得深挖。

这个角色转变很关键：**规则引擎擅长"全覆盖"（不会漏掉明显的模式），LLM 擅长"去伪存真"（理解语义）**。组合起来就是：规则引擎广撒网，LLM 精选。

### 5.4 add_finding / mark_verified —— Agent 的记事本入口

```python
add_finding(
    title="SQL注入 — /login 用户名参数",
    severity="high",
    vuln_type="sql_injection",
    location="app.py:132",
    evidence="f-string拼接SQL: query = f\"SELECT * FROM users WHERE username = '{username}'\""
)
```

去重逻辑：**同类型+同位置的发现自动合并**，防止 LLM 反复记录同一个漏洞刷数量。

### 5.5 switch_phase / session_status / read_source —— 导航工具

- `switch_phase`：切换工作阶段（LLM 判断"信息够了，进入验证"）
- `session_status`：查看当前进度（LLM 的"我现在做到哪了"）
- `read_source`：读源码文件做白盒审计

---

## 6. 会话本：Agent 的"记忆"

### 6.1 为什么需要会话持久化

LLM 的上下文窗口有限（几万 token）。长任务做到第 20 轮，前面的细节会被挤出去。而且程序崩了怎么办？从头再来？

会话本（`core/session.py`）解决这个问题——每轮结束把所有重要状态写成 JSON 存盘：

```json
{
  "phase": "verification",
  "round": 17,
  "findings": [{"finding_id": "F001", "title": "SQL注入", "verification_status": "verified"}],
  "executed_steps": ["Round 1: ...", "Round 2: ..."],
  "confirmed_facts": ["F001: POST /login 登录绕过成功"],
  "metrics": {"llm_calls": 17, "llm_cost_usd": 0.18}
}
```

### 6.2 三个价值

1. **可恢复**：程序中断，重新读档继续
2. **可审计**：评审能看到 Agent 每一步做了什么、为什么这么做
3. **可统计**：指标（轮次、token、成本）从会话本直接算出

这其实就是操作系统课上的**状态持久化**思想：把易失的内存状态变成耐久的磁盘状态。

---

## 7. 护栏：约束与安全

安全 Agent 必须有护栏，三层：

### 7.1 范围约束（对目标）

```python
allowed_hosts = ["127.0.0.1", "demo.target.com"]
# http_request 工具执行前检查：目标主机不在白名单 → 拒绝执行
```

防止 Agent 被恶意提示词诱导去攻击无关目标（提示词注入攻击的常见利用方式）。

### 7.2 操作约束（对动作）

破坏性操作黑名单：`DROP`、`DELETE FROM`、`rm -rf`、`shutdown`……LLM 写的 python 代码或构造的 payload 里出现这些词，直接拦截。

### 7.3 能力约束（对自己）

LLM 被明确告知："路径遍历和命令注入不做实测验证，标记 L1 待人工复核"。**知道什么不能做，比知道什么能做更体现工程成熟度。**

---

## 8. 证据分级：说了不算，测了才算

这是防 LLM 幻觉的核心设计。每个漏洞发现分两个证据等级：

| 等级 | 含义 | 来源 |
|------|------|------|
| **L1** | 分析推断 | 源码审计/规则匹配，没实际测试 |
| **L2** | 实测验证 | 真的发了 payload，观察到了预期效果 |

LLM 光凭"看代码觉得像漏洞"只能记 L1。只有 `mark_verified` 工具被调用（意味着实际验证过）才升 L2。

**为什么重要**：LLM 幻觉是公认问题——它会一本正经地编造不存在的漏洞。证据分级让"脑补"和"实测"在报告里一目了然，评审可以直接核验 L2 漏洞的 payload 和响应。

---

## 9. 完整的一次任务长什么样

以演示靶场（6 个故意埋的漏洞）为例，Agent 的完整决策轨迹：

```
Round 1-3   信息采集期
  → session_status 看任务
  → http_request 探测首页、发现 /login /search /fetch 等端点
  → rule_scan 扫描源码，拿到可疑点清单（含大量噪音）

Round 4-9   分析期
  → read_source 精读 /login 源码：f-string 拼接 SQL，无参数化
  → add_finding 记录 SQL 注入（L1）
  → 同样流程发现 XSS（未编码反射）、IDOR（无鉴权）、SSRF（urlopen直连）
  → 路径遍历、命令注入记录 L1，按纪律跳过实测

Round 10-15 验证期
  → http_request: POST /login username="' OR '1'='1 --" → "Login successful!"
  → mark_verified F001
  → http_request: GET /search?q=<script>alert(1)</script> → 未转义反射
  → mark_verified F002
  → 同样验证 IDOR、SSRF

Round 16-17 收尾
  → session_status 确认全部记录
  → switch_phase → reporting
  → 生成报告: 6 发现 / 4 验证 / 0 误报 / 17 轮 / 65 秒 / $0.18
```

注意看这个过程的**信息闭环**：每一步都产生新信息，新信息改变下一步决策。这就是 Agent 和"一次性问 LLM"的本质区别。

---

## 10. 关键概念速查

| 概念 | 一句话解释 | 在本项目哪里 |
|------|-----------|-------------|
| Agent | 有工具、有记忆、能自主完成任务的 AI 系统 | 整个项目 |
| Function Calling | LLM 点菜、程序炒菜的调用机制 | `core/tools.py` 工具定义 |
| ReAct 循环 | 思考→行动→观察→再思考 | `core/orchestrator.py` 主循环 |
| 系统提示词 | 给 LLM 的"实习生守则" | `SYSTEM_PROMPT` 常量 |
| 推理模型 | 先思考再回答的 LLM，token 消耗大 | `utils/llm_client.py` reasoning 处理 |
| 会话持久化 | 每轮把状态存 JSON，可中断恢复 | `core/session.py` |
| 约束管理 | 白名单/黑名单护栏 | `core/constraints.py` |
| 证据分级 | L1 分析推断 / L2 实测验证 | `add_finding`/`mark_verified` |
| 规则引擎 | 正则匹配危险代码模式的确定性工具 | `utils/rule_engine.py` + `rules/*.yaml` |
| 零重试 HTTP | 10 秒硬超时不重试，防卡死纪律 | `utils/http_client.py` |
| Token 预算 | 每次 LLM 调用的输入输出上限 | `max_tokens` 配置 |

---

## 11. 干中学：你可以怎么上手

### 第一步：跑起来（10 分钟）

```bash
pip install -r requirements.txt
copy config.example.yaml config.yaml
copy .env.example .env    # 填你的 API key
python demos/demo_run.py --auto
```

观察终端里每轮 LLM 调了什么工具、得到什么结果。**这份日志就是最好的教材。**

### 第二步：改一行提示词（30 分钟）

打开 `core/orchestrator.py`，找到 `SYSTEM_PROMPT`，改一条纪律（比如把"每个端点探测1-2次"改成"3-4次"），再跑一遍，观察 Agent 行为变化。**体会：提示词 = 行为。**

### 第三步：加一个新工具（2 小时）

在 `core/tools.py` 里加一个工具，比如 `dns_lookup`（查域名解析）：

1. 在 `get_tool_schemas()` 里加工具定义（name/description/parameters）
2. 实现 `dns_lookup` 方法
3. 在 `self._tools` 注册表里登记
4. 在系统提示词里告诉 LLM 这个工具什么时候用
5. 跑 demo 看 LLM 会不会主动用它

### 第四步：改约束逻辑（1 小时）

打开 `core/constraints.py`，把 `blocked_actions` 加一条（比如禁止 payload 里出现 `SLEEP`），跑 demo 验证拦截生效。**体会：护栏是怎么工作的。**

### 第五步：挑战题

- 让 Agent 同时扫描两个目标（改任务 JSON + 约束白名单）
- 给 agent 加"输出中文报告"的要求（改提示词）
- 统计 LLM 每轮的平均 token 消耗，找找哪里浪费了（看 sessions/ 目录的 JSON）

### 前置知识速查

| 如果不懂 | 快速补课 |
|---------|---------|
| Function Calling 原理 | 搜"OpenAI function calling 教程"，20 分钟看懂 |
| 什么是 token | 搜"LLM token 是什么"，10 分钟 |
| HTTP 请求/响应 | MDN HTTP 概述 |
| SQL 注入原理 | OWASP SQL Injection |
| 正则表达式 | regex101.com 交互式练习 |
| Python dataclass | 官方文档 10 分钟 |

---

## 附录：v1→v2 的架构演进（给参赛文档用）

| 维度 | v1 固定流水线 | v2 LLM 驱动 |
|------|--------------|-------------|
| 决策者 | 规则引擎+置信度阈值 | LLM 语义理解 |
| 流程 | 6 模块固定顺序 | 轮次循环，自主流转 |
| 漏洞发现 | 0 confirmed | 6/6 命中 |
| 实测验证 | 0 | 4 个（L2） |
| 演示完成度 | 卡死/超时 | 65 秒完成 |
| 卡死原因 | HTTP 重试风暴 | 零重试+LLM 主动避让 |

**一句话总结这次重构**：不要用确定性代码去模拟智能决策，把决策权交给 LLM，把执行力交给工具，把记忆力交给会话，把安全交给护栏——各司其职。
