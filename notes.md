# SRC漏洞挖掘Agent — 搭建过程与关键概念笔记

> 写给大二同学：如果你已经粗略学过数据结构、计组、操作系统、计算机网络，对AI有一些大概了解，这篇笔记会帮你理解这个Agent是怎么一步步搭建起来的，以及其中涉及的关键概念。更重要的是，你可以跟着"干中学"——实际操作一遍，比只看理论理解深刻得多。

---

## 目录

1. [先搞清楚：什么是Agent？它不是简单的"问AI"](#1-什么是agent)
2. [整体架构：六步流水线是怎么设计的](#2-整体架构)
3. [模块1：任务解析 —— 让Agent理解"你要我做什么"](#3-任务解析)
4. [模块2：信息采集 —— Agent的"眼睛和耳朵"](#4-信息采集)
5. [模块3：分析推理 —— 最核心的部分，双引擎设计](#5-分析推理)
6. [模块4：过滤研判 —— 怎么不把正常代码报成漏洞](#6-过滤研判)
7. [模块5：验证执行 —— "我说有漏洞，怎么证明？"](#7-验证执行)
8. [模块6：结果汇总 —— 生成人能看懂的报告](#8-结果汇总)
9. [关键概念深入](#9-关键概念深入)
10. [干中学：你可以怎么上手](#10-干中学)

---

## 1. 什么是Agent？

### 1.1 从"问ChatGPT"到"让Agent干活"

你可能用过ChatGPT或Claude——打开网页，输入问题，它给你回答。这叫"对话式AI"。

**Agent（智能体）不一样**。它不是一个问答机器，而是一个能自主完成任务的系统。

打个比方：
- **对话式AI** = 一个知识渊博的朋友，你问什么他答什么
- **Agent** = 一个实习生，你交代一个任务，他自己去查资料、做分析、写报告，最后交给你完整成果

### 1.2 Agent的核心能力

我们这个SRC-VulnMiner Agent体现了Agent的四个关键能力：

```
┌──────────────────────────────────────────────┐
│                 Agent 核心能力                  │
├───────────────┬──────────────┬───────────────┤
│   感知能力     │   推理能力    │   行动能力     │
│  (Perceive)  │  (Reason)   │   (Act)      │
├───────────────┼──────────────┼───────────────┤
│ 信息采集模块   │ 分析推理模块  │ 验证执行模块   │
│ 爬取网页      │ 规则引擎匹配  │ 发送验证请求   │
│ 提取表单      │ LLM深度分析   │ 生成PoC      │
│ 指纹识别      │ 多轮反思     │ 收集证据      │
└───────────────┴──────────────┴───────────────┘
         │              │              │
         └──────────────┴──────────────┘
                        │
               ┌────────┴────────┐
               │   记忆/状态管理   │
               │   Metrics追踪    │
               │   事件日志       │
               └─────────────────┘
```

### 1.3 为什么不直接调大模型API？

这是很多同学会问的问题：既然LLM（大语言模型）这么强，为什么不直接把代码扔给它，让它分析漏洞？

**核心原因：幻觉（Hallucination）**

LLM会"一本正经地胡说八道"。在安全领域，这意味着：
- LLM可能报告一个根本不存在的漏洞（误报）
- LLM可能漏掉真实存在的漏洞（漏报）
- 每次调用LLM都要花钱（Token费用）

我们的策略是：**规则引擎做初筛（免费、确定性强），LLM做深度推理（只在需要时调用）**。

```
代码/HTTP数据
    │
    ├──→ 规则引擎（快速通道）── 80%的常规场景 ──→ 直接产出候选漏洞
    │         │
    │         └──→ 标记为"需要深度分析" ──→ LLM引擎（深度通道）
    │                                               │
    │                                               └──→ 复杂场景分析
    │
    └──→ 结果合并 ──→ 过滤研判 ──→ 验证 ──→ 报告
```

**这就是"双引擎"设计的本质：确定性规则处理常规情况，AI处理复杂情况，两者互补。**

---

## 2. 整体架构

### 2.1 流水线（Pipeline）模式

Agent采用经典的Pipeline架构——数据像流水线一样按顺序经过6个处理站：

```
[任务输入]
    │
    ▼
┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐    ┌──────────┐
│ 1.任务   │───→│ 2.信息   │───→│ 3.分析   │───→│ 4.过滤   │───→│ 5.验证   │───→│ 6.结果   │
│   解析   │    │   采集   │    │   推理   │    │   研判   │    │   执行   │    │   汇总   │
└──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘    └──────────┘
     │               │               │               │               │               │
     ▼               ▼               ▼               ▼               ▼               ▼
 结构化任务      资产清单        候选漏洞        分类结果        验证证据        量化报告
 (JSON)         (endpoints     (findings      (confirmed/    (PoC+HTTP      (metrics+
                +files+forms)   with evidence) FP/uncertain)  trace)         report)
```

### 2.2 为什么用Pipeline而不是其他模式？

你可能在AI课上听说过"ReAct模式"（推理-行动循环）或"Plan-Execute模式"。我们选择Pipeline是因为：

1. **安全任务有明确的阶段性**——必须先知道目标是什么，才能去收集信息；必须先定位疑似漏洞，才能去验证
2. **可追踪、可审计**——每一步的输入输出都是结构化数据，评审老师可以清楚地看到Agent的推理过程
3. **成本可控**——LLM只在分析推理和过滤研判两个阶段被调用，其他阶段用确定性规则

### 2.3 但实际上也有"反馈回路"

Pipeline不是完全单向的。比如：
- 验证失败 → 反馈给过滤模块降低置信度
- 信息不足 → 触发补充采集

这在代码中体现为：Agent的`run()`方法在执行完每个模块后会根据结果决定是否需要回退。

---

## 3. 任务解析

### 3.1 这个模块做什么？

把任何形式的任务输入（自然语言描述、JSON格式、命令行参数）转换成结构化的任务对象。

```
输入: "扫描 http://test.com 的SQL注入和XSS漏洞，不要破坏数据"
          │
          ▼
输出: {
  "target_url": "http://test.com",
  "vuln_types": ["sql_injection", "xss"],
  "constraints": {"destructive_allowed": false},
  "subtasks": [
    {"id": 1, "description": "Test login forms for SQL injection", "priority": "high"},
    {"id": 2, "description": "Test search fields for XSS vulnerabilities", "priority": "medium"},
    ...
  ]
}
```

### 3.2 涉及的关键概念

**NLP（自然语言处理）的"信息抽取"任务**：
- 命名实体识别（NER）：从文本中提取URL、域名、IP
- 意图分类：判断用户想要测试什么类型的漏洞
- 槽位填充：提取约束条件（时间限制、是否允许破坏性测试等）

**正则表达式（Regex）**：
你学过的形式语言与自动机在这里有直接应用！任务解析器先用正则快速提取URL和已知漏洞类型关键词，只有复杂情况才调用LLM。看看`task_parser.py`中的`URL_PATTERN`和`VULN_TYPE_ALIASES`——这就是正则表达式在工业代码中的实际应用。

### 3.3 竞赛要求中的"任务边界控制"

模块中还包含一个**边界控制器**（`boundary.py`），它的作用是：
- 检查目标是否在授权范围内（不在 → 拒绝执行）
- 识别超出Agent能力的任务（如二进制漏洞分析 → 标记需要人工介入）
- 这是Agent"知道自己不知道什么"的能力

```python
# boundary.py 中的关键逻辑
BEYOND_CAPABILITY_INDICATORS = [
    "binary exploitation",    # Agent做不了二进制漏洞
    "kernel exploit",         # Agent做不了内核漏洞
    "social engineering",     # Agent做不了社会工程学
    ...
]
```

---

## 4. 信息采集

### 4.1 这个模块做什么？

Agent需要"看见"目标系统。这个模块就像爬虫，把目标的相关信息都收集回来。

```
目标URL: http://test.com
         │
         ├──→ 抓取首页HTML → 提取链接、表单
         ├──→ 读取robots.txt → 发现sitemap
         ├──→ 目录扫描 → 发现/admin, /api, /backup
         ├──→ 技术栈识别 → Server: Apache/2.4.41, X-Powered-By: PHP/7.4
         ├──→ WAF检测 → 发现Cloudflare
         ├──→ API文档发现 → 找到/swagger.json
         └──→ 表单提取 → POST /login (username, password)
```

### 4.2 涉及的关键概念

**HTTP协议（计算机网络）**：
你在计算机网络课上学到的HTTP请求/响应、状态码、Header、Cookie，在这里全部用上了：
- `200 OK` → 正常响应
- `403 Forbidden` → 可能需要认证
- `Server`头 → 识别Web服务器类型
- `Set-Cookie` → 追踪会话

**网络爬虫基础**：
- BFS（广度优先搜索）策略爬取页面
- URL去重（用`visited`集合记录已访问的URL）
- robots.txt协议（尊重网站的爬取规则）

**异步I/O**：
信息采集需要发很多HTTP请求，如果一个个串行发送会非常慢。实际生产环境中会用`aiohttp`做异步并发请求。这也是操作系统课上学到的"I/O多路复用"概念的直接应用。

### 4.3 安全采集的约束

Agent的采集不是无节制的：
- **速率限制**：每秒最多发N个请求，避免触发WAF或被当成DDoS
- **深度限制**：只爬3层链接，不会无限深入
- **范围限制**：只采集同域名的资源，不会爬到外部网站

---

## 5. 分析推理（最核心）

### 5.1 双引擎是怎么工作的？

这是整个Agent最核心的部分。它用两个引擎协同工作：

#### 引擎1：规则引擎（Rule Engine）— 快速通道

规则引擎是**确定性的**——同样的输入永远产生同样的输出，不会"幻觉"。

它是怎么工作的？以检测SQL注入为例：

1. **找Sink（危险函数调用）**：扫描代码，找`cursor.execute()`、`mysqli_query()`等数据库操作
2. **找Source（用户输入点）**：扫描代码，找`request.args.get()`、`$_GET['id']`等用户输入
3. **数据流分析**：如果用户输入能"流到"危险函数，就标记为疑似漏洞

```python
# 规则引擎会发现这行代码有问题：
query = "SELECT * FROM users WHERE id = " + request.args.get('id')
#       ↑ sink (SQL查询)                  ↑ source (用户输入)
# 因为用户输入直接拼接到SQL查询中，没有参数化处理
```

规则存储在YAML文件中（`rules/sqli.yaml`等）。每条规则包含：
- 正则表达式模式
- 适用的编程语言
- 基础置信度

```yaml
# sqli.yaml 中的一条规则
- id: SQLI_CODE_001
  name: "String concatenation in SQL query"
  languages: [python, php, java, javascript, go]
  regex: "(?:execute|query|raw)\\s*\\(\\s*[\"'](?:SELECT|INSERT|UPDATE|DELETE)"
  confidence_base: 0.7
```

#### 引擎2：LLM引擎 — 深度通道

规则引擎只能匹配模式，但无法理解**语义**。比如：

```python
# 这段代码规则引擎会标记，但LLM能看出它其实是安全的：
query = "SELECT * FROM users WHERE id = ?"
cursor.execute(query, (user_id,))  # 参数化查询，安全！
```

LLM引擎做的事情：
1. 拿到规则引擎标记的代码片段
2. 理解代码的上下文和意图
3. 判断这是真的漏洞还是误报
4. 调整置信度
5. 补充规则引擎可能漏掉的分析角度

**自反思（Self-Reflection）**：LLM分析完后，还会"扮演反方"再检查一遍——"如果这不是漏洞，那可能是什么原因？"这能显著降低误报率。

### 5.2 涉及的关键概念

**编译原理中的模式匹配**：
规则引擎的正则匹配本质上是一种简化的词法分析。你编译原理课上学到的正则表达式、自动机理论，在这里是真正干活的核心工具。

**程序分析中的污点追踪（Taint Analysis）**：
规则引擎的Sink-Source分析就是一个简化的污点追踪系统：
- Source = 污点源（用户输入）
- Sink = 污点汇聚点（危险函数）
- 如果污点能从Source流到Sink且未经过净化（Sanitization），就是漏洞

**AI中的Prompt Engineering（提示词工程）**：
`prompts/`目录下的模板文件就是精心设计的提示词。好的提示词需要：
- 明确角色定位（"你是一个资深安全分析师"）
- 清晰的输出格式要求（"返回JSON"）
- 边界约束（"只报告有证据的发现"）
- 思维链引导（"先分析代码逻辑，再判断是否存在漏洞"）

**Token与成本控制**：
每次调用LLM都有成本。比如Claude Sonnet大约每100万输入token收费$3。我们通过以下策略控制成本：
- 只把规则引擎标记过的函数发给LLM，而不是整个代码库
- 每个分析请求控制在2000 tokens以内
- 用便宜的模型（Haiku）做简单任务，贵的模型（Opus/Sonnet）做核心分析

---

## 6. 过滤研判

### 6.1 这个模块做什么？

分析推理产生了大量"疑似漏洞"，其中很多其实是误报。过滤研判负责：

1. **去重**：同一个漏洞可能被多条规则重复标记
2. **降噪**：识别并过滤已知的误报模式
3. **分类**：把每个疑似漏洞归入三类之一：
   - ✅ Confirmed（确认）— 置信度 ≥ 70%
   - ❌ False Positive（误报）— 置信度 < 30%
   - ❓ Uncertain（不确定）— 两者之间，需人工介入

### 6.2 怎么降噪——误报规则

有些模式几乎总是误报，比如：

```python
# 误报案例1：测试文件中的代码
# test_login.py 中的这段代码永远不会在生产环境运行
def test_sql_injection():
    query = "SELECT * FROM users WHERE name = '" + user_input + "'"
    # ↑ 这只是测试代码，不是真实漏洞

# 误报案例2：已有输入验证
user_id = int(request.args.get('id'))  # int() 转换已经阻止了注入
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # 安全

# 误报案例3：硬编码的值
db.execute("SELECT * FROM config WHERE key = 'hardcoded_value'")  # 不是漏洞
```

过滤模块的`FP_PATTERNS`就是这些经验规则：

```python
FP_PATTERNS = [
    (lambda f: "test_" in f.get("file_path", ""), "Test file"),      # 测试文件
    (lambda f: "int(" in f.get("evidence", ""), "Input validation"), # 已有验证
    (lambda f: ".filter(" in f.get("evidence", ""), "ORM usage"),    # ORM安全查询
    ...
]
```

### 6.3 涉及的关键概念

**机器学习中的分类问题**：
三分类（Confirmed/FP/Uncertain）是典型的分类问题。但这里用的是规则+启发式方法，而不是训练模型——因为在安全领域，可解释性比准确率更重要。评审老师需要知道Agent**为什么**判定一个发现是误报。

**置信度计算**：
```
最终置信度 = 规则引擎置信度 × 0.6 + LLM置信度 × 0.3 + 证据加分
然后减去误报规则扣分
如果经过反思质疑，再乘以0.85
```

这个公式体现了"规则为王，LLM为辅"的设计哲学——规则引擎的权重(0.6)远高于LLM(0.3)。

---

## 7. 验证执行

### 7.1 这个模块做什么？

"我怀疑这里有SQL注入"——光说不行，你得证明它。

验证模块对每个确认的漏洞执行安全的自动化验证：

```
疑似SQL注入 (http://test.com/item?id=1)
    │
    ├──→ 发送基准请求:      id=1       → 记录正常响应
    ├──→ 发送测试Payload:   id=1'      → 检查是否有SQL错误
    ├──→ 发送延时Payload:   id=1' AND SLEEP(3)-- → 检查响应是否延迟>2.5s
    └──→ 如果任一测试成功  → 漏洞已验证！保存请求/响应作为证据
```

### 7.2 安全约束——最重要的设计

**这是本Agent区别于普通漏洞扫描器的关键设计。** 所有验证必须是非破坏性的：

| 漏洞类型 | ❌ 不允许 | ✅ 允许 |
|---------|----------|---------|
| SQL注入 | DROP TABLE, INSERT, UPDATE, 读取真实数据 | 延时注入(SLEEP), 报错注入, 布尔盲注 |
| XSS | 窃取Cookie, 重定向到恶意站点 | `alert(1)`, `alert(document.domain)` |
| SSRF | 访问真实外部服务 | 访问127.0.0.1, 169.254.169.254 |
| 路径遍历 | 读取/etc/shadow, 私钥文件 | 读取/etc/hostname（非敏感文件） |
| 命令注入 | rm -rf, 反弹shell | sleep命令（延时检测） |

```python
# sandbox.py 中的安全检查
DESTRUCTIVE_SQL = [
    "DROP", "DELETE", "TRUNCATE", "UPDATE", "INSERT",
    "ALTER", "CREATE", "EXEC", "INTO OUTFILE", ...
]

def check_payload_safety(payload):
    for keyword in DESTRUCTIVE_SQL:
        if keyword in payload.upper():
            return SafetyVerdict.UNSAFE  # 拒绝执行！
    return SafetyVerdict.SAFE
```

### 7.3 涉及的关键概念

**操作系统中的沙箱（Sandbox）概念**：
验证代码在一个受限的"沙箱"中执行。所有操作都通过HTTP请求完成，没有任何本地命令执行。即使Payload中包含恶意代码，也只会影响目标（而且Payload本身已被安全检查过滤）。

**网络中的请求/响应分析**：
验证的核心是对比——"正常请求的响应"和"注入Payload后的响应"有什么区别？这涉及：
- 响应时间差异（Time-based盲注检测）
- 响应内容差异（Boolean-based盲注检测）
- 错误信息匹配（Error-based注入检测）

---

## 8. 结果汇总

### 8.1 产出什么？

报告模块生成两种格式：

1. **JSON报告**（机器可读，对接靶场评测系统）
2. **Markdown报告**（人类可读，供安全分析师审核）

### 8.2 竞赛要求的量化指标

| 指标 | 含义 | 计算方式 |
|------|------|---------|
| 漏洞发现率 | 确认漏洞占总候选的比例 | confirmed / total_candidates |
| 误报率 | 伪警报占总候选的比例 | false_positives / total_candidates |
| 代码审计量级 | 分析的代码行数和文件数 | sum(line_count) / files_count |
| 单高危漏洞发现时长 | 从任务开始到首个高危确认的时间 | first_high_severity_time |
| 大模型运行成本 | LLM调用的总费用(USD) | Σ(token_cost_per_call) |
| 人机验证时间占比 | 人工介入耗时占总耗时的比例 | human_wait / total_duration |

这些指标由`metrics.py`中的`MetricsTracker`自动追踪。每个模块开始/结束时记录时间戳，每次LLM调用记录Token消耗和费用。

---

## 9. 关键概念深入

### 9.1 为什么"规则引擎+LLM"比纯LLM好？

这是本项目最核心的设计思想。用一个类比：

**纯LLM方案** = 让一个知识渊博的教授检查100个学生作业
- 优点：教授能理解复杂情况
- 缺点：慢（每份作业都要仔细看）、贵（教授的时薪高）、可能出错（累了会看走眼）

**规则引擎+LLM** = 先用助教（规则引擎）筛一遍，只有疑难作业才给教授看
- 规则引擎：快速处理80%的常规问题（免费、不会累、永远一致）
- LLM：深度分析20%的复杂案例
- 结果：又快又准又省钱

### 9.2 大模型"幻觉"问题在安全领域的特殊性

LLM的幻觉在安全领域特别危险：
- **方向1：假阳性（把安全代码报成漏洞）** → 浪费安全团队时间
- **方向2：假阴性（漏掉真实漏洞）** → 造成安全事故

所以我们的策略是：**LLM只能做"假设生成器"，不能做"最终裁决者"**。最终裁决必须由规则引擎或验证模块给出。

```python
# boundary.py 中的"幻觉守卫"
def guard_llm_finding(finding):
    if finding is LLM-only (no rule match, no evidence):
        finding.confidence = min(finding.confidence, 0.4)  # 封顶40%
        finding.verdict = "uncertain"  # 绝不允许"confirmed"
        finding.guard_note = "LLM finding without independent evidence"
```

### 9.3 正则表达式在安全领域的威力

很多同学觉得正则表达式只是用来做表单验证的。但在安全领域，正则表达式是一个强大的模式匹配工具：

```python
# 检测SQL注入：找execute("SELECT... 这类模式
r'execute\s*\(\s*["\']SELECT'

# 检测命令注入：找 os.system(、subprocess.run( 这类危险调用
r'os\.system\s*\(|subprocess\.run\s*\('

# 检测XSS：找 innerHTML = 这类不安全DOM操作
r'\.innerHTML\s*='
```

学会写高质量的正则表达式，是成为安全工程师的基本功。

### 9.4 状态管理与可恢复性

Agent不是"一次性运行"的程序。如果任务执行到一半因为网络问题中断了怎么办？

我们的设计考虑了**检查点（Checkpoint）机制**：
- 每个模块执行完，中间结果都保存到JSON文件
- 如果中断了，可以从上次的检查点恢复
- 这也是操作系统"进程状态保存"概念的直接应用

### 9.5 可观测性（Observability）

一个复杂系统在运行时，你需要知道它"正在做什么"、"做得怎么样"。这就是可观测性：

- **日志（Logging）**：`utils/logger.py` 记录每一步的详细操作
- **指标（Metrics）**：`utils/metrics.py` 追踪数量、时间、成本
- **事件流（Events）**：每个关键决策（"标记为确认"、"需要人工介入"）都记录为事件

这是分布式系统的基本概念在单机Agent中的应用。

---

## 10. 干中学

### 10.1 推荐的学习路径

不要试图一次性理解所有代码。按以下顺序逐步深入：

#### 第一步：跑起来（30分钟）

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 启动演示靶场
python demos/demo_target/app.py

# 打开浏览器访问 http://127.0.0.1:5000
# 手动测试每个漏洞，理解漏洞原理

# 3. 运行Agent（Mock模式，不需要API Key）
python demos/demo_run.py --mock-llm
```

#### 第二步：理解一个模块（2小时）

建议从**规则引擎**开始（`utils/rule_engine.py`）：
1. 读懂`scan_code()`方法——它怎么找漏洞？
2. 打开`rules/sqli.yaml`——规则长什么样？
3. 改一条规则（比如降低`confidence_base`），看看输出有什么变化
4. 运行`python tests/test_rule_engine.py`验证你的理解

#### 第三步：添加一条新规则（2小时）

在`rules/`下新建一个`csrf.yaml`，写几条检测CSRF漏洞的规则：
- 想想：CSRF漏洞的代码特征是什么？（没有CSRF Token的表单？Cookie没有SameSite属性？）
- 写出对应的正则表达式
- 在`test_rule_engine.py`中添加测试用例
- 跑通测试

#### 第四步：理解Pipeline调度（2小时）

读`agent.py`中的`run()`方法：
- 六个模块是怎么串联的？
- 中间结果是怎么传递的？
- 如果某个模块失败，Agent怎么处理？

#### 第五步：改进一个模块（4小时）

选择一个你想改进的模块：
- **分析模块**：改进规则引擎的Sink-Source分析，让它更准确
- **验证模块**：添加新类型漏洞的验证逻辑（比如CSRF验证）
- **报告模块**：改进Markdown报告的输出格式

### 10.2 可以自己做的扩展方向

1. **添加新的漏洞类型检测**：CSRF、SSTI、XXE、反序列化
2. **改进信息采集**：添加JavaScript源映射分析、GraphQL schema爬取
3. **接入真实LLM**：配置你的 LLM API Key，测试LLM引擎的实际效果
4. **容器化部署**：用Docker打包Agent和演示靶场
5. **Web界面**：用Flask/Streamlit做一个简单的Web UI
6. **性能优化**：将一些模块改成异步执行，提升大规模扫描的速度

### 10.3 前置知识速查表

| 如果你不懂... | 快速补课资源 |
|-------------|------------|
| YAML格式 | 5分钟看 [learnxinyminutes.com/docs/yaml](https://learnxinyminutes.com/docs/yaml/) |
| 正则表达式 | [regex101.com](https://regex101.com/) 交互式学习 |
| HTTP协议 | MDN [HTTP概述](https://developer.mozilla.org/zh-CN/docs/Web/HTTP/Overview) |
| SQL注入原理 | OWASP [SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection) |
| XSS原理 | OWASP [XSS](https://owasp.org/www-community/attacks/xss/) |
| Python dataclass | 10分钟看Python官方文档的dataclass部分 |
| LLM API调用 | Anthropic [API文档](https://docs.anthropic.com/en/docs/) |

### 10.4 给参赛同学的建议

如果你用这个项目参加比赛，这些是加分项：

1. **对比实验数据**：在文档中对比"纯LLM方案"和"规则+LLM双引擎方案"的误报率、成本、耗时差异。要有真实数据，不要只做定性描述。

2. **创新点突出**：从以下方向选1-2个深入：
   - 多轮自主反思（提高准确率）
   - 工具调用编排（集成更多安全工具如Nuclei、SQLMap）
   - 漏洞自动验证（扩展更多漏洞类型的自动化PoC生成）
   - 漏洞上下文溯源（从Sink反向追踪到Source的完整数据流）

3. **人机干预统计**：在报告中清晰展示每一步是否经过人工干预，人机时间占比是多少。越低越好（但不要为零——零意味着Agent可能在不确定时强行输出）。

4. **工程完整性**：
   - 代码有注释（中英文均可，关键逻辑必须注释）
   - README写清依赖和部署步骤
   - 评审能一键复现你的实验结果

5. **安全与合规**：
   - 明确声明所有验证是非破坏性的
   - 所有演示案例脱敏
   - 只在授权目标上运行

---

## 附录：项目文件速查

| 文件 | 作用 | 适合从哪里开始读 |
|------|------|----------------|
| `agent.py` | 主编排器，Pipeline调度 | 理解整体流程 |
| `utils/rule_engine.py` | 规则引擎核心 | 理解漏洞检测原理 |
| `utils/sandbox.py` | 安全验证沙箱 | 理解安全约束设计 |
| `utils/metrics.py` | 指标追踪器 | 理解量化统计 |
| `utils/llm_client.py` | LLM API封装 | 理解AI调用策略 |
| `modules/analyzer.py` | 分析推理模块 | 理解双引擎协同 |
| `modules/filter_judge.py` | 过滤研判模块 | 理解误报控制 |
| `rules/sqli.yaml` | SQL注入规则 | 理解规则定义格式 |
| `demos/demo_target/app.py` | 演示漏洞应用 | 理解常见Web漏洞 |
| `tests/test_rule_engine.py` | 规则引擎测试 | 学习怎么写测试 |
| `config.yaml` | 配置文件 | 学习系统配置管理 |

---

*这篇笔记的目标不是让你"读完就懂"，而是给你一个地图，让你知道每个部分在哪里、为什么这样设计。真正的理解来自于动手改代码、跑测试、看输出变化。祝你在"干中学"的过程中享受到构建Agent的乐趣！*
