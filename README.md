# SRC Vulnerability Mining Agent v2 (SRC-VulnMiner)

LLM驱动的端到端Web漏洞挖掘Agent。

## 架构对比

| | v1（固定Pipeline） | v2（LLM驱动） |
|---|---|---|
| 决策者 | 规则引擎+固定流程 | **LLM自主决策** |
| 流程 | 6模块按固定顺序执行 | LLM按阶段流转，每轮自主调用工具 |
| 漏洞发现 | 规则匹配→LLM分析 | LLM主动探测+规则扫描辅助 |
| 验证 | 沙箱策略固定 | LLM自主构造payload验证 |
| 会话 | 无持久化 | **JSON持久化，可中断恢复** |
| LLM | 单一Provider | **可配置（OpenAI兼容协议）** |
| 演示结果 | 卡死/hang | **65秒跑完，6漏洞全发现，4个实测验证** |

## 工作原理

```
┌─────────────────────────────────────────────────────┐
│                LLM 推理引擎（可配置）                 │
│   系统提示词：安全分析师角色 + 阶段说明 + 纪律约束      │
└──────────────┬──────────────────────────────────────┘
               │ function-calling（每轮自主决策）
               ▼
┌─────────────────────────────────────────────────────┐
│                 工具层（LLM的"手"）                   │
│  http_request    HTTP请求（10s硬超时、零重试）         │
│  python_exec     Python执行（审计记录，数据处理）      │
│  rule_scan       规则引擎扫描（确定性漏洞模式）         │
│  add_finding     记录漏洞发现                         │
│  mark_verified   标记验证（L2证据）                    │
│  switch_phase    阶段流转                             │
│  read_source     读取源码                             │
│  session_status  查看会话状态                         │
└──────────────┬──────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────┐
│              会话状态（JSON持久化）                   │
│  findings / executed_steps / notes / confirmed_facts │
│  每轮自动保存 → sessions/ 目录                        │
└─────────────────────────────────────────────────────┘
```

### 阶段流转（LLM自主推进）

```
task_parsing → info_collection → analysis → verification → reporting
```

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置

```bash
# 复制配置模板
cp config.example.yaml config.yaml     # Windows: copy config.example.yaml config.yaml
cp .env.example .env                   # Windows: copy .env.example .env
```

然后编辑 `.env` 填入你的 API key，按需修改 `config.yaml`：
- `llm.base_url`：API 端点（OpenAI 兼容协议，留空用官方端点）
- `llm.model`：模型名
- `llm.api_key`：通过 `.env` 的 `LLM_API_KEY` 读取

### 3. 运行演示

```bash
# 自动启动演示靶场 + 运行Agent
python demos/demo_run.py --auto
```

预期输出（实测数据）：
```
发现: 6 个漏洞候选
验证: 4 个已验证 (L2证据)
轮次: 17 轮 LLM 决策
耗时: 65.2s
LLM调用: 17 次, $0.18
```

### 4. 命令行

```bash
# JSON任务
python agent.py --task task.json

# 自然语言
python agent.py --text "扫描 http://testphp.vulnweb.com 的SQL注入和XSS"

# stdin（靶场管道）
echo '{"target":"http://127.0.0.1:5000","vuln_types":["sqli"]}' | python agent.py --stdin
```

### 任务JSON格式

```json
{
  "task_id": "task_001",
  "target": "http://target.com",
  "vuln_types": ["sql_injection", "xss", "idor", "ssrf"],
  "source_path": "path/to/source/code",
  "constraints": {"destructive_allowed": false}
}
```

## 项目结构

```
agent+/
├── agent.py                  # CLI入口（v2）
├── config.yaml               # Agent配置（复制自config.example.yaml）
├── core/                     # v2核心（LLM驱动架构）
│   ├── orchestrator.py       # LLM主循环（轮次+工具调用）
│   ├── session.py            # 会话持久化
│   ├── tools.py              # 工具注册表
│   └── constraints.py        # 任务约束
├── modules/                  # v1模块（规则引擎等仍被复用）
├── rules/                    # 漏洞规则库（YAML）
├── utils/                    # 基础设施
│   ├── llm_client.py         # LLM API（含function-calling）
│   ├── http_client.py        # HTTP客户端（零重试模式）
│   ├── rule_engine.py        # 规则引擎
│   └── desensitizer.py       # 数据脱敏
├── demos/
│   ├── demo_target/app.py    # 演示靶场（6种漏洞，threaded）
│   └── demo_run.py           # 演示运行
├── tests/
│   ├── test_rule_engine.py   # 规则引擎测试（7个）
│   └── test_integration.py   # v2集成测试（6个）
├── sessions/                 # 会话JSON（自动生成）
├── output/                   # 报告输出
└── notes.md                  # 教学笔记
```

## 测试

```bash
set PYTHONIOENCODING=utf-8
python tests/test_rule_engine.py    # 7 tests
python tests/test_integration.py    # 6 tests
```

## 演示靶场漏洞清单

| # | 漏洞 | 端点 | 实测验证 |
|---|------|------|---------|
| 1 | SQL注入 | POST /login (username) |  `' OR '1'='1` 登录绕过 |
| 2 | 反射XSS | GET /search?q= |  script标签未编码反射 |
| 3 | IDOR | GET /user/<id> |  无认证访问他人资料 |
| 4 | SSRF | GET /fetch?url= |  服务器请求内部URL |
| 5 | 路径遍历 | GET /view?file= | L1（跳过实测，避免搞挂靶场）|
| 6 | 命令注入 | GET /ping?host= | L1（跳过实测，避免搞挂靶场）|

## 安全声明

- 仅供授权测试、CTF竞赛和教育用途
- LLM被提示词约束为非破坏性验证
- Python执行有审计日志
- 报告自动脱敏
