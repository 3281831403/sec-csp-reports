# sec-csp-reports

浏览器的违规报告接进来之后，同一条告警刷了几万条，真正的新问题全被淹了：只有解析不做去重，同一条告警重复入库；去重键包含时间戳，同一问题每次都是新键；去重键不含指令，不同指令被合并；地址规范化不去片段，带锚点的地址被当成不同来源；聚合按到达顺序而不是时间桶，乱序报告算错；限流按去重键计数，换键即可绕过；限流不清理过期计数，长期运行后全部被限；清洗只转义尖括号，引号与与号未处理；策略校验不检查是否校验来源页；批量处理复用聚合桶，后一批次命中前一批次的计数。engine/report/collect.py 是核心，tests/report/test_collect.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

## 运行方式

在仓库根目录执行：

    python -m pytest tests -q

当前为待修复状态，预期输出尾部为：

    15 failed

即 15 个测试全部失败且没有 error。按题面顺序修完 10 个缺陷后，应变为 15 passed。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

## 约束与说明

- tests 不可修改：只允许修改 engine/report/collect.py；tests/report/test_collect.py 是验收测试。
- 本仓库采用 engine 嵌套布局：唯一实现文件位于 engine/report/collect.py，测试位于 tests/report/test_collect.py，仓库根的 conftest.py 把仓库根加入 sys.path，使 engine.report.collect 可以直接导入。
- 实现只使用标准库中的 json、urllib.parse、hashlib、collections，测试使用 pytest；全程离线，不使用随机数，所有时间由调用方以毫秒时间戳显式传入。
- engine/report/collect.py 恰好有 8 个公开函数，当前全部是 raise NotImplementedError 的桩；docstring 写明了去重键组成、按来源限流与过期清理、容差为 0 等契约。
- 修复时按题面列出的顺序逐个处理 10 个缺陷，不要改动函数签名与测试文件。