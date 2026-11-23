"""CSP 违规报告收集引擎。

本模块是仓库中唯一的实现文件，只暴露 8 个公开函数，全部为待实现桩。
外部输入一律视为不可信：解析、规范化、清洗、限流、校验必须显式完成。
所有时间均由调用方以毫秒时间戳显式传入，不读取系统时钟，不使用随机数。
"""


def parse_report(body):
    """解析一条 CSP 违规报告。

    契约：
    - body 必须是 str 形式的 JSON 对象文本，不能是 bytes、None 或空串。
    - 报告必须且只能包含四个字段，缺一不可，多出字段同样拒绝：
      directive（非空字符串，CSP 指令名，如 script-src）、
      blocked_url（绝对 http 或 https URL，被拦截的资源地址）、
      source（绝对 http 或 https URL，触发拦截的来源页）、
      timestamp_ms（非负整数，毫秒时间戳，由上报方显式携带）。
    - 返回一个新的 dict，仅含上述四个键，字段值原样保留，不做 HTML 清洗，
      清洗由 sanitize 负责，也不做去重，去重由 dedup_key 负责。
    - 以下情况一律抛出 ValueError，容差为 0，不猜测、不补默认值、不吞异常：
      JSON 非法、body 不是 str、字段缺失或多余、类型不符、directive 为空、
      URL 非绝对地址或 scheme 不是 http/https、timestamp_ms 为负。
    - 相同 body 必须解析出相等（==）的 dict，函数不得修改 body。

    参数：
        body: str，一条上报的 JSON 文本。

    返回：
        dict，键为 directive、blocked_url、source、timestamp_ms。
    """
    raise NotImplementedError


def dedup_key(report):
    """计算报告的去重键。

    契约：
    - 键只由 directive 与 normalize_url(source) 组成，绝不包含 timestamp_ms，
      也不包含 blocked_url。同一来源同一指令的告警无论上报多少次、时间如何变化，
      都必须得到同一个键。
    - directive 先去除首尾空白并把内部连续空白折叠为单个空格，再转为小写
      （CSP 指令名大小写不敏感）；不同指令（如 script-src 与 img-src）
      必须得到不同的键。
    - 返回 64 位小写十六进制 sha256 字符串，输入材料为
      directive 加换行符加规范化 source，换行符用于分隔字段避免拼接歧义。
    - report 不是 dict、字段缺失或类型不对时抛出 ValueError，容差为 0。
    - 该键用于同一批次内的重复告警合并：相同键只计一次。
    """
    raise NotImplementedError


def normalize_url(url):
    """规范化 URL，用于去重与按来源限流。

    契约：
    - 只接受绝对 http/https URL；其他 scheme、相对地址、空值一律抛 ValueError，
      容差为 0。
    - 丢弃片段：去掉 # 及其后的全部内容；查询串保留原顺序与原编码，不排序、
      不重新编码。
    - scheme 与主机名转为小写；丢弃用户信息（userinfo），防止
      https://trusted.example@evil.example 这类伪造来源混淆；丢弃默认端口
      （http 的 80、https 的 443），非默认端口保留；IPv6 字面量主机保留方括号。
    - 路径为空时保持为空，不擅自补斜杠；路径大小写原样保留。
    - 返回规范化后的字符串；对已规范化的 URL 再调用一次结果不变（幂等）。
    - 示例：HTTPS://CDN.Example:443/a.js?x=1#frag 规范化为
      https://cdn.example/a.js?x=1
    """
    raise NotImplementedError


def aggregate(reports, bucket_ms):
    """按时间桶聚合报告计数。

    契约：
    - reports 为 report dict 的可迭代对象；bucket_ms 必须为正整数，否则
      抛 ValueError，容差为 0。
    - 桶起点 start = (timestamp_ms // bucket_ms) * bucket_ms，每个报告恰好
      落入一个桶，同一桶内计数加一。
    - 返回 dict，键为桶起点（int），值为该桶内的报告数（int）；只包含实际
      出现的桶，不补齐空桶；空输入返回空 dict。
    - 结果只由报告集合与 bucket_ms 决定，与报告的到达顺序完全无关；
      不得修改入参 reports。
    - 本函数不去重、不限流、不清洗：重复报告由调用方先按 dedup_key 去掉，
      来源风控由 rate_limit 负责。
    """
    raise NotImplementedError


def rate_limit(source, policy, now):
    """按来源限流，防止单来源伪造报告刷量。

    契约：
    - source 先经 normalize_url 规范化；now 为非负整数毫秒时间戳，显式传入。
    - policy 必须是 dict，且包含：
      limit（正整数，窗口内允许的最大报告数）、
      window_ms（正整数，窗口长度，单位毫秒）、
      counters（dict，调用方提供的可变计数状态，形如
      dict[规范化来源, list[整数时间戳]]，本函数原地更新）。
      缺失或类型不对时抛 ValueError，容差为 0。
    - 计数维度是来源，不是 dedup_key：攻击者更换指令、更换被拦地址或构造
      新的去重键都不能绕过限流。
    - 判断前先清理该来源所有小于等于 now 减 window_ms 的时间戳，过期计数
      不得继续占用窗口；只统计落在 (now - window_ms, now] 内的记录。
    - 窗口内记录数小于 limit 时，把 now 追加到该来源的计数并返回 True；
      否则返回 False 且不记录本次。
    - 结果完全由 counters、source、policy 与 now 决定；不读取系统时钟，
      不使用模块级全局状态。
    """
    raise NotImplementedError


def sanitize(report):
    """清洗报告中的不可信字段，防止二次注入。

    契约：
    - 返回一个新的 dict，键集合与 report 相同，不修改入参。
    - directive、blocked_url、source 三个字符串字段执行 HTML 转义，且必须
      先替换 & 为 &amp;，再替换 <、>、双引号、单引号，避免顺序错误造成
      二次转义或漏转义；映射为：
      & 转 &amp;，< 转 &lt;，> 转 &gt;，双引号转 &quot;，单引号转 &#x27;。
    - timestamp_ms 必须是 int 且非负，否则抛 ValueError；该字段原样保留。
    - 不做 URL 规范化、不去重、不校验来源信任关系；URL 合法性由
      parse_report 负责，来源信任由 validate_policy 与调用方负责。
    - 容差为 0：不吞异常，不静默丢弃字段，不把非字符串字段强制转成字符串。
    """
    raise NotImplementedError


def validate_policy(policy):
    """校验采集策略是否覆盖三类滥用风险。

    契约：
    - policy 必须为 dict，否则抛 ValueError，容差为 0。
    - 依次检查三项，缺一即记一个问题，每类最多一项，顺序稳定：
      1) dedup：policy 中 dedup 必须严格为 True，确保同一来源同一指令的
         重复报告会被合并；
      2) rate_limit：policy 中 rate_limit 必须为 dict，limit 与 window_ms
         均为正整数，确保按来源限流；
      3) source_validation：policy 中 trusted_sources 必须为非空 list，
         且每一项都是字符串，并且经 normalize_url 后与自身完全相等，
         即只接受规范化后的 http/https 绝对来源；带 userinfo、片段、
         默认端口或非 http/https scheme 的伪造来源不得通过校验。
    - 返回 list[str] 问题代码，无问题返回空 list；问题代码依次为
      missing_dedup、missing_rate_limit、missing_source_validation。
    - 本函数只校验策略配置本身，不读取报告、不修改 policy。
    """
    raise NotImplementedError


def report_batch(batches, policy):
    """按批次独立处理报告，批次之间绝不共享状态。

    契约：
    - batches 为 list，每个元素是 dict，含：
      bucket_ms（正整数，该批次的聚合桶宽）、
      reports（report dict 的 list）。
      结构不符抛 ValueError，容差为 0。
    - policy 必须先通过 validate_policy；存在问题时代码列表作为 ValueError
      的消息抛出，不带着无效策略继续处理。
    - 每个批次独立处理，顺序与输入一致，状态不跨批次：
      1) 按 dedup_key 合并该批次内部的重复报告，保留首次出现；
      2) 为该批次新建独立的按来源限流计数（空 dict），以报告自带的
         timestamp_ms 作为 now 逐条检查，被限流的报告丢弃；
      3) 用该批次自己的 bucket_ms 和空桶调用 aggregate，绝不复用前一批次
         的桶，也绝不让后一批次命中前一批次的计数。
    - 返回 dict：
      batches 为 list，每项含 bucket_ms、counts（aggregate 的结果）、
      kept（保留条数）、dropped（去重或限流丢弃条数）；
      total 为所有批次 kept 之和。
    - 结果必须与逐个批次单独处理等价；不得修改入参 batches 与 policy。
    """
    raise NotImplementedError