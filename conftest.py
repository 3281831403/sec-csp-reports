"""把仓库根目录加入 sys.path，使 engine 嵌套布局可直接导入。"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))